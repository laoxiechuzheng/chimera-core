package quicx

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/chimera-proxy/chimera-core/internal/chimera"
	"github.com/quic-go/quic-go"
)

const quicALPN = "chimera-quic/1"

func generateCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "chimera"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

type Server struct {
	listener *quic.Listener
	Password string
}

func ListenServer(ctx context.Context, listenAddr, password, obfsPassword string) (*Server, string, error) {
	cert, fingerprint, err := generateCert()
	if err != nil {
		return nil, "", err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{quicALPN},
	}
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, "", err
	}
	if obfsPassword != "" {
		_ = obfsPassword // anti-QoS at stream level
	}
	listener, err := quic.Listen(pc, tlsConf, &quic.Config{MaxIdleTimeout: 120 * time.Second})
	if err != nil {
		return nil, "", err
	}
	s := &Server{listener: listener, Password: password}
	go s.acceptLoop(ctx)
	return s, fingerprint, nil
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			return
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn quic.Connection) {
	defer conn.CloseWithError(0, "")
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleStream(ctx, stream)
	}
}

func (s *Server) handleStream(ctx context.Context, stream quic.Stream) {
	defer stream.Close()

	var head [1]byte
	if _, err := io.ReadFull(stream, head[:]); err != nil {
		return
	}
	var tokLen [1]byte
	if _, err := io.ReadFull(stream, tokLen[:]); err != nil {
		return
	}
	tok := make([]byte, tokLen[0])
	if _, err := io.ReadFull(stream, tok); err != nil {
		return
	}
	if !verifyToken(tok, s.Password) {
		return
	}
	addr, err := chimera.ReadAddress(stream)
	if err != nil {
		return
	}
	if head[0] != chimera.CmdConnect {
		return
	}
	target, err := net.DialTimeout("tcp", addr.String(), 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, stream); done <- struct{}{} }()
	go func() { io.Copy(stream, target); done <- struct{}{} }()
	<-done
	stream.CancelRead(0)
	<-done
}

func token(password string) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("chimera-connect"))
	return mac.Sum(nil)
}

func verifyToken(tok []byte, password string) bool {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("chimera-connect"))
	return hmac.Equal(mac.Sum(nil), tok)
}

type Client struct {
	Conn     quic.Connection
	password string
}

func DialClient(ctx context.Context, serverAddr, password, obfsPassword, certFingerprint string) (*Client, error) {
	var fp []byte
	if certFingerprint != "" {
		var err error
		fp, err = hex.DecodeString(certFingerprint)
		if err != nil || len(fp) != 32 {
			return nil, errors.New("quicx: invalid fingerprint")
		}
	}
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{quicALPN},
		}
		if len(fp) == 32 {
			tlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("quicx: no certs")
				}
				sum := sha256.Sum256(rawCerts[0])
				if !bytes.Equal(sum[:], fp) {
					return errors.New("quicx: cert fingerprint mismatch")
				}
				return nil
			}
		}
	var pc net.PacketConn
	var pcAddr net.Addr
	if obfsPassword != "" {
		var err error
		pc, err = net.ListenPacket("udp", "")
		if err != nil {
			return nil, err
		}
		_ = obfsPassword // anti-QoS at stream level
		udpAddr, err2 := net.ResolveUDPAddr("udp", serverAddr)
		if err2 != nil {
			return nil, err2
		}
		pcAddr = udpAddr
		conn, err := quic.Dial(ctx, pc, pcAddr, tlsConf, &quic.Config{MaxIdleTimeout: 120 * time.Second})
		if err != nil {
			return nil, err
		}
		return &Client{Conn: conn, password: password}, nil
	}
	_ = obfsPassword // anti-QoS at stream level
	conn, err := quic.DialAddr(ctx, serverAddr, tlsConf, &quic.Config{MaxIdleTimeout: 120 * time.Second})
	if err != nil {
		return nil, err
	}
	return &Client{Conn: conn, password: password}, nil
}

func (c *Client) DialTCP(ctx context.Context, addr *chimera.Address) (quic.Stream, error) {
	stream, err := c.Conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	tok := token(c.password)
	buf := []byte{chimera.CmdConnect, byte(len(tok))}
	buf = append(buf, tok...)
	var addrBuf bytes.Buffer
	if err := chimera.WriteAddress(&addrBuf, addr); err != nil {
		stream.Close()
		return nil, err
	}
	buf = append(buf, addrBuf.Bytes()...)
	if _, err := stream.Write(buf); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}


