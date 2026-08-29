package quicx

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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

const quicALPN = "chimera-quic/2"

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

// Server accepts QUIC connections authenticated with the Chimera v2 auth
// frame. password is mandatory; ListenServer refuses an empty one so the
// open-proxy failure mode of v0.x can never return.
type Server struct {
	listener *quic.Listener
	password string
	replay   *chimera.ReplayCache
}

func ListenServer(ctx context.Context, listenAddr, password string) (*Server, string, error) {
	if password == "" {
		return nil, "", errors.New("quicx: refusing to listen without a password (open proxy guard)")
	}
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
	listener, err := quic.Listen(pc, tlsConf, &quic.Config{MaxIdleTimeout: 120 * time.Second})
	if err != nil {
		return nil, "", err
	}
	s := &Server{
		listener: listener,
		password: password,
		replay:   chimera.NewReplayCache(10 * time.Minute),
	}
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

	// Auth deadline: unauthenticated streams get at most 10s.
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	cmd, addr, err := readAuthedConnect(stream, s.password, s.replay)
	if err != nil {
		return
	}
	stream.SetReadDeadline(time.Time{})
	if cmd != chimera.CmdConnect {
		return
	}

	dialer := net.Dialer{}
	target, err := dialer.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		// v2 protocol: tell the client the dial failed instead of hanging.
		_ = chimera.WriteQUICResult(stream, chimera.QUICStatusDialError)
		return
	}
	defer target.Close()
	if err := chimera.WriteQUICResult(stream, chimera.QUICStatusOK); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, stream); done <- struct{}{} }()
	go func() { io.Copy(stream, target); done <- struct{}{} }()
	<-done
	stream.CancelRead(0)
	<-done
}

// readAuthedConnect delegates to the shared chimera v2 parser.
func readAuthedConnect(r io.Reader, password string, replay *chimera.ReplayCache) (byte, *chimera.Address, error) {
	return chimera.ReadQUICConnectWithCache(r, password, replay)
}

type Client struct {
	Conn     quic.EarlyConnection
	password string
}

// DialClient requires both the derived password and the server certificate
// fingerprint. Without a fingerprint the connection is refused — this closes
// the InsecureSkipVerify hole from v0.x.
func DialClient(ctx context.Context, serverAddr, password, certFingerprint string) (*Client, error) {
	if password == "" {
		return nil, errors.New("quicx: empty auth password")
	}
	if certFingerprint == "" {
		return nil, errors.New("quicx: certificate fingerprint required (anti-MITM)")
	}
	fp, err := hex.DecodeString(certFingerprint)
	if err != nil || len(fp) != 32 {
		return nil, errors.New("quicx: invalid fingerprint")
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // we pin by fingerprint below instead of CA
		NextProtos:         []string{quicALPN},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("quicx: no certs")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(sum[:], fp) {
				return errors.New("quicx: cert fingerprint mismatch")
			}
			return nil
		},
	}
	conn, err := quic.DialAddrEarly(ctx, serverAddr, tlsConf, &quic.Config{MaxIdleTimeout: 120 * time.Second})
	if err != nil {
		return nil, err
	}
	return &Client{Conn: conn, password: password}, nil
}

// DialTCP opens a stream, sends the authed connect frame, and waits for the
// server's dial-result before returning. A nil error means the server has
// actually connected to the target.
func (c *Client) DialTCP(ctx context.Context, addr *chimera.Address) (quic.Stream, error) {
	stream, err := c.Conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := chimera.WriteQUICConnect(stream, chimera.CmdConnect, c.password, addr); err != nil {
		stream.Close()
		return nil, err
	}
	stream.SetWriteDeadline(time.Time{})

	stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	status, err := chimera.ReadQUICResult(stream)
	stream.SetReadDeadline(time.Time{})
	if err != nil {
		stream.Close()
		return nil, err
	}
	if status != chimera.QUICStatusOK {
		stream.Close()
		return nil, errors.New("quicx: server dial failed")
	}
	return stream, nil
}
