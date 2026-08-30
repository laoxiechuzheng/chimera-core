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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chimera-proxy/chimera-core/internal/chimera"
	"github.com/quic-go/quic-go"
)

// v0.4 "h3 camouflage mode":
//
// Camouflage goals, aligned with TCP/REALITY mode:
//   1. Handshake looks like standard HTTP/3: ALPN is exactly "h3", TLS
//      settings are quic-go defaults (no exotic fingerprints).
//   2. Active probes get a real website: any h3 connection that does not
//      authenticate as chimera is reverse-proxied to the REALITY target site
//      over TCP/TLS, so a prober browsing "our" server sees the borrowed
//      site's actual pages.
//   3. Proxy traffic rides in ordinary QUIC streams next to the decoy h3
//      service; the protocol bytes are inside QUIC encryption and the
//      per-stream chimera v2 auth (nonce + HMAC + replay cache).
//
// Certificate note: like most h3 deployments we serve a self-signed ECDSA
// cert. Clients pin its SHA-256 fingerprint (mandatory, enforced below), so
// MITM is impossible for real users. A passive observer sees a normal QUIC
// certificate; an active prober is answered by the real-site reverse proxy.

const h3ALPN = "h3"

func generateCert() (tls.Certificate, string, error) {
	// Persist the certificate so the fingerprint stays stable across restarts.
	// Path can be overridden with CHIMERA_QUIC_CERT; default is quic-cert.pem
	// in the working directory (installer places it in /opt/chimera).
	certPath := "quic-cert.pem"
	if v := os.Getenv("CHIMERA_QUIC_CERT"); v != "" {
		certPath = v
	}
	if b, err := os.ReadFile(certPath); err == nil {
		block, _ := pem.Decode(b)
		if block != nil {
			cert, err := tls.X509KeyPair(b, b)
			if err == nil {
				sum := sha256.Sum256(cert.Certificate[0])
				return cert, hex.EncodeToString(sum[:]), nil
			}
		}
	}
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
	// Save cert+key together in one PEM so it can be reloaded.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	var pemBuf bytes.Buffer
	pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&pemBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, pemBuf.Bytes(), 0600); err != nil {
		// Non-fatal: fingerprint just won't persist.
		_ = err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

type Server struct {
	listener  *quic.Listener
	passwords []string
	replay    *chimera.ReplayCache
	target    string // host:port of the REALITY target site for probe fallback
}

// ListenServer starts the camouflaged QUIC endpoint. password and target are
// mandatory: no password would recreate the open-proxy hole, no target would
// leave active probes unanswered.
func ListenServer(ctx context.Context, listenAddr string, passwords []string, target string) (*Server, string, error) {
	if len(passwords) == 0 {
		return nil, "", errors.New("quicx: refusing to listen without a password (open proxy guard)")
	}
	for _, p := range passwords {
		if p == "" {
			return nil, "", errors.New("quicx: empty password in list")
		}
	}
	if target == "" {
		return nil, "", errors.New("quicx: refusing to listen without a fallback target")
	}
	cert, fingerprint, err := generateCert()
	if err != nil {
		return nil, "", err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{h3ALPN},
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
		listener:  listener,
		passwords: passwords,
		replay:    chimera.NewReplayCache(10 * time.Minute),
		target:    target,
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

// isChimeraClient distinguishes our clients from ordinary h3 traffic without
// adding any handshake-visible marker: our clients open their first
// bidirectional stream and immediately send a fixed 4-byte magic that no h3
// client would send (h3 control streams start with known type varints).
func isChimeraFirstBytes(b []byte) bool {
	return len(b) >= 4 && b[0] == chimera.MagicByte0 && b[1] == chimera.MagicByte1 &&
		b[2] == chimera.MagicByte2 && b[3] == chimera.MagicByte3
}

func (s *Server) handleConn(ctx context.Context, conn quic.Connection) {
	// Peek the first bytes of the first stream to classify the connection.
	first, err := conn.AcceptStream(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return
	}
	head := make([]byte, 4)
	first.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(first, head); err != nil {
		first.Close()
		conn.CloseWithError(0, "")
		return
	}
	first.SetReadDeadline(time.Time{})

	if isChimeraFirstBytes(head) {
		// The 4 magic bytes are prepended back via prefixReader inside the
		// handler so the v2 frame parser sees the full frame.
		go s.handleChimeraStream(ctx, conn, first, head)
		// Additional streams on this connection belong to the same client.
		for {
			st, err := conn.AcceptStream(ctx)
			if err != nil {
				conn.CloseWithError(0, "")
				return
			}
			go s.handleChimeraStream(ctx, conn, st, nil)
		}
	}

	// Not a chimera client: serve as reverse proxy of the real site (h3).
	go s.serveProbe(ctx, conn, first, head)
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			conn.CloseWithError(0, "")
			return
		}
		go s.serveProbeStream(ctx, st, head)
	}
}

func (s *Server) handleChimeraStream(ctx context.Context, conn quic.Connection, stream quic.Stream, prefix []byte) {
	defer stream.Close()

	reader := io.Reader(stream)
	if prefix != nil {
		reader = newPrefixReader(stream, prefix)
	}
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var cmd byte
	var addr *chimera.Address
	var err error
	for _, pw := range s.passwords {
		cmd, addr, err = chimera.ReadQUICConnectWithCache(reader, pw, s.replay)
		if err == nil {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, chimera.ErrBadMagic) || errors.Is(err, chimera.ErrVersionMismatch) {
			// Frame is malformed rather than mis-authenticated: stop early.
			return
		}
	}
	if err != nil {
		return
	}
	stream.SetReadDeadline(time.Time{})
	if cmd != chimera.CmdConnect {
		return
	}
	if chimera.IsForbiddenTarget(addr) {
		_ = chimera.WriteQUICResult(stream, chimera.QUICStatusDialError)
		return
	}

	dialer := net.Dialer{}
	target, err := dialer.DialContext(ctx, "tcp", addr.String())
	if err != nil {
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

// serveProbe handles a full non-authenticated connection: we answer h3-style
// with content reverse-proxied from the real target so probers see a working
// website. QUIC-level h3 request parsing is heavy; instead we accept both
// plain HTTP/1.1-in-stream probes and h3 control probes and always respond
// with the real site's HTTP/1.1 response over the stream. Browsers doing
// real h3 would not interop, but browsers never connect here (cert is
// pinned for real users only); what matters is prober tooling seeing a real
// site response.
func (s *Server) serveProbe(ctx context.Context, conn quic.Connection, first quic.Stream, head []byte) {
	defer conn.CloseWithError(0, "")
	s.serveProbeStreamWithPrefix(ctx, first, head)
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.serveProbeStream(ctx, st, nil)
	}
}

func (s *Server) serveProbeStream(ctx context.Context, st quic.Stream, prefix []byte) {
	s.serveProbeStreamWithPrefix(ctx, st, prefix)
}

func (s *Server) serveProbeStreamWithPrefix(ctx context.Context, st quic.Stream, prefix []byte) {
	defer st.Close()
	// Drain whatever the prober sends (we do not need to parse it).
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := st.Read(buf); err != nil {
			break
		}
	}
	st.SetReadDeadline(time.Time{})

	// Fetch the real site's root page over TCP/TLS and relay it verbatim.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+strings.TrimSuffix(s.target, ":443")+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprint(st, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	st.SetWriteDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(st, "HTTP/1.1 %s\r\n", resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(st, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprint(st, "\r\n")
	io.Copy(st, resp.Body)
}

// prefixReader replays bytes already consumed during classification.
type prefixReader struct {
	r      io.Reader
	prefix []byte
	off    int
}

func newPrefixReader(r io.Reader, prefix []byte) *prefixReader {
	return &prefixReader{r: r, prefix: prefix}
}

func (p *prefixReader) Read(b []byte) (int, error) {
	if p.off < len(p.prefix) {
		n := copy(b, p.prefix[p.off:])
		p.off += n
		return n, nil
	}
	return p.r.Read(b)
}

type Client struct {
	Conn     quic.EarlyConnection
	password string
}

// DialClient dials with standard h3 ALPN. Certificate fingerprint pinning is
// mandatory - there is no insecure mode.
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
		InsecureSkipVerify: true, // pinned by fingerprint below instead of CA
		NextProtos:         []string{h3ALPN},
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

// DialTCP opens a stream, sends the authed connect frame, waits for dial
// result. Nil error means the target is connected end to end.
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
