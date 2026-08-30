package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/chimera-proxy/chimera-core/internal/chimera"
	"github.com/chimera-proxy/chimera-core/internal/padstream"
	"github.com/chimera-proxy/chimera-core/internal/quicx"
	"github.com/chimera-proxy/chimera-core/internal/realclient"
)

var (
	socksAddr       = flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address")
	serverAddr      = flag.String("server", "", "chimera server address host:port")
	serverName      = flag.String("sni", "", "SNI (must be in server whitelist)")
	pubKeyB64       = flag.String("pub", "", "server x25519 public key (base64url)")
	shortIDHex      = flag.String("sid", "", "short ID (hex)")
	fingerprint     = flag.String("fp", "chrome", "uTLS fingerprint")
	quicMode        = flag.Bool("quic", false, "use HTTP/3 QUIC transport")
	autoMode        = flag.Bool("auto", false, "try QUIC first, then TCP/REALITY")
	quicPSKB64      = flag.String("quic-psk", "", "independent 32-byte QUIC PSK (base64url; required for -quic/-auto)")
	quicFP          = flag.String("quic-fp", "", "server QUIC certificate SHA-256 fingerprint")
	autoQUICTimeout = flag.Duration("auto-quic-timeout", 1200*time.Millisecond, "maximum QUIC selection time before TCP fallback")
)

type runtimeConfig struct {
	reality         *realclient.ClientConfig
	mode            string
	serverAddr      string
	serverName      string
	quicAuthKey     []byte
	quicFingerprint string
	autoQUICTimeout time.Duration
}

func main() {
	flag.Parse()
	if *serverAddr == "" || *serverName == "" || *pubKeyB64 == "" {
		log.Fatal("must provide -server, -sni and -pub")
	}
	mode, err := selectedMode(*quicMode, *autoMode)
	if err != nil {
		log.Fatal(err)
	}
	if *autoQUICTimeout <= 0 {
		log.Fatal("-auto-quic-timeout must be positive")
	}
	pubKey, err := base64.RawURLEncoding.DecodeString(*pubKeyB64)
	if err != nil || len(pubKey) != 32 {
		log.Fatalf("invalid public key: len=%d", len(pubKey))
	}
	shortID, err := decodeShortID(*shortIDHex)
	if err != nil {
		log.Fatalf("invalid short ID: %v", err)
	}
	psk, err := validateQUICConfig(mode, *quicPSKB64, *quicFP)
	if err != nil {
		log.Fatal(err)
	}
	var quicAuthKey []byte
	if mode != "tcp" {
		quicAuthKey, err = quicx.DeriveAuthKey(psk, pubKey, shortID)
		if err != nil {
			log.Fatalf("derive QUIC auth key: %v", err)
		}
	}
	cfg := &runtimeConfig{
		reality: &realclient.ClientConfig{
			ServerAddr:  *serverAddr,
			ServerName:  *serverName,
			PublicKey:   pubKey,
			ShortId:     shortID,
			Fingerprint: *fingerprint,
		},
		mode:            mode,
		serverAddr:      *serverAddr,
		serverName:      *serverName,
		quicAuthKey:     quicAuthKey,
		quicFingerprint: *quicFP,
		autoQUICTimeout: *autoQUICTimeout,
	}

	listener, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("chimera-client SOCKS5 listening on %s -> %s (SNI: %s, mode: %s)", *socksAddr, *serverAddr, *serverName, mode)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleSocks5(conn, cfg)
	}
}

func handleSocks5(conn net.Conn, cfg *runtimeConfig) {
	defer conn.Close()
	if err := socks5Handshake(conn); err != nil {
		return
	}
	target, err := socks5ReadRequest(conn)
	if err != nil {
		_ = socks5Reply(conn, 0x01)
		return
	}
	if err := chimeraConnect(conn, target, cfg); err != nil {
		log.Printf("chimera error: %v", err)
		_ = socks5Reply(conn, 0x05)
	}
}

func chimeraConnect(socks net.Conn, target *chimera.Address, cfg *runtimeConfig) error {
	ctx := context.Background()
	proxy, err := selectTransport(ctx, cfg.mode, cfg.autoQUICTimeout,
		func(dialCtx context.Context) (transportConn, error) {
			conn, err := dialChimeraQUIC(dialCtx, target, cfg)
			if err != nil && cfg.mode == "auto" {
				log.Printf("QUIC unavailable (%v), falling back to TCP/REALITY", err)
			}
			return conn, err
		},
		func(dialCtx context.Context) (transportConn, error) {
			return dialChimeraTCP(dialCtx, target, cfg.reality)
		},
	)
	if err != nil {
		return err
	}
	defer proxy.Close()
	if err := socks5Reply(socks, 0x00); err != nil {
		return err
	}
	log.Printf("relay(%s) -> %s", cfg.mode, target)
	return chimera.Relay(proxy, socks)
}

func dialChimeraTCP(ctx context.Context, target *chimera.Address, cfg *realclient.ClientConfig) (transportConn, error) {
	conn, err := realclient.Dial(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("chimera dial: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	if err := chimera.WriteSessionHeader(conn, 0x01); err != nil {
		return nil, fmt.Errorf("session header: %w", err)
	}
	status, err := chimera.ReadSessionResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("session response: %w", err)
	}
	if status != chimera.StatusOK {
		return nil, fmt.Errorf("server rejected: status %d", status)
	}
	pc := padstream.New(conn, padstream.DefaultPolicy())
	if err := chimera.WriteTargetConnect(pc, chimera.CmdConnect, target); err != nil {
		return nil, fmt.Errorf("target connect: %w", err)
	}
	status, err = chimera.ReadSessionResponse(pc)
	if err != nil {
		return nil, fmt.Errorf("connect result: %w", err)
	}
	if status != chimera.StatusOK {
		return nil, fmt.Errorf("server dial failed: status %d", status)
	}
	success = true
	return pc, nil
}

func dialChimeraQUIC(ctx context.Context, target *chimera.Address, cfg *runtimeConfig) (transportConn, error) {
	client, err := quicx.DialClientWithConfig(ctx, quicx.ClientConfig{
		ServerAddr:      cfg.serverAddr,
		ServerName:      cfg.serverName,
		AuthKey:         cfg.quicAuthKey,
		CertFingerprint: cfg.quicFingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}
	stream, err := client.DialTCP(ctx, target)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("quic CONNECT: %w", err)
	}
	return &ownedConn{Conn: stream, closeOwner: client.Close}, nil
}

type transportConn interface {
	io.ReadWriteCloser
}

type transportDial func(context.Context) (transportConn, error)

func selectTransport(ctx context.Context, mode string, quicTimeout time.Duration, dialQUIC, dialTCP transportDial) (transportConn, error) {
	switch mode {
	case "tcp":
		return dialTCP(ctx)
	case "quic":
		return dialQUIC(ctx)
	case "auto":
		if quicTimeout <= 0 {
			return nil, errors.New("chimera: QUIC selection timeout must be positive")
		}
		quicCtx, cancel := context.WithTimeout(ctx, quicTimeout)
		conn, quicErr := dialQUIC(quicCtx)
		cancel()
		if quicErr == nil {
			return conn, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		return dialTCP(ctx)
	default:
		return nil, fmt.Errorf("chimera: unknown transport mode %q", mode)
	}
}

func selectedMode(forceQUIC, automatic bool) (string, error) {
	if forceQUIC && automatic {
		return "", errors.New("chimera: -quic and -auto are mutually exclusive")
	}
	if forceQUIC {
		return "quic", nil
	}
	if automatic {
		return "auto", nil
	}
	return "tcp", nil
}

func validateQUICConfig(mode, pskText, fingerprint string) ([]byte, error) {
	if mode == "tcp" {
		return nil, nil
	}
	psk, err := base64.RawURLEncoding.DecodeString(pskText)
	if err != nil || len(psk) != 32 {
		return nil, errors.New("chimera: -quic-psk must be a base64url-encoded 32-byte secret")
	}
	fp, err := hex.DecodeString(fingerprint)
	if err != nil || len(fp) != 32 {
		return nil, errors.New("chimera: -quic-fp must be a 64-character SHA-256 hex fingerprint")
	}
	return psk, nil
}

type ownedConn struct {
	net.Conn
	closeOwner func() error
	once       sync.Once
	err        error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() {
		var connErr, ownerErr error
		if c.Conn != nil {
			connErr = c.Conn.Close()
		}
		if c.closeOwner != nil {
			ownerErr = c.closeOwner()
		}
		c.err = errors.Join(connErr, ownerErr)
	})
	return c.err
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex")
	}
	out := make([]byte, len(s)/2)
	if _, err := hex.Decode(out, []byte(s)); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeShortID(s string) ([]byte, error) {
	shortID, err := decodeHex(s)
	if err != nil {
		return nil, err
	}
	if len(shortID) == 0 || len(shortID) > 8 {
		return nil, errors.New("short ID must contain 1 to 8 bytes")
	}
	return shortID, nil
}

func socks5Handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	ver, nMethods := buf[0], buf[1]
	if ver != 5 {
		return fmt.Errorf("bad socks5 version %d", ver)
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == 0 {
			_, err := conn.Write([]byte{5, 0})
			return err
		}
	}
	_, _ = conn.Write([]byte{5, 0xff})
	return errors.New("socks5: client did not offer no-auth method")
}

func socks5ReadRequest(conn net.Conn) (*chimera.Address, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	if head[0] != 5 {
		return nil, fmt.Errorf("bad request version")
	}
	if head[1] != 1 {
		return nil, fmt.Errorf("only CONNECT supported")
	}
	addr := &chimera.Address{}
	switch head[3] {
	case 0x01:
		addr.Type = chimera.AtypIPv4
		ip := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		addr.IP = net.IP(ip)
	case 0x03:
		addr.Type = chimera.AtypDomain
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		addr.Domain = string(domain)
	case 0x04:
		addr.Type = chimera.AtypIPv6
		ip := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		addr.IP = net.IP(ip)
	default:
		return nil, fmt.Errorf("bad address type")
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return nil, err
	}
	addr.Port = binary.BigEndian.Uint16(portBuf[:])
	return addr, nil
}

func socks5Reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
