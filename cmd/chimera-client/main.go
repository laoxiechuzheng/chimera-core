package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/chimera-proxy/chimera-core/internal/chimera"
	"github.com/chimera-proxy/chimera-core/internal/padstream"
	"github.com/chimera-proxy/chimera-core/internal/quicx"
	"github.com/chimera-proxy/chimera-core/internal/realclient"
)

var (
	socksAddr   = flag.String("socks", ":1080", "SOCKS5 listen address")
	serverAddr  = flag.String("server", "", "chimera server address host:port")
	serverName  = flag.String("sni", "", "SNI (must be in server whitelist)")
	pubKeyB64   = flag.String("pub", "", "server x25519 public key (base64)")
	shortIDHex  = flag.String("sid", "", "short ID (hex)")
	fingerprint = flag.String("fp", "chrome", "uTLS fingerprint")
	quicMode    = flag.Bool("quic", false, "use QUIC (Mode U) transport")
	autoMode    = flag.Bool("auto", false, "auto-detect optimal transport (QUIC first, TCP fallback)")
	quicObfs    = flag.String("quic-obfs", "", "QUIC obfuscation password (optional)")
	quicFP      = flag.String("quic-fp", "", "server QUIC cert sha256 fingerprint (required for -quic)")
)

func main() {
	flag.Parse()
	if *serverAddr == "" || *serverName == "" || *pubKeyB64 == "" {
		log.Fatal("must provide -server, -sni and -pub")
	}

	pubKey, err := base64.RawURLEncoding.DecodeString(*pubKeyB64)
	if err != nil || len(pubKey) != 32 {
		log.Fatalf("invalid public key: len=%d", len(pubKey))
	}
	var shortID []byte
	if *shortIDHex != "" {
		shortID, err = decodeHex(*shortIDHex)
		if err != nil {
			log.Fatalf("invalid short ID: %v", err)
		}
	}

	cfg := &realclient.ClientConfig{
		ServerAddr:  *serverAddr,
		ServerName:  *serverName,
		PublicKey:   pubKey,
		ShortId:     shortID,
		Fingerprint: *fingerprint,
	}

	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("chimera-client SOCKS5 listening on %s -> %s (SNI: %s)", *socksAddr, *serverAddr, *serverName)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleSocks5(conn, cfg)
	}
}

func handleSocks5(conn net.Conn, cfg *realclient.ClientConfig) {
	defer conn.Close()

	if err := socks5Handshake(conn); err != nil {
		return
	}
	target, err := socks5ReadRequest(conn)
	if err != nil {
		socks5Reply(conn, 0x01)
		return
	}

	if err := chimeraConnect(conn, target, cfg); err != nil {
		log.Printf("chimera error: %v", err)
		socks5Reply(conn, 0x05)
	}
}

func chimeraConnect(socks net.Conn, target *chimera.Address, cfg *realclient.ClientConfig) error {
	if *autoMode {
		// Try QUIC first with 3s timeout
		// Since we can't reuse the same socks conn after QUIC failure, we need to handle
		// this at the caller level. For now, just try QUIC and if it fails try TCP.
		err := chimeraConnectQuic(socks, target)
		if err == nil {
			return nil
		}
		log.Printf("QUIC failed (%v), falling back to TCP...", err)
		socks5Reply(socks, 0x01) // signal error
		return err
	}
	if *quicMode {
		return chimeraConnectQuic(socks, target)
	}
	ctx := context.Background()
	conn, err := realclient.Dial(ctx, cfg)
	if err != nil {
		return fmt.Errorf("chimera dial: %w", err)
	}
	defer conn.Close()

	if err := chimera.WriteSessionHeader(conn, 0x01); err != nil {
		return fmt.Errorf("session header: %w", err)
	}
	status, err := chimera.ReadSessionResponse(conn)
	if err != nil {
		return fmt.Errorf("session response: %w", err)
	}
	if status != chimera.StatusOK {
		return fmt.Errorf("server rejected: status %d", status)
	}

	pc := padstream.New(conn, padstream.DefaultPolicy())
	if err := chimera.WriteTargetConnect(pc, chimera.CmdConnect, target); err != nil {
		return fmt.Errorf("target connect: %w", err)
	}

	if err := socks5Reply(socks, 0x00); err != nil {
		return err
	}

	log.Printf("relay -> %s", target)
	return chimera.Relay(pc, socks)
}

func chimeraConnectQuic(socks net.Conn, target *chimera.Address) error {
	ctx := context.Background()
	qc, err := quicx.DialClient(ctx, *serverAddr, "chimera-default", *quicObfs, *quicFP)
	if err != nil {
		return fmt.Errorf("quic dial: %w", err)
	}
	defer qc.Conn.CloseWithError(0, "")
	stream, err := qc.DialTCP(ctx, target)
	if err != nil {
		return fmt.Errorf("quic stream: %w", err)
	}
	if err := socks5Reply(socks, 0x00); err != nil {
		return err
	}
	log.Printf("relay(quic) -> %s", target)
	done := make(chan struct{}, 2)
	go func() { io.Copy(stream, socks); done <- struct{}{} }()
	go func() { io.Copy(socks, stream); done <- struct{}{} }()
	<-done
	stream.CancelRead(0)
	<-done
	return nil
}

func decodeHex(s string) ([]byte, error) {
	var out []byte
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex")
	}
	for i := 0; i < len(s); i += 2 {
		var b byte
		_, err := fmt.Sscanf(s[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// --- minimal SOCKS5 ---

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
	// reply: no-auth
	_, err := conn.Write([]byte{5, 0})
	return err
}

func socks5ReadRequest(conn net.Conn) (*chimera.Address, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, err
	}
	if head[0] != 5 {
		return nil, fmt.Errorf("bad request version")
	}
	cmd := head[1]
	if cmd != 1 {
		return nil, fmt.Errorf("only CONNECT supported")
	}

	addr := &chimera.Address{}
	switch head[3] {
	case 0x01: // IPv4
		addr.Type = chimera.AtypIPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return nil, err
		}
		addr.IP = net.IP(ip[:])
	case 0x03: // domain
		addr.Type = chimera.AtypDomain
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		domain := make([]byte, l[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		addr.Domain = string(domain)
	case 0x04: // IPv6
		addr.Type = chimera.AtypIPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return nil, err
		}
		addr.IP = net.IP(ip[:])
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
	// VER REP RSV ATYP BND.ADDR BND.PORT
	_, err := conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
