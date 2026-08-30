package main

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/chimera-proxy/chimera-core/internal/chimera"
	"github.com/chimera-proxy/chimera-core/internal/padstream"
	"github.com/chimera-proxy/chimera-core/internal/quicx"
	"github.com/chimera-proxy/chimera-core/internal/realserv"
)

func main() {
	genkey := flag.Bool("genkey", false, "generate x25519 keypair and shortId")
	listen := flag.String("listen", ":443", "listen address")
	target := flag.String("target", "www.microsoft.com:443", "REALITY target site host:port")
	sniList := flag.String("sni", "www.microsoft.com", "comma-separated SNI whitelist")
	privKeyB64 := flag.String("key", "", "x25519 private key (base64 rawurl)")
	sidList := flag.String("sid", "", "comma-separated short IDs (hex)")
	show := flag.Bool("show", false, "show debug output")
	quicListen := flag.String("quic", "", "QUIC listen address (UDP, defaults to same port as -listen). Leave empty to auto-share port with TCP.")
	quicPass := flag.String("quic-pass", "", "QUIC auth password")
	quicDisable := flag.Bool("no-quic", false, "disable the QUIC listener entirely (TCP-only mode)")
	printFP := flag.Bool("print-quic-fp", false, "print the QUIC cert fingerprint at startup (default: log-only)")
	flag.Parse()

	if *genkey {
		priv, pub, err := chimera.GenerateKeyPair()
		if err != nil {
			log.Fatal(err)
		}
		sid := make([]byte, 8)
		rand.Read(sid)
		fmt.Printf("Private Key: %s\n", priv)
		fmt.Printf("Public Key:  %s\n", pub)
		fmt.Printf("Short ID:    %s\n", hex.EncodeToString(sid))
		return
	}

	if *privKeyB64 == "" {
		log.Fatal("must provide -key (x25519 private key)")
	}
	privKey, err := base64.RawURLEncoding.DecodeString(*privKeyB64)
	if err != nil || len(privKey) != 32 {
		log.Fatalf("invalid private key: %v (len=%d)", err, len(privKey))
	}

	var serverNames []string
	for _, s := range strings.Split(*sniList, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			serverNames = append(serverNames, s)
		}
	}

	var shortIds [][]byte
	for _, s := range strings.Split(*sidList, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			log.Fatalf("invalid short ID %q: %v", s, err)
		}
		shortIds = append(shortIds, b)
	}

	cfg := &realserv.ServerConfig{
		ListenAddr:  *listen,
		Target:      *target,
		ServerNames: serverNames,
		PrivateKey:  privKey,
		ShortIds:    shortIds,
		Show:        *show,
	}

	listener, err := realserv.Listen(cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("chimera-server listening on %s (SNI: %v, target: %s)", *listen, serverNames, *target)

	if !*quicDisable {
		if *quicListen == "" && *listen != "" {
			// Auto-share the same host:port for UDP (single-port mode), so a
			// TCP bind to 127.0.0.1 does not silently expose QUIC on all
			// interfaces.
			*quicListen = *listen
		}
		pass := *quicPass
		var passes []string
		if pass != "" {
			passes = []string{pass}
		} else {
			// Derive from the PUBLIC key (base64) + each short ID so the client
			// can compute the identical password from connection info it has.
			curve := ecdh.X25519()
			priv, _ := curve.NewPrivateKey(privKey)
			pubB64 := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
			for _, sid := range shortIds {
				passes = append(passes, deriveQUICPassword(sid, pubB64))
			}
		}
		_, fp, err := quicx.ListenServer(context.Background(), *quicListen, passes, *target)
		if err != nil {
			log.Fatalf("quic listen: %v", err)
		}
		log.Printf("chimera-server QUIC listening on UDP %s (anti-QoS pipeline active)", *quicListen)
		log.Printf("chimera-server QUIC cert fingerprint: %s", fp)
		if *printFP {
			fmt.Printf("QUIC Fingerprint: %s\n", fp)
		}
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

// handleConn handles an authenticated TCP/REALITY connection.
func handleConn(conn net.Conn) {
	defer conn.Close()

	flags, err := chimera.ReadSessionHeader(conn)
	if err != nil {
		if err != io.EOF {
			log.Printf("session header: %v", err)
		}
		return
	}
	if err := chimera.WriteSessionResponse(conn, chimera.StatusOK); err != nil {
		return
	}

	_ = flags
	pc := padstream.New(conn, padstream.DefaultPolicy())

	cmd, addr, err := chimera.ReadTargetConnect(pc)
	if err != nil {
		log.Printf("target connect: %v", err)
		return
	}
	if cmd != chimera.CmdConnect {
		log.Printf("unsupported cmd %d", cmd)
		return
	}
	if chimera.IsForbiddenTarget(addr) {
		log.Printf("blocked private target: %s", addr)
		_ = chimera.WriteSessionResponse(pc, chimera.StatusDialError)
		return
	}

	// Resolve domains and re-check the resolved IPs against the private
	// guard, so DNS names cannot bypass the private-network block.
	var target net.Conn
	if addr.Type == chimera.AtypDomain {
		ips, rerr := net.LookupIP(addr.Domain)
		if rerr != nil {
			log.Printf("resolve %s: %v", addr.Domain, rerr)
			_ = chimera.WriteSessionResponse(pc, chimera.StatusDialError)
			return
		}
		blocked := len(ips) > 0
		for _, ip := range ips {
			a4 := &chimera.Address{Type: chimera.AtypIPv4, IP: ip, Port: addr.Port}
			a6 := &chimera.Address{Type: chimera.AtypIPv6, IP: ip, Port: addr.Port}
			if !chimera.IsForbiddenTarget(a4) && !chimera.IsForbiddenTarget(a6) {
				blocked = false
				break
			}
		}
		if blocked {
			log.Printf("blocked private DNS target: %s", addr)
			_ = chimera.WriteSessionResponse(pc, chimera.StatusDialError)
			return
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	target, err = dialer.DialContext(context.Background(), "tcp", addr.String())
	if err != nil {
		log.Printf("dial %s: %v", addr, err)
		// Tell the client the target dial failed so it can surface an error
		// instead of hanging. Uses the same v2 result-frame shape as QUIC.
		_ = chimera.WriteSessionResponse(pc, chimera.StatusDialError)
		return
	}
	defer target.Close()
	log.Printf("connected: %s", addr)

	// v2 protocol: confirm to the client that the target is connected before
	// streaming. The client now expects this frame after sending CONNECT.
	if err := chimera.WriteSessionResponse(pc, chimera.StatusOK); err != nil {
		return
	}

	chimera.Relay(pc, target)
}

// deriveQUICPassword derives the QUIC auth password from the REALITY short ID
// and private key material. Both server and clients can compute the same value
// from credentials they already share, so no second secret needs configuring.
func deriveQUICPassword(shortID []byte, privKeyB64 string) string {
	h := hmac.New(sha256.New, []byte("chimera-quic-key-v2"))
	h.Write(shortID)
	h.Write([]byte(privKeyB64))
	return string(h.Sum(nil))
}
