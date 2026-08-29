package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

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
	quicObfs := flag.String("quic-obfs", "", "QUIC obfuscation password (optional)")
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

	if *quicListen == "" && *listen != "" {
		// Auto-share the same port number for UDP (single-port mode)
		_, port, _ := net.SplitHostPort(*listen)
		*quicListen = ":" + port
	}

	if *quicListen != "" {
		pass := *quicPass
		if pass == "" {
			pass = "chimera-default"
		}
		_, _, err := quicx.ListenServer(context.Background(), *quicListen, pass, *quicObfs)
		if err != nil {
			log.Fatalf("quic listen: %v", err)
		}
		log.Printf("chimera-server QUIC listening on UDP %s (anti-QoS pipeline active)", *quicListen)
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

	target, err := net.DialTimeout("tcp", addr.String(), 10*1e9)
	if err != nil {
		log.Printf("dial %s: %v", addr, err)
		return
	}
	defer target.Close()
	log.Printf("connected: %s", addr)

	chimera.Relay(pc, target)
}
