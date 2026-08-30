package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/laoxiechuzheng/chimera-core/internal/chimera"
	"github.com/laoxiechuzheng/chimera-core/internal/padstream"
	"github.com/laoxiechuzheng/chimera-core/internal/quicx"
	"github.com/laoxiechuzheng/chimera-core/internal/realserv"
)

const defaultUDPRelayEnabled = true

func main() {
	genKey := flag.Bool("genkey", false, "generate REALITY keypair, short ID and QUIC PSK")
	genPSK := flag.Bool("genpsk", false, "generate an independent 32-byte QUIC PSK")
	quicCertInfo := flag.Bool("quic-cert-info", false, "create/load the QUIC certificate and print its fingerprint")
	systemdUnit := flag.Bool("systemd-unit", false, "render a hardened systemd unit and exit")
	installDir := flag.String("install-dir", "/opt/chimera", "installation directory used by -systemd-unit")
	listen := flag.String("listen", ":443", "TCP listen address")
	target := flag.String("target", "www.microsoft.com:443", "REALITY and decoy target host:port")
	sniList := flag.String("sni", "www.microsoft.com", "comma-separated SNI whitelist")
	privKeyB64 := flag.String("key", envFirst("CHIMERA_PRIVATE_KEY", "PRIV"), "x25519 private key (base64url; prefer CHIMERA_PRIVATE_KEY env)")
	sidList := flag.String("sid", envFirst("CHIMERA_SHORT_IDS", "SID"), "comma-separated short IDs (hex; prefer CHIMERA_SHORT_IDS env)")
	show := flag.Bool("show", false, "show REALITY debug output")
	quicListen := flag.String("quic", "", "HTTP/3 QUIC listen address (UDP; defaults to -listen)")
	quicPSKB64 := flag.String("quic-psk", os.Getenv("CHIMERA_QUIC_PSK"), "independent 32-byte QUIC PSK (base64url; prefer env)")
	quicCertPath := flag.String("quic-cert", os.Getenv("CHIMERA_QUIC_CERT"), "persisted self-signed QUIC certificate path")
	quicCertFile := flag.String("quic-cert-file", "", "CA-signed QUIC certificate file")
	quicKeyFile := flag.String("quic-key-file", "", "CA-signed QUIC private key file")
	quicDisable := flag.Bool("no-quic", false, "disable the QUIC listener")
	udpDisable := flag.Bool("no-udp", false, "disable UDP relay over HTTP/3 datagrams")
	printFP := flag.Bool("print-quic-fp", false, "print the QUIC certificate fingerprint")
	flag.Parse()

	if *genPSK {
		psk, err := generatePSK()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("QUIC PSK:     %s\n", psk)
		return
	}
	if *genKey {
		priv, pub, err := chimera.GenerateKeyPair()
		if err != nil {
			log.Fatal(err)
		}
		sid := make([]byte, 8)
		if _, err := rand.Read(sid); err != nil {
			log.Fatal(err)
		}
		psk, err := generatePSK()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Private Key: %s\n", priv)
		fmt.Printf("Public Key:  %s\n", pub)
		fmt.Printf("Short ID:    %s\n", hex.EncodeToString(sid))
		fmt.Printf("QUIC PSK:    %s\n", psk)
		return
	}

	serverNames := parseServerNames(*sniList)
	if len(serverNames) == 0 {
		log.Fatal("at least one SNI is required")
	}
	if *systemdUnit {
		unit, err := renderSystemdUnit(*installDir, *listen, *target, serverNames[0])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print(unit)
		return
	}
	if *quicCertInfo {
		path := strings.TrimSpace(*quicCertPath)
		if path == "" {
			path = "quic-v5-cert.pem"
		}
		fingerprint, err := quicx.EnsureCertificate(path, serverNames[0])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("QUIC Fingerprint: %s\n", fingerprint)
		return
	}
	if *privKeyB64 == "" {
		log.Fatal("must provide CHIMERA_PRIVATE_KEY or -key")
	}
	privKey, err := base64.RawURLEncoding.DecodeString(*privKeyB64)
	if err != nil || len(privKey) != 32 {
		log.Fatalf("invalid private key: %v (len=%d)", err, len(privKey))
	}
	shortIDs, err := parseShortIDs(*sidList)
	if err != nil {
		log.Fatal(err)
	}
	if len(shortIDs) == 0 {
		log.Fatal("at least one short ID is required")
	}

	realityConfig := &realserv.ServerConfig{
		ListenAddr:  *listen,
		Target:      *target,
		ServerNames: serverNames,
		PrivateKey:  privKey,
		ShortIds:    shortIDs,
		Show:        *show,
	}
	listener, err := realserv.Listen(realityConfig)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("chimera-server TCP/REALITY listening on %s (SNI: %v, target: %s)", *listen, serverNames, *target)

	if !*quicDisable {
		if *quicListen == "" {
			*quicListen = *listen
		}
		psk, err := decodePSK(*quicPSKB64)
		if err != nil {
			log.Fatal(err)
		}
		curve := ecdh.X25519()
		privateKey, err := curve.NewPrivateKey(privKey)
		if err != nil {
			log.Fatalf("invalid x25519 private key: %v", err)
		}
		authKeys, err := deriveServerAuthKeys(psk, privateKey.PublicKey().Bytes(), shortIDs)
		if err != nil {
			log.Fatal(err)
		}
		server, info, err := quicx.ListenServerWithConfig(context.Background(), quicx.ServerConfig{
			ListenAddr:      *quicListen,
			ServerName:      serverNames[0],
			AuthKeys:        authKeys,
			CertificatePath: *quicCertPath,
			CertificateFile: *quicCertFile,
			PrivateKeyFile:  *quicKeyFile,
			DecoyTarget:     *target,
			EnableUDPRelay:  defaultUDPRelayEnabled && !*udpDisable,
		})
		if err != nil {
			log.Fatalf("HTTP/3 listen: %v", err)
		}
		_ = server
		log.Printf("chimera-server HTTP/3 CONNECT listening on UDP %s", info.Addr)
		log.Printf("chimera-server QUIC certificate fingerprint: %s", info.Fingerprint)
		if *printFP {
			fmt.Printf("QUIC Fingerprint: %s\n", info.Fingerprint)
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
	validatedTarget, err := chimera.ResolveAndValidateAuthority(context.Background(), addr.String(), nil)
	if err != nil {
		log.Printf("blocked target %s: %v", addr, err)
		_ = chimera.WriteSessionResponse(pc, chimera.StatusDialError)
		return
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	target, err := dialer.DialContext(context.Background(), "tcp", validatedTarget)
	if err != nil {
		log.Printf("dial %s: %v", validatedTarget, err)
		_ = chimera.WriteSessionResponse(pc, chimera.StatusDialError)
		return
	}
	defer target.Close()
	if err := chimera.WriteSessionResponse(pc, chimera.StatusOK); err != nil {
		return
	}
	log.Printf("connected: %s", validatedTarget)
	_ = chimera.Relay(pc, target)
}

func generatePSK() (string, error) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(psk), nil
}

func decodePSK(encoded string) ([]byte, error) {
	psk, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(psk) != 32 {
		return nil, errors.New("CHIMERA_QUIC_PSK / -quic-psk must be a base64url-encoded 32-byte secret")
	}
	return psk, nil
}

func deriveServerAuthKeys(psk, publicKey []byte, shortIDs [][]byte) ([][]byte, error) {
	if len(shortIDs) == 0 {
		return nil, errors.New("cannot derive QUIC keys without short IDs")
	}
	keys := make([][]byte, 0, len(shortIDs))
	for _, shortID := range shortIDs {
		key, err := quicx.DeriveAuthKey(psk, publicKey, shortID)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func parseServerNames(value string) []string {
	var names []string
	for _, item := range strings.Split(value, ",") {
		if name := strings.ToLower(strings.TrimSpace(item)); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func parseShortIDs(value string) ([][]byte, error) {
	var shortIDs [][]byte
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		shortID, err := hex.DecodeString(item)
		if err != nil || len(shortID) == 0 || len(shortID) > 8 {
			return nil, fmt.Errorf("invalid short ID %q", item)
		}
		shortIDs = append(shortIDs, shortID)
	}
	return shortIDs, nil
}

func envFirst(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func renderSystemdUnit(installDir, listen, target, sni string) (string, error) {
	installDir = strings.TrimSuffix(strings.TrimSpace(installDir), "/")
	listen = strings.TrimSpace(listen)
	target = strings.TrimSpace(target)
	sni = strings.TrimSpace(sni)
	if !strings.HasPrefix(installDir, "/") || installDir == "/" || strings.ContainsAny(installDir, "\t\r\n '"+"\"") {
		return "", errors.New("invalid install directory for systemd unit")
	}
	for name, value := range map[string]string{"listen": listen, "target": target, "sni": sni} {
		if value == "" || strings.ContainsAny(value, "\t\r\n '"+"\"") {
			return "", fmt.Errorf("invalid %s value for systemd unit", name)
		}
	}
	binaryPath := path.Join(installDir, "chimera-server")
	keysPath := path.Join(installDir, "keys.env")
	return fmt.Sprintf(`[Unit]
Description=Chimera Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=%s
Environment=CHIMERA_QUIC_CERT=/var/lib/chimera/quic-v5-cert.pem
ExecStart=%s -listen %s -target %s -sni %s
DynamicUser=true
WorkingDirectory=/var/lib/chimera
StateDirectory=chimera
StateDirectoryMode=0700
UMask=0077
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
`, keysPath, binaryPath, listen, target, sni), nil
}
