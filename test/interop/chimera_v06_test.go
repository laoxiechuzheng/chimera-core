package interop

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestChimeraV06MihomoUDPTwoDestinationInterop(t *testing.T) {
	if os.Getenv("CHIMERA_INTEROP") != "1" {
		t.Skip("set CHIMERA_INTEROP=1 with MIHOMO_DIR to run cross-repository interop")
	}
	mihomoDir := strings.TrimSpace(os.Getenv("MIHOMO_DIR"))
	if mihomoDir == "" {
		t.Fatal("MIHOMO_DIR is required when CHIMERA_INTEROP=1")
	}
	if err := runChimeraV06MihomoUDPInterop(t, mihomoDir); err != nil {
		t.Fatal(err)
	}
}

const interopSNI = "interop.example"

type interopCredentials struct {
	privateKey string
	publicKey  string
	shortID    string
	quicPSK    string
	quicFP     string
}

func runChimeraV06MihomoUDPInterop(t *testing.T, mihomoDir string) error {
	t.Helper()
	if info, err := os.Stat(filepath.Join(mihomoDir, "go.mod")); err != nil || info.IsDir() {
		return errors.New("MIHOMO_DIR must point to a Mihomo source checkout")
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		return errors.New("go executable is required for Chimera interop")
	}
	coreDir, err := interopCoreDir()
	if err != nil {
		return err
	}
	runDir := t.TempDir()
	serverBinary := filepath.Join(runDir, "chimera-server"+interopExecutableSuffix())
	mihomoBinary := filepath.Join(runDir, "mihomo"+interopExecutableSuffix())
	if err := interopBuild(goBinary, coreDir, serverBinary, "./cmd/chimera-server"); err != nil {
		return fmt.Errorf("build Chimera server: %w", err)
	}
	if err := interopBuild(goBinary, mihomoDir, mihomoBinary, "-tags", "with_gvisor", "."); err != nil {
		return fmt.Errorf("build Mihomo: %w", err)
	}

	credentials, err := interopMakeCredentials(serverBinary, filepath.Join(runDir, "quic-cert.pem"))
	if err != nil {
		return err
	}
	serverPort, err := interopFreeTCPPort()
	if err != nil {
		return err
	}
	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
	server, err := interopStart(serverBinary, runDir, []string{
		"-listen", serverAddr,
		"-quic", serverAddr,
		"-target", "example.com:443",
		"-sni", interopSNI,
		"-quic-cert", filepath.Join(runDir, "quic-cert.pem"),
	}, []string{
		"CHIMERA_PRIVATE_KEY=" + credentials.privateKey,
		"CHIMERA_SHORT_IDS=" + credentials.shortID,
		"CHIMERA_QUIC_PSK=" + credentials.quicPSK,
	})
	if err != nil {
		return fmt.Errorf("start Chimera server: %w", err)
	}
	t.Cleanup(func() { interopStop(server) })

	for _, mode := range []string{"quic", "auto"} {
		socksPort, err := interopFreeTCPPort()
		if err != nil {
			return err
		}
		configPath := filepath.Join(runDir, "mihomo-"+mode+".yaml")
		if err := os.WriteFile(configPath, []byte(interopMihomoConfig(socksPort, serverPort, mode, credentials)), 0o600); err != nil {
			return err
		}
		mihomo, err := interopStart(mihomoBinary, runDir, []string{"-d", runDir, "-f", configPath}, nil)
		if err != nil {
			return fmt.Errorf("start Mihomo %s mode: %w", mode, err)
		}
		socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
		err = interopWaitForTCP(socksAddr, 8*time.Second)
		if err == nil {
			err = interopSOCKSUDPProbe(socksAddr)
		}
		interopStop(mihomo)
		if err != nil {
			return fmt.Errorf("%s UDP interop: %w", mode, err)
		}
	}
	return nil
}

func interopCoreDir() (string, error) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not determine Core source directory")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	if info, err := os.Stat(filepath.Join(root, "go.mod")); err != nil || info.IsDir() {
		return "", errors.New("could not locate Core go.mod")
	}
	return root, nil
}

func interopBuild(goBinary, dir, output string, args ...string) error {
	commandArgs := append([]string{"build", "-trimpath", "-o", output}, args...)
	command := exec.Command(goBinary, commandArgs...)
	command.Dir = dir
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return err
	}
	return nil
}

func interopMakeCredentials(serverBinary, certificatePath string) (interopCredentials, error) {
	output, err := exec.Command(serverBinary, "-genkey").Output()
	if err != nil {
		return interopCredentials{}, errors.New("generate temporary interop credentials")
	}
	credentials := interopCredentials{
		privateKey: interopOutputField(output, "Private Key:"),
		publicKey:  interopOutputField(output, "Public Key:"),
		shortID:    interopOutputField(output, "Short ID:"),
		quicPSK:    interopOutputField(output, "QUIC PSK:"),
	}
	if credentials.privateKey == "" || credentials.publicKey == "" || credentials.shortID == "" || credentials.quicPSK == "" {
		return interopCredentials{}, errors.New("generated temporary interop credentials were incomplete")
	}
	output, err = exec.Command(serverBinary, "-quic-cert-info", "-quic-cert", certificatePath, "-sni", interopSNI).Output()
	if err != nil {
		return interopCredentials{}, errors.New("generate temporary interop certificate")
	}
	credentials.quicFP = interopOutputField(output, "QUIC Fingerprint:")
	if len(credentials.quicFP) != 64 {
		return interopCredentials{}, errors.New("generated temporary interop certificate fingerprint was incomplete")
	}
	return credentials, nil
}

func interopOutputField(output []byte, prefix string) string {
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func interopMihomoConfig(socksPort, serverPort int, mode string, credentials interopCredentials) string {
	return fmt.Sprintf(`mixed-port: %d
allow-lan: false
mode: rule
log-level: silent
ipv6: false

proxies:
  - name: chimera-interop
    type: chimera
    server: 127.0.0.1
    port: %d
    sni: %s
    public-key: %q
    short-id: %q
    client-fingerprint: chrome
    mode: %s
    udp: true
    quic-psk: %q
    quic-fp: %q
    auto-quic-timeout: 1200

proxy-groups:
  - name: PROXY
    type: select
    proxies: [chimera-interop]

rules:
  - MATCH,PROXY
`, socksPort, serverPort, interopSNI, credentials.publicKey, credentials.shortID, mode, credentials.quicPSK, credentials.quicFP)
}

func interopStart(binary, dir string, args, extraEnv []string) (*exec.Cmd, error) {
	command := exec.Command(binary, args...)
	command.Dir = dir
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.Env = interopEnvironment(extraEnv)
	if err := command.Start(); err != nil {
		return nil, err
	}
	return command, nil
}

func interopEnvironment(extraEnv []string) []string {
	const sensitivePrefix = "CHIMERA_"
	environment := make([]string, 0, len(os.Environ())+len(extraEnv))
	for _, value := range os.Environ() {
		name, _, ok := strings.Cut(value, "=")
		if ok && strings.HasPrefix(name, sensitivePrefix) {
			continue
		}
		environment = append(environment, value)
	}
	return append(environment, extraEnv...)
}

func interopStop(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Kill()
	_, _ = command.Process.Wait()
}

func interopFreeTCPPort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func interopWaitForTCP(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 150*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("Mihomo SOCKS listener did not start")
}

func interopSOCKSUDPProbe(socksAddress string) error {
	control, relay, err := interopSOCKSUDPAssociate(socksAddress)
	if err != nil {
		return err
	}
	defer control.Close()

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer udp.Close()

	targets := []struct {
		address *net.UDPAddr
		id      uint16
	}{
		{address: &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}, id: 0xA101},
		{address: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}, id: 0xB202},
	}
	expected := make(map[uint16]string, len(targets))
	for _, target := range targets {
		expected[target.id] = target.address.String()
	}

	for attempt := 0; attempt < 3; attempt++ {
		for _, target := range targets {
			if _, err := udp.WriteToUDP(interopSOCKSUDPDatagram(target.address, interopDNSQuery(target.id)), relay); err != nil {
				return err
			}
		}
		received := make(map[uint16]bool, len(targets))
		deadline := time.Now().Add(3 * time.Second)
		for len(received) < len(targets) && time.Now().Before(deadline) {
			_ = udp.SetReadDeadline(deadline)
			buffer := make([]byte, 4096)
			n, _, err := udp.ReadFromUDP(buffer)
			if err != nil {
				break
			}
			from, payload, err := interopParseSOCKSUDPDatagram(buffer[:n])
			if err != nil || len(payload) < 2 {
				continue
			}
			id := binary.BigEndian.Uint16(payload[:2])
			if expectedAddress, known := expected[id]; known && from.String() == expectedAddress {
				received[id] = true
			}
		}
		if len(received) == len(targets) {
			return nil
		}
	}
	return errors.New("did not receive matching DNS replies from both UDP destinations through one SOCKS source")
}

func interopSOCKSUDPAssociate(address string) (net.Conn, *net.UDPAddr, error) {
	control, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil, nil, err
	}
	if err := control.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		_ = control.Close()
		return nil, nil, err
	}
	if _, err := control.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = control.Close()
		return nil, nil, err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(control, method); err != nil || !bytes.Equal(method, []byte{0x05, 0x00}) {
		_ = control.Close()
		return nil, nil, errors.New("Mihomo SOCKS listener did not accept no-authentication")
	}
	if _, err := control.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		_ = control.Close()
		return nil, nil, err
	}
	relay, err := interopReadSOCKSAddress(control)
	if err != nil {
		_ = control.Close()
		return nil, nil, err
	}
	if relay.IP.IsUnspecified() {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			_ = control.Close()
			return nil, nil, err
		}
		relay.IP = net.ParseIP(host)
	}
	_ = control.SetDeadline(time.Time{})
	return control, relay, nil
}

func interopReadSOCKSAddress(reader io.Reader) (*net.UDPAddr, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x05 || header[1] != 0x00 || header[2] != 0x00 {
		return nil, errors.New("Mihomo SOCKS UDP associate was rejected")
	}
	var ip net.IP
	switch header[3] {
	case 0x01:
		ip = make(net.IP, net.IPv4len)
	case 0x04:
		ip = make(net.IP, net.IPv6len)
	default:
		return nil, errors.New("Mihomo SOCKS reply used an unsupported address type")
	}
	if _, err := io.ReadFull(reader, ip); err != nil {
		return nil, err
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(reader, port); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(port))}, nil
}

func interopSOCKSUDPDatagram(target *net.UDPAddr, payload []byte) []byte {
	ip := target.IP.To4()
	packet := make([]byte, 0, 10+len(payload))
	packet = append(packet, 0x00, 0x00, 0x00, 0x01)
	packet = append(packet, ip...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(target.Port))
	return append(packet, payload...)
}

func interopParseSOCKSUDPDatagram(packet []byte) (*net.UDPAddr, []byte, error) {
	if len(packet) < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0x01 {
		return nil, nil, errors.New("invalid SOCKS UDP IPv4 datagram")
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), packet[4:8]...),
		Port: int(binary.BigEndian.Uint16(packet[8:10])),
	}, packet[10:], nil
}

func interopDNSQuery(id uint16) []byte {
	query := make([]byte, 0, 64)
	query = binary.BigEndian.AppendUint16(query, id)
	query = binary.BigEndian.AppendUint16(query, 0x0100)
	query = binary.BigEndian.AppendUint16(query, 1)
	query = append(query, 0, 0, 0, 0, 0, 0)
	for _, label := range []string{"example", "com"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0)
	query = binary.BigEndian.AppendUint16(query, 1)
	return binary.BigEndian.AppendUint16(query, 1)
}

func interopExecutableSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
