package quicx

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/laoxiechuzheng/chimera-core/internal/chimera"
)

func TestHTTP3UDPRelayRoundTrip(t *testing.T) {
	var hooks fakeUDPHooks
	server, info := startTestServerWithConfig(t, udpServerConfig(t, &hooks))
	if !server.SupportsUDPRelay() {
		t.Fatal("UDP relay is not enabled")
	}
	client, err := DialClientWithConfig(context.Background(), ClientConfig{
		ServerAddr:      info.Addr,
		ServerName:      "proxy.example",
		AuthKey:         mustDerivedTestKey(t),
		CertFingerprint: info.Fingerprint,
		EnableDatagrams: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	session, err := client.DialUDP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "echo.example", Port: 9999})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	payload := []byte("chimera-udp-v06")
	if _, err := session.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	_ = session.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	n, _, err := session.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("echo = %q, want %q", got[:n], payload)
	}
}

func TestHTTP3UDPRelayFragmentsLargePacket(t *testing.T) {
	var hooks fakeUDPHooks
	serverCfg := udpServerConfig(t, &hooks)
	serverCfg.UDPMaxPacketSize = 4096
	server, info := startTestServerWithConfig(t, serverCfg)
	if !server.SupportsUDPRelay() {
		t.Fatal("UDP relay is not enabled")
	}
	client, err := DialClientWithConfig(context.Background(), ClientConfig{
		ServerAddr:      info.Addr,
		ServerName:      "proxy.example",
		AuthKey:         mustDerivedTestKey(t),
		CertFingerprint: info.Fingerprint,
		EnableDatagrams: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	session, err := client.DialUDP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "echo.example", Port: 9999})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := session.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	_ = session.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	n, _, err := session.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || string(got[:n]) != string(payload) {
		t.Fatalf("fragmented echo mismatch: got %d bytes, want %d", n, len(payload))
	}
}

func TestHTTP3UDPRelayRejectsPrivateTarget(t *testing.T) {
	var hooks fakeUDPHooks
	_, info := startTestServerWithConfig(t, udpServerConfig(t, &hooks))
	client, err := DialClientWithConfig(context.Background(), ClientConfig{
		ServerAddr:      info.Addr,
		ServerName:      "proxy.example",
		AuthKey:         mustDerivedTestKey(t),
		CertFingerprint: info.Fingerprint,
		EnableDatagrams: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.DialUDP(context.Background(), &chimera.Address{Type: chimera.AtypIPv4, IP: net.ParseIP("127.0.0.1"), Port: 80}); err == nil {
		t.Fatal("private UDP target accepted")
	}
}

func TestHTTP3UDPRelayRejectsOversizedPacket(t *testing.T) {
	var hooks fakeUDPHooks
	serverCfg := udpServerConfig(t, &hooks)
	serverCfg.UDPMaxPacketSize = 1200
	server, info := startTestServerWithConfig(t, serverCfg)
	client, err := DialClientWithConfig(context.Background(), ClientConfig{
		ServerAddr:       info.Addr,
		ServerName:       "proxy.example",
		AuthKey:          mustDerivedTestKey(t),
		CertFingerprint:  info.Fingerprint,
		EnableDatagrams:  true,
		UDPMaxPacketSize: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	session, err := client.DialUDP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "echo.example", Port: 9999})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if _, err := session.WriteTo(make([]byte, 1201), nil); err == nil {
		_ = session.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, readErr := session.ReadFrom(make([]byte, 2048)); readErr == nil {
			t.Fatal("oversized UDP datagram was accepted")
		}
	}
	_ = server
}

func TestHTTP3UDPRelayClosesIdleSession(t *testing.T) {
	var hooks fakeUDPHooks
	serverCfg := udpServerConfig(t, &hooks)
	serverCfg.UDPIdleTimeout = 100 * time.Millisecond
	_, info := startTestServerWithConfig(t, serverCfg)
	client, err := DialClientWithConfig(context.Background(), ClientConfig{
		ServerAddr:      info.Addr,
		ServerName:      "proxy.example",
		AuthKey:         mustDerivedTestKey(t),
		CertFingerprint: info.Fingerprint,
		EnableDatagrams: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	session, err := client.DialUDP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "echo.example", Port: 9999})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	_ = session.SetReadDeadline(time.Now().Add(time.Second))
	started := time.Now()
	if _, _, err := session.ReadFrom(make([]byte, 2048)); err == nil {
		t.Fatal("idle UDP session remained open")
	} else if elapsed := time.Since(started); elapsed > 900*time.Millisecond {
		t.Fatalf("idle session closed too slowly: %s", elapsed)
	}
}

func TestHTTP3UDPRelayRequiresDatagrams(t *testing.T) {
	var hooks fakeUDPHooks
	_, info := startTestServerWithConfig(t, udpServerConfig(t, &hooks))
	client := newTestClient(t, info)
	if _, err := client.DialUDP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "echo.example", Port: 9999}); err == nil {
		t.Fatal("UDP session opened without HTTP Datagram support")
	}
}

func TestUDPSourceMatchesValidatedTarget(t *testing.T) {
	target := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	if !udpSourceMatchesTarget(&net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}, target) {
		t.Fatal("validated UDP target did not match itself")
	}
	if udpSourceMatchesTarget(&net.UDPAddr{IP: net.ParseIP("8.8.4.4"), Port: 53}, target) {
		t.Fatal("different UDP source matched validated target")
	}
	if udpSourceMatchesTarget(&net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 54}, target) {
		t.Fatal("different UDP port matched validated target")
	}
}

func udpServerConfig(t *testing.T, hooks *fakeUDPHooks) ServerConfig {
	t.Helper()
	cfg := testServerConfig(t)
	cfg.EnableUDPRelay = true
	cfg.UDPMaxPacketSize = 1200
	cfg.UDPIdleTimeout = 2 * time.Second
	cfg.UDPMaxSessions = 4
	cfg.Network.LookupIP = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }
	cfg.Network.ListenPacket = hooks.ListenPacket
	return cfg
}

type fakeUDPHooks struct {
	mu    sync.Mutex
	conns []*fakePacketConn
}

func (h *fakeUDPHooks) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	c := newFakePacketConn()
	h.mu.Lock()
	h.conns = append(h.conns, c)
	h.mu.Unlock()
	return c, nil
}

type fakePacketConn struct {
	readCh chan fakePacket
	closed chan struct{}
	once   sync.Once
}

type fakePacket struct {
	data []byte
	addr net.Addr
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{readCh: make(chan fakePacket, 16), closed: make(chan struct{})}
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.readCh:
		return copy(p, packet.data), packet.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	data := append([]byte(nil), p...)
	select {
	case c.readCh <- fakePacket{data: data, addr: addr}:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *fakePacketConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *fakePacketConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "udp" }
func (a fakeAddr) String() string  { return string(a) }

var _ = errors.Is
