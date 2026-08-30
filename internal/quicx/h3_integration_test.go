package quicx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/laoxiechuzheng/chimera-core/internal/chimera"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var (
	testPSK       = bytes.Repeat([]byte{0x51}, 32)
	testPublicKey = bytes.Repeat([]byte{0x52}, 32)
	testShortID   = []byte{1, 2, 3, 4, 5, 6, 7, 8}
)

func TestStandardHTTP3GETReceivesDecoy(t *testing.T) {
	server, info := startTestServer(t)
	transport := pinnedHTTP3Transport(t, info, false)
	resp, err := transport.RoundTrip(mustRequest(t, http.MethodGet, "https://"+server.Addr()+"/"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := string(readAll(t, resp.Body)); got != "decoy" {
		t.Fatalf("body = %q, want decoy", got)
	}
}

func TestHTTP3ConnectRelaysTCPEcho(t *testing.T) {
	server, info := startTestServerWithNetwork(t, NetworkHooks{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			clientSide, serverSide := net.Pipe()
			go func() {
				defer serverSide.Close()
				_, _ = io.Copy(serverSide, serverSide)
			}()
			return clientSide, nil
		},
	})
	client := newTestClient(t, info)
	conn, err := client.DialTCP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "echo.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("chimera-v5")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("chimera-v5"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "chimera-v5" {
		t.Fatalf("echo = %q", got)
	}
	if server.Addr() == "" {
		t.Fatal("server address is empty")
	}
}

func TestInvalidAuthMatchesMissingAuthDecoy(t *testing.T) {
	_, info := startTestServer(t)
	missing := doH3Request(t, info, http.MethodConnect, "example.com:443", "")
	bad := doH3Request(t, info, http.MethodConnect, "example.com:443", "Bearer invalid")
	if missing.StatusCode != http.StatusNotFound || bad.StatusCode != http.StatusNotFound {
		missing.Body.Close()
		bad.Body.Close()
		t.Fatalf("statuses = %d and %d, want 404", missing.StatusCode, bad.StatusCode)
	}
	missingBody := readAll(t, missing.Body)
	badBody := readAll(t, bad.Body)
	if !bytes.Equal(missingBody, badBody) {
		t.Fatalf("decoy bodies differ: %q != %q", missingBody, badBody)
	}
}

func TestConnectRejectsDomainResolvingToLoopback(t *testing.T) {
	var dialCalls atomic.Int32
	_, info := startTestServerWithNetwork(t, NetworkHooks{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("must not dial")
		},
	})
	client := newTestClient(t, info)
	if _, err := client.DialTCP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "localhost", Port: 8080}); err == nil {
		t.Fatal("loopback target accepted")
	}
	if dialCalls.Load() != 0 {
		t.Fatalf("dial called %d times for forbidden target", dialCalls.Load())
	}
}

func TestConnectDialsValidatedIPNotOriginalHostname(t *testing.T) {
	dialed := make(chan string, 1)
	_, info := startTestServerWithNetwork(t, NetworkHooks{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed <- address
			clientSide, serverSide := net.Pipe()
			go func() {
				defer serverSide.Close()
				_, _ = io.Copy(io.Discard, serverSide)
			}()
			return clientSide, nil
		},
	})
	client := newTestClient(t, info)
	conn, err := client.DialTCP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "public.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := <-dialed; got != "1.1.1.1:443" {
		t.Fatalf("dialed %q, want 1.1.1.1:443", got)
	}
}

func TestRawCHIMDoesNotTriggerDecoyOriginFetch(t *testing.T) {
	var fetches atomic.Int32
	_, info := startTestServerWithDecoyFetcher(t, func(context.Context, string) (DecoySnapshot, error) {
		fetches.Add(1)
		return DecoySnapshot{Status: http.StatusOK, Body: []byte("decoy")}, nil
	})
	before := fetches.Load()
	if err := sendRawQUICStream(info.Addr, pinnedTLSConfig(t, info.Fingerprint), []byte("CHIMjunk")); err == nil {
		t.Fatal("malformed HTTP/3 stream unexpectedly produced a response")
	}
	if got := fetches.Load(); got != before {
		t.Fatalf("decoy origin fetches changed: %d -> %d", before, got)
	}
}

func TestRateLimitReturnsSmallResponseWithoutOriginFetch(t *testing.T) {
	var fetches atomic.Int32
	cfg := testServerConfig(t)
	cfg.Limits = LimitConfig{MaxConcurrent: 4, PerIPBurst: 1, PerIPWindow: time.Minute, MaxTrackedIPs: 4}
	cfg.DecoyOptions.Fetch = func(context.Context, string) (DecoySnapshot, error) {
		fetches.Add(1)
		return DecoySnapshot{Status: http.StatusOK, Body: bytes.Repeat([]byte{'x'}, maxDecoyBody)}, nil
	}
	_, info := startTestServerWithConfig(t, cfg)
	first := doH3Request(t, info, http.MethodGet, "proxy.example", "")
	_ = readAll(t, first.Body)
	second := doH3Request(t, info, http.MethodGet, "proxy.example", "")
	body := readAll(t, second.Body)
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", second.StatusCode)
	}
	if len(body) > 1024 {
		t.Fatalf("rate-limit body len = %d, want <= 1024", len(body))
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("origin fetches = %d, want 1", got)
	}
}

func TestAuthenticatedConnectsBypassUnauthenticatedPerIPBurst(t *testing.T) {
	var dialCalls atomic.Int32
	cfg := testServerConfig(t)
	cfg.Limits = LimitConfig{MaxConcurrent: 4, PerIPBurst: 1, PerIPWindow: time.Minute, MaxTrackedIPs: 4}
	cfg.Network = NetworkHooks{
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			clientSide, serverSide := net.Pipe()
			go func() {
				defer serverSide.Close()
				_, _ = io.Copy(serverSide, serverSide)
			}()
			return clientSide, nil
		},
	}
	_, info := startTestServerWithConfig(t, cfg)
	client := newTestClient(t, info)
	for i := 0; i < 2; i++ {
		conn, err := client.DialTCP(context.Background(), &chimera.Address{Type: chimera.AtypDomain, Domain: "echo.test", Port: 443})
		if err != nil {
			t.Fatalf("authenticated CONNECT %d failed: %v", i+1, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := dialCalls.Load(); got != 2 {
		t.Fatalf("target dials = %d, want 2", got)
	}
}

func startTestServer(t *testing.T) (*Server, ServerInfo) {
	t.Helper()
	return startTestServerWithDecoyFetcher(t, func(context.Context, string) (DecoySnapshot, error) {
		return DecoySnapshot{Status: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: []byte("decoy")}, nil
	})
}

func startTestServerWithDecoyFetcher(t *testing.T, fetch DecoyFetchFunc) (*Server, ServerInfo) {
	t.Helper()
	cfg := testServerConfig(t)
	cfg.DecoyOptions.Fetch = fetch
	return startTestServerWithConfig(t, cfg)
}

func startTestServerWithNetwork(t *testing.T, hooks NetworkHooks) (*Server, ServerInfo) {
	t.Helper()
	cfg := testServerConfig(t)
	cfg.Network = hooks
	return startTestServerWithConfig(t, cfg)
}

func startTestServerWithConfig(t *testing.T, cfg ServerConfig) (*Server, ServerInfo) {
	t.Helper()
	server, info, err := ListenServerWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, info
}

func testServerConfig(t *testing.T) ServerConfig {
	t.Helper()
	return ServerConfig{
		ListenAddr:      "127.0.0.1:0",
		ServerName:      "proxy.example",
		AuthKeys:        [][]byte{mustDerivedTestKey(t)},
		CertificatePath: filepath.Join(t.TempDir(), "quic.pem"),
		DecoyTarget:     "origin.example:443",
		DecoyOptions: DecoyOptions{Fetch: func(context.Context, string) (DecoySnapshot, error) {
			return DecoySnapshot{Status: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: []byte("decoy")}, nil
		}},
		Limits: LimitConfig{MaxConcurrent: 16, PerIPBurst: 16, PerIPWindow: time.Minute, MaxTrackedIPs: 16},
	}
}

func mustDerivedTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := DeriveAuthKey(testPSK, testPublicKey, testShortID)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newTestClient(t *testing.T, info ServerInfo) *Client {
	t.Helper()
	client, err := DialClientWithConfig(context.Background(), ClientConfig{
		ServerAddr:      info.Addr,
		ServerName:      "proxy.example",
		AuthKey:         mustDerivedTestKey(t),
		CertFingerprint: info.Fingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func pinnedHTTP3Transport(t *testing.T, info ServerInfo, alwaysDialServer bool) *http3.Transport {
	t.Helper()
	transport := &http3.Transport{TLSClientConfig: pinnedTLSConfig(t, info.Fingerprint)}
	if alwaysDialServer {
		transport.Dial = func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, info.Addr, tlsCfg, cfg)
		}
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport
}

func pinnedTLSConfig(t *testing.T, fingerprint string) *tls.Config {
	t.Helper()
	fp, err := hex.DecodeString(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "proxy.example",
		NextProtos:         []string{http3.NextProtoH3},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("missing certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(sum[:], fp) {
				return errors.New("fingerprint mismatch")
			}
			return nil
		},
	}
}

func mustRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func doH3Request(t *testing.T, info ServerInfo, method, authority, authorization string) *http.Response {
	t.Helper()
	request := mustRequest(t, method, "https://"+authority+"/")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := pinnedHTTP3Transport(t, info, true).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readAll(t *testing.T, r io.ReadCloser) []byte {
	t.Helper()
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sendRawQUICStream(address string, tlsConfig *tls.Config, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, tlsConfig, &quic.Config{HandshakeIdleTimeout: time.Second})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	if _, err := stream.Write(payload); err != nil {
		return err
	}
	_ = stream.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var one [1]byte
	_, err = stream.Read(one[:])
	return err
}
