package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func successfulPipeDial(t *testing.T) transportDial {
	t.Helper()
	return func(context.Context) (transportConn, error) {
		clientSide, serverSide := net.Pipe()
		t.Cleanup(func() {
			clientSide.Close()
			serverSide.Close()
		})
		return clientSide, nil
	}
}

func TestSelectTransportQUICNeverDialsTCP(t *testing.T) {
	var tcpCalls atomic.Int32
	conn, err := selectTransport(context.Background(), "quic", 20*time.Millisecond,
		successfulPipeDial(t),
		func(context.Context) (transportConn, error) {
			tcpCalls.Add(1)
			return nil, errors.New("unexpected TCP")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if tcpCalls.Load() != 0 {
		t.Fatalf("TCP calls = %d", tcpCalls.Load())
	}
}

func TestSelectTransportAutoUsesQUICWithoutDialingTCP(t *testing.T) {
	var tcpCalls atomic.Int32
	conn, err := selectTransport(context.Background(), "auto", 20*time.Millisecond,
		successfulPipeDial(t),
		func(context.Context) (transportConn, error) {
			tcpCalls.Add(1)
			return nil, errors.New("unexpected TCP")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if tcpCalls.Load() != 0 {
		t.Fatalf("TCP calls = %d", tcpCalls.Load())
	}
}

func TestSelectTransportAutoFallsBackWithinBudget(t *testing.T) {
	started := time.Now()
	conn, err := selectTransport(context.Background(), "auto", 20*time.Millisecond,
		func(ctx context.Context) (transportConn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		successfulPipeDial(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("fallback took %s", elapsed)
	}
}

func TestSelectTransportTCPNeverDialsQUIC(t *testing.T) {
	var quicCalls atomic.Int32
	conn, err := selectTransport(context.Background(), "tcp", 20*time.Millisecond,
		func(context.Context) (transportConn, error) {
			quicCalls.Add(1)
			return nil, errors.New("unexpected QUIC")
		},
		successfulPipeDial(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if quicCalls.Load() != 0 {
		t.Fatalf("QUIC calls = %d", quicCalls.Load())
	}
}

func TestValidateQUICConfigRequiresIndependentPSKAndFingerprint(t *testing.T) {
	validPSK := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	validFP := strings.Repeat("a", 64)
	if _, err := validateQUICConfig("quic", "", validFP); err == nil {
		t.Fatal("empty PSK accepted")
	}
	if _, err := validateQUICConfig("quic", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), validFP); err == nil {
		t.Fatal("31-byte PSK accepted")
	}
	if _, err := validateQUICConfig("quic", validPSK, ""); err == nil {
		t.Fatal("empty fingerprint accepted")
	}
	if _, err := validateQUICConfig("quic", validPSK, strings.Repeat("z", 64)); err == nil {
		t.Fatal("non-hex fingerprint accepted")
	}
	if got, err := validateQUICConfig("quic", validPSK, validFP); err != nil {
		t.Fatal(err)
	} else if len(got) != 32 {
		t.Fatalf("PSK len = %d", len(got))
	}
	if got, err := validateQUICConfig("tcp", "", ""); err != nil || got != nil {
		t.Fatalf("TCP config = %x, %v", got, err)
	}
}

func TestDecodeShortIDRequiresOneToEightBytes(t *testing.T) {
	for _, invalid := range []string{"", "0", strings.Repeat("aa", 9)} {
		if _, err := decodeShortID(invalid); err == nil {
			t.Fatalf("invalid short ID %q accepted", invalid)
		}
	}
	for _, valid := range []string{"00", "0102030405060708"} {
		if _, err := decodeShortID(valid); err != nil {
			t.Fatalf("valid short ID %q rejected: %v", valid, err)
		}
	}
}

func TestOwnedConnClosesOwnerExactlyOnce(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	var ownerCloses atomic.Int32
	conn := &ownedConn{
		Conn: clientSide,
		closeOwner: func() error {
			ownerCloses.Add(1)
			return nil
		},
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if ownerCloses.Load() != 1 {
		t.Fatalf("owner close count = %d", ownerCloses.Load())
	}
}

func TestSocks5HandshakeRejectsClientWithoutNoAuthMethod(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	done := make(chan error, 1)
	go func() { done <- socks5Handshake(serverSide) }()
	if _, err := clientSide.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := clientSide.Read(reply); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("handshake accepted without no-auth method")
	}
	if reply[0] != 5 || reply[1] != 0xff {
		t.Fatalf("reply = %v, want [5 255]", reply)
	}
}
