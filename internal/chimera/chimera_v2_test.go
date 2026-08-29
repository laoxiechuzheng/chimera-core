package chimera

import (
	"bytes"
	"testing"
	"time"
)

func TestQUICConnectRoundTrip(t *testing.T) {
	pw := "test-password"
	addr := &Address{Type: AtypDomain, Domain: "example.com", Port: 443}
	var buf bytes.Buffer
	if err := WriteQUICConnect(&buf, CmdConnect, pw, addr); err != nil {
		t.Fatal(err)
	}
	cmd, got, err := ReadQUICConnect(&buf, pw)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != CmdConnect {
		t.Fatalf("cmd = %d", cmd)
	}
	if got.Domain != addr.Domain || got.Port != addr.Port {
		t.Fatalf("addr = %+v", got)
	}
}

func TestQUICConnectBadPassword(t *testing.T) {
	addr := &Address{Type: AtypDomain, Domain: "example.com", Port: 443}
	var buf bytes.Buffer
	if err := WriteQUICConnect(&buf, CmdConnect, "correct", addr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadQUICConnect(&buf, "wrong"); err != ErrQUICAuth {
		t.Fatalf("expected ErrQUICAuth, got %v", err)
	}
}

func TestQUICConnectReplayRejected(t *testing.T) {
	pw := "pw"
	addr := &Address{Type: AtypIPv4, IP: []byte{1, 2, 3, 4}, Port: 80}
	var buf bytes.Buffer
	if err := WriteQUICConnect(&buf, CmdConnect, pw, addr); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	cache := NewReplayCache(time.Minute)
	r1 := bytes.NewReader(frame)
	if _, _, err := ReadQUICConnectWithCache(r1, pw, cache); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	r2 := bytes.NewReader(frame)
	if _, _, err := ReadQUICConnectWithCache(r2, pw, cache); err != ErrQUICAuth {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestDeriveQUICPasswordStable(t *testing.T) {
	a := DeriveQUICPassword([]byte{1, 2}, []byte("pub"))
	b := DeriveQUICPassword([]byte{1, 2}, []byte("pub"))
	c := DeriveQUICPassword([]byte{1, 3}, []byte("pub"))
	if a != b {
		t.Fatal("derivation not deterministic")
	}
	if a == c {
		t.Fatal("different shortIDs produced same password")
	}
}

func TestAddressValidation(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteAddress(&buf, &Address{Type: AtypDomain, Domain: "", Port: 80}); err == nil {
		t.Fatal("empty domain accepted")
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	buf.Reset()
	if err := WriteAddress(&buf, &Address{Type: AtypDomain, Domain: string(long), Port: 80}); err == nil {
		t.Fatal("over-long domain accepted")
	}
}
