package quicx

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

func fixedNonceSource(fill byte) *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{fill}, authNonceLen))
}

func TestAuthenticatorRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, authKeyLen)
	auth, err := NewAuthenticator([][]byte{key}, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	auth.rand = fixedNonceSource(0x11)
	now := time.Unix(1_788_000_000, 0)
	token, err := auth.Sign(http.MethodConnect, "example.com:443", "proxy.example", now)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.Validate(token, http.MethodConnect, "example.com:443", "proxy.example", now) {
		t.Fatal("valid token rejected")
	}
}

func TestAuthenticatorCoversAuthorityAndServerName(t *testing.T) {
	auth, err := NewAuthenticator([][]byte{bytes.Repeat([]byte{1}, authKeyLen)}, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	auth.rand = fixedNonceSource(0x12)
	now := time.Unix(1_788_000_000, 0)
	token, err := auth.Sign(http.MethodConnect, "example.com:443", "proxy.example", now)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Validate(token, http.MethodConnect, "other.example:443", "proxy.example", now) {
		t.Fatal("token accepted for a different authority")
	}
	if auth.Validate(token, http.MethodConnect, "example.com:443", "other-proxy.example", now) {
		t.Fatal("token accepted for a different server name")
	}
}

func TestAuthenticatorRejectsWrongKeyExpiredAndReplay(t *testing.T) {
	now := time.Unix(1_788_000_000, 0)
	signer, err := NewAuthenticator([][]byte{bytes.Repeat([]byte{1}, authKeyLen)}, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	signer.rand = fixedNonceSource(0x13)
	token, err := signer.Sign(http.MethodConnect, "example.com:443", "proxy.example", now)
	if err != nil {
		t.Fatal(err)
	}

	wrong, err := NewAuthenticator([][]byte{bytes.Repeat([]byte{2}, authKeyLen)}, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	if wrong.Validate(token, http.MethodConnect, "example.com:443", "proxy.example", now) {
		t.Fatal("wrong key accepted")
	}

	validator, err := NewAuthenticator([][]byte{bytes.Repeat([]byte{1}, authKeyLen)}, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	if validator.Validate(token, http.MethodConnect, "example.com:443", "proxy.example", now.Add(2*time.Minute)) {
		t.Fatal("expired token accepted")
	}
	if !validator.Validate(token, http.MethodConnect, "example.com:443", "proxy.example", now) {
		t.Fatal("first valid use rejected")
	}
	if validator.Validate(token, http.MethodConnect, "example.com:443", "proxy.example", now) {
		t.Fatal("replay accepted")
	}
}

func TestAuthenticatorAcceptsSecondConfiguredKeyWithoutReReadingRequest(t *testing.T) {
	key1 := bytes.Repeat([]byte{1}, authKeyLen)
	key2 := bytes.Repeat([]byte{2}, authKeyLen)
	now := time.Unix(1_788_000_000, 0)

	signer, err := NewAuthenticator([][]byte{key2}, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	signer.rand = fixedNonceSource(0x14)
	token, err := signer.Sign(http.MethodConnect, "example.com:443", "proxy.example", now)
	if err != nil {
		t.Fatal(err)
	}

	validator, err := NewAuthenticator([][]byte{key1, key2}, time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !validator.Validate(token, http.MethodConnect, "example.com:443", "proxy.example", now) {
		t.Fatal("token signed by second configured key rejected")
	}
}

func TestReplayCacheNeverExceedsCapacity(t *testing.T) {
	cache := newReplayCache(4, time.Minute)
	now := time.Unix(1_788_000_000, 0)
	for i := byte(0); i < 10; i++ {
		if !cache.Add([]byte{i}, now) {
			t.Fatalf("nonce %d rejected", i)
		}
	}
	if got := cache.Len(); got != 4 {
		t.Fatalf("cache len = %d, want 4", got)
	}
}

func TestDeriveAuthKeyRequires32BytePSK(t *testing.T) {
	if _, err := DeriveAuthKey(make([]byte, 31), make([]byte, 32), []byte("sid")); err == nil {
		t.Fatal("31-byte PSK accepted")
	}
	if _, err := DeriveAuthKey(make([]byte, 32), make([]byte, 32), []byte("sid")); err != nil {
		t.Fatalf("32-byte PSK rejected: %v", err)
	}
}

func TestDeriveAuthKeyIsStableAndCredentialBound(t *testing.T) {
	psk := bytes.Repeat([]byte{0x21}, 32)
	pub := bytes.Repeat([]byte{0x22}, 32)
	a, err := DeriveAuthKey(psk, pub, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveAuthKey(psk, pub, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	c, err := DeriveAuthKey(psk, pub, []byte{1, 2, 3, 5})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("derivation is not stable")
	}
	if bytes.Equal(a, c) {
		t.Fatal("different short IDs produced the same key")
	}
}
