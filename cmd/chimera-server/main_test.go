package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGeneratePSKReturnsURLSafe32ByteSecret(t *testing.T) {
	encoded, err := generatePSK()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Fatalf("PSK len = %d, want 32", len(decoded))
	}
}

func TestServerEnablesUDPRelayByDefault(t *testing.T) {
	if !defaultUDPRelayEnabled {
		t.Fatal("UDP relay is disabled by default")
	}
}

func TestRenderSystemdUnitUsesStateDirectoryAndNoSecretArguments(t *testing.T) {
	unit, err := renderSystemdUnit("/opt/chimera", ":9443", "g.alicdn.com:443", "g.alicdn.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"EnvironmentFile=/opt/chimera/keys.env",
		"DynamicUser=true",
		"StateDirectory=chimera",
		"StateDirectoryMode=0700",
		"WorkingDirectory=/var/lib/chimera",
		"Environment=CHIMERA_QUIC_CERT=/var/lib/chimera/quic-v5-cert.pem",
		"ExecStart=/opt/chimera/chimera-server -listen :9443 -target g.alicdn.com:443 -sni g.alicdn.com",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"RestrictAddressFamilies=AF_INET AF_INET6",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("unit missing %q:\n%s", required, unit)
		}
	}
	for _, forbidden := range []string{" -key ", " -sid ", " -quic-psk "} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("unit exposes secret argument %q:\n%s", forbidden, unit)
		}
	}
}

func TestRenderSystemdUnitRejectsWhitespaceInjection(t *testing.T) {
	if _, err := renderSystemdUnit("/opt/chimera", ":9443", "good.example:443", "good.example\nExecStart=/bin/sh"); err == nil {
		t.Fatal("newline injection accepted")
	}
}

func TestDeriveServerAuthKeysIncludesEverySID(t *testing.T) {
	psk := bytes.Repeat([]byte{0x31}, 32)
	publicKey := bytes.Repeat([]byte{0x32}, 32)
	shortIDs := [][]byte{{1, 2, 3, 4}, {5, 6, 7, 8}}
	keys, err := deriveServerAuthKeys(psk, publicKey, shortIDs)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
	if bytes.Equal(keys[0], keys[1]) {
		t.Fatal("different SIDs produced the same auth key")
	}
}

func TestDeriveServerAuthKeysRejectsMissingSID(t *testing.T) {
	if _, err := deriveServerAuthKeys(make([]byte, 32), make([]byte, 32), nil); err == nil {
		t.Fatal("empty SID list accepted")
	}
}

func TestDecodePSKRejectsWrongLength(t *testing.T) {
	if _, err := decodePSK(base64.RawURLEncoding.EncodeToString(make([]byte, 31))); err == nil {
		t.Fatal("31-byte PSK accepted")
	}
	if got, err := decodePSK(base64.RawURLEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Fatal(err)
	} else if len(got) != 32 {
		t.Fatalf("PSK len = %d", len(got))
	}
}
