package chimera

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestResolveAndValidateAuthorityRejectsLoopbackDNS(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	if _, err := ResolveAndValidateAuthority(context.Background(), "localhost:8080", lookup); err == nil {
		t.Fatal("loopback DNS answer accepted")
	}
}

func TestResolveAndValidateAuthorityRejectsMixedPublicPrivateDNS(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.0.0.1")}, nil
	}
	if _, err := ResolveAndValidateAuthority(context.Background(), "mixed.example:443", lookup); err == nil {
		t.Fatal("mixed public/private DNS answer accepted")
	}
}

func TestResolveAndValidateAuthorityReturnsValidatedIPLiteral(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	got, err := ResolveAndValidateAuthority(context.Background(), "public.example:443", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.1.1.1:443" {
		t.Fatalf("authority = %q", got)
	}
}

func TestResolveAndValidateAuthorityRejectsDocumentationIPWithoutLookup(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IP, error) {
		return nil, errors.New("lookup must not be called for IP literals")
	}
	if _, err := ResolveAndValidateAuthority(context.Background(), "192.0.2.1:443", lookup); err == nil {
		t.Fatal("documentation IP accepted")
	}
}
