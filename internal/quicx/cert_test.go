package quicx

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCertificatePersistsAndUsesConfiguredSAN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quic.pem")
	first, fp1, err := loadOrCreateCertificate(path, "proxy.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, err := loadOrCreateCertificate(path, "proxy.example", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint changed: %s != %s", fp1, fp2)
	}
	cert, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("proxy.example"); err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "proxy.example" {
		t.Fatalf("common name = %q", cert.Subject.CommonName)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("certificate mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCertificateWriteFailureIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "quic.pem")
	if _, _, err := loadOrCreateCertificate(path, "proxy.example", time.Now()); err == nil {
		t.Fatal("certificate write failure was ignored")
	}
}

func TestCertificateRejectsCorruptPersistedPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quic.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateCertificate(path, "proxy.example", time.Now()); err == nil {
		t.Fatal("corrupt persisted certificate was silently replaced")
	}
}
