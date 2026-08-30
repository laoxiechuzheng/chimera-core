package quicx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func loadServerCertificate(cfg ServerConfig, now time.Time) (tls.Certificate, string, error) {
	if cfg.CertificateFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("quicx: load certificate pair: %w", err)
		}
		if err := verifyCertificateName(cert, cfg.ServerName); err != nil {
			return tls.Certificate{}, "", err
		}
		return cert, certificateFingerprint(cert), nil
	}
	return loadOrCreateCertificate(cfg.CertificatePath, cfg.ServerName, now)
}

func EnsureCertificate(path, serverName string) (string, error) {
	_, fingerprint, err := loadOrCreateCertificate(path, serverName, time.Now())
	return fingerprint, err
}

func loadOrCreateCertificate(path, serverName string, now time.Time) (tls.Certificate, string, error) {
	path = strings.TrimSpace(path)
	serverName = strings.TrimSpace(serverName)
	if path == "" || serverName == "" {
		return tls.Certificate{}, "", errors.New("quicx: certificate path and server name are required")
	}
	if data, err := os.ReadFile(path); err == nil {
		cert, err := tls.X509KeyPair(data, data)
		if err != nil {
			return tls.Certificate{}, "", fmt.Errorf("quicx: parse persisted certificate: %w", err)
		}
		if err := verifyCertificateName(cert, serverName); err != nil {
			return tls.Certificate{}, "", err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return tls.Certificate{}, "", fmt.Errorf("quicx: secure certificate permissions: %w", err)
		}
		return cert, certificateFingerprint(cert), nil
	} else if !os.IsNotExist(err) {
		return tls.Certificate{}, "", fmt.Errorf("quicx: read certificate: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(serverName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	var pemBuffer bytes.Buffer
	if err := pem.Encode(&pemBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := pem.Encode(&pemBuffer, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writeFileAtomic(path, pemBuffer.Bytes(), 0o600); err != nil {
		return tls.Certificate{}, "", fmt.Errorf("quicx: persist certificate: %w", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return cert, certificateFingerprint(cert), nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".chimera-cert-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func verifyCertificateName(cert tls.Certificate, serverName string) error {
	if len(cert.Certificate) == 0 {
		return errors.New("quicx: certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("quicx: parse leaf certificate: %w", err)
	}
	if err := leaf.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("quicx: certificate does not match server name: %w", err)
	}
	return nil
}

func certificateFingerprint(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}
