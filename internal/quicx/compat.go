package quicx

import (
	"context"
	"crypto/sha256"
	"os"
)

// ListenServer keeps the v0.4 call surface compiling while carrying traffic
// over the v0.5 HTTP/3 implementation. New callers use ListenServerWithConfig.
func ListenServer(ctx context.Context, listenAddr string, passwords []string, target string) (*Server, string, error) {
	keys := make([][]byte, 0, len(passwords))
	for _, password := range passwords {
		keys = append(keys, compatibilityAuthKey(password))
	}
	server, info, err := ListenServerWithConfig(ctx, ServerConfig{
		ListenAddr:      listenAddr,
		ServerName:      compatibilityServerName,
		AuthKeys:        keys,
		CertificatePath: os.Getenv("CHIMERA_QUIC_CERT"),
		DecoyTarget:     target,
	})
	return server, info.Fingerprint, err
}

// DialClient keeps the v0.4 call surface compiling. New callers use
// DialClientWithConfig with a separately derived v0.5 authentication key.
func DialClient(ctx context.Context, serverAddr, password, certFingerprint string) (*Client, error) {
	return DialClientWithConfig(ctx, ClientConfig{
		ServerAddr:      serverAddr,
		ServerName:      compatibilityServerName,
		AuthKey:         compatibilityAuthKey(password),
		CertFingerprint: certFingerprint,
	})
}

func compatibilityAuthKey(password string) []byte {
	if len(password) == authKeyLen {
		return append([]byte(nil), []byte(password)...)
	}
	sum := sha256.Sum256([]byte(password))
	return sum[:]
}
