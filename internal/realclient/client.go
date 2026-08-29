package realclient

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

type ClientConfig struct {
	ServerAddr  string
	ServerName  string
	PublicKey   []byte
	ShortId     []byte
	Fingerprint string
}

func fingerprintToID(name string) utls.ClientHelloID {
	switch strings.ToLower(name) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "golang":
		return utls.HelloGolang
	default:
		return utls.HelloChrome_Auto
	}
}

func Dial(ctx context.Context, config *ClientConfig) (net.Conn, error) {
	var d net.Dialer
	rawConn, err := d.DialContext(ctx, "tcp", config.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("chimera: tcp dial: %w", err)
	}

	var authKey []byte
	verified := false

	verifyFunc := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("REALITY: no certificates")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("REALITY: parse cert: %w", err)
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("REALITY: pubkey not ed25519 (real cert)")
		}
		if authKey == nil {
			return errors.New("REALITY: authKey not computed")
		}
		h := hmac.New(sha512.New, authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), cert.Signature) {
			verified = true
			return nil
		}
		return errors.New("REALITY: verification failed (real cert)")
	}

	utlsConfig := &utls.Config{
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verifyFunc,
	}

	uConn := utls.UClient(rawConn, utlsConfig, fingerprintToID(config.Fingerprint))
	uConn.BuildHandshakeState()
	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	hello.SessionId[0] = 1
	hello.SessionId[1] = 0
	hello.SessionId[2] = 0
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], config.ShortId)

	publicKey, err := ecdh.X25519().NewPublicKey(config.PublicKey)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("chimera: invalid pubkey: %w", err)
	}
	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		rawConn.Close()
		return nil, errors.New("chimera: no X25519 key share (check fingerprint)")
	}
	shared, err := ecdhe.ECDH(publicKey)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("chimera: ECDH: %w", err)
	}
	authKey = make([]byte, 32)
	copy(authKey, shared)
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		rawConn.Close()
		return nil, err
	}

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("chimera: handshake: %w", err)
	}
	if !verified {
		rawConn.Close()
		return nil, errors.New("chimera: REALITY not verified")
	}
	return uConn, nil
}
