package quicx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chimera-proxy/chimera-core/internal/chimera"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Client struct {
	Conn       *quic.Conn
	h3         *http3.ClientConn
	transport  *http3.Transport
	auth       *Authenticator
	serverName string
	closeOnce  sync.Once
	closeErr   error
}

type StreamConn interface {
	net.Conn
	CancelRead(quic.StreamErrorCode)
}

func DialClientWithConfig(ctx context.Context, cfg ClientConfig) (*Client, error) {
	cfg, err := normalizeClientConfig(cfg)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := pinnedClientTLSConfig(cfg.ServerName, cfg.CertFingerprint)
	if err != nil {
		return nil, err
	}
	conn, err := quic.DialAddr(ctx, cfg.ServerAddr, tlsConfig, cfg.QUICConfig)
	if err != nil {
		return nil, err
	}
	transport := &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: cfg.QUICConfig}
	auth, err := NewAuthenticator([][]byte{cfg.AuthKey}, time.Minute, 1)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	return &Client{
		Conn:       conn,
		h3:         transport.NewClientConn(conn),
		transport:  transport,
		auth:       auth,
		serverName: cfg.ServerName,
	}, nil
}

func (c *Client) DialTCP(ctx context.Context, addr *chimera.Address) (StreamConn, error) {
	authority, err := authorityFromAddress(addr)
	if err != nil {
		return nil, err
	}
	authorization, err := c.auth.Sign(http.MethodConnect, authority, c.serverName, time.Now())
	if err != nil {
		return nil, err
	}
	stream, err := c.h3.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: authority},
		Host:   authority,
		Header: make(http.Header),
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	if err := stream.SendRequestHeader(request); err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.CopyN(io.Discard, response.Body, 4<<10)
		_ = response.Body.Close()
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return nil, fmt.Errorf("quicx: CONNECT rejected with status %d", response.StatusCode)
	}
	return &h3StreamConn{RequestStream: stream, local: c.Conn.LocalAddr(), remote: c.Conn.RemoteAddr()}, nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		if c.transport != nil {
			c.closeErr = c.transport.Close()
		}
		if c.Conn != nil {
			if err := c.Conn.CloseWithError(0, ""); err != nil && c.closeErr == nil {
				c.closeErr = err
			}
		}
	})
	return c.closeErr
}

type h3StreamConn struct {
	*http3.RequestStream
	local  net.Addr
	remote net.Addr
	once   sync.Once
	err    error
}

func (c *h3StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *h3StreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *h3StreamConn) Close() error {
	c.once.Do(func() {
		c.CancelRead(0)
		c.err = c.RequestStream.Close()
	})
	return c.err
}

func pinnedClientTLSConfig(serverName, fingerprint string) (*tls.Config, error) {
	fp, err := hex.DecodeString(strings.TrimSpace(fingerprint))
	if err != nil || len(fp) != sha256.Size {
		return nil, errors.New("quicx: invalid certificate fingerprint")
	}
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{http3.NextProtoH3},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("quicx: no server certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(sum[:], fp) {
				return errors.New("quicx: certificate fingerprint mismatch")
			}
			return nil
		},
	}, nil
}

func authorityFromAddress(addr *chimera.Address) (string, error) {
	if addr == nil || addr.Port == 0 {
		return "", errors.New("quicx: invalid target address")
	}
	port := strconv.Itoa(int(addr.Port))
	switch addr.Type {
	case chimera.AtypDomain:
		if addr.Domain == "" {
			return "", errors.New("quicx: empty target domain")
		}
		return net.JoinHostPort(addr.Domain, port), nil
	case chimera.AtypIPv4, chimera.AtypIPv6:
		if addr.IP == nil {
			return "", errors.New("quicx: empty target IP")
		}
		return net.JoinHostPort(addr.IP.String(), port), nil
	default:
		return "", errors.New("quicx: unsupported target address type")
	}
}
