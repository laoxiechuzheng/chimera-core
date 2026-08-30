package quicx

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

type NetworkHooks struct {
	LookupIP     func(context.Context, string) ([]net.IP, error)
	DialContext  func(context.Context, string, string) (net.Conn, error)
	ListenPacket func(context.Context, string, string) (net.PacketConn, error)
}

type ServerConfig struct {
	ListenAddr string
	ServerName string
	AuthKeys   [][]byte

	CertificatePath string
	CertificateFile string
	PrivateKeyFile  string

	DecoyTarget          string
	DecoyOptions         DecoyOptions
	DecoyRefreshInterval time.Duration
	Limits               LimitConfig
	Network              NetworkHooks
	TargetDialTimeout    time.Duration
	AuthenticationSkew   time.Duration
	ReplayCapacity       int
	QUICConfig           *quic.Config
	EnableUDPRelay       bool
	UDPMaxPacketSize     int
	UDPMaxSessions       int
	UDPIdleTimeout       time.Duration
}

type ServerInfo struct {
	Addr        string
	Fingerprint string
}

type ClientConfig struct {
	ServerAddr       string
	ServerName       string
	AuthKey          []byte
	CertFingerprint  string
	EnableDatagrams  bool
	UDPMaxPacketSize int
	QUICConfig       *quic.Config
}

func normalizeServerConfig(cfg ServerConfig) (ServerConfig, error) {
	cfg.ListenAddr = strings.TrimSpace(cfg.ListenAddr)
	if cfg.ListenAddr == "" {
		return ServerConfig{}, errors.New("quicx: listen address is required")
	}
	cfg.ServerName = strings.ToLower(strings.TrimSpace(cfg.ServerName))
	if cfg.ServerName == "" {
		return ServerConfig{}, errors.New("quicx: server name is required")
	}
	if len(cfg.AuthKeys) == 0 {
		return ServerConfig{}, errors.New("quicx: authentication keys are required")
	}
	if (cfg.CertificateFile == "") != (cfg.PrivateKeyFile == "") {
		return ServerConfig{}, errors.New("quicx: certificate and private key files must be configured together")
	}
	if cfg.CertificatePath == "" && cfg.CertificateFile == "" {
		cfg.CertificatePath = strings.TrimSpace(os.Getenv("CHIMERA_QUIC_CERT"))
		if cfg.CertificatePath == "" {
			cfg.CertificatePath = "quic-cert.pem"
		}
	}
	if strings.TrimSpace(cfg.DecoyTarget) == "" {
		return ServerConfig{}, errors.New("quicx: decoy target is required")
	}
	if cfg.DecoyRefreshInterval <= 0 {
		cfg.DecoyRefreshInterval = 10 * time.Minute
	}
	if cfg.TargetDialTimeout <= 0 {
		cfg.TargetDialTimeout = 10 * time.Second
	}
	if cfg.AuthenticationSkew <= 0 {
		cfg.AuthenticationSkew = time.Minute
	}
	if cfg.ReplayCapacity <= 0 {
		cfg.ReplayCapacity = 4096
	}
	if cfg.EnableUDPRelay {
		if cfg.UDPMaxPacketSize <= 0 {
			cfg.UDPMaxPacketSize = defaultUDPMaxPacketSize
		}
		if cfg.UDPMaxSessions <= 0 {
			cfg.UDPMaxSessions = 64
		}
		if cfg.UDPIdleTimeout <= 0 {
			cfg.UDPIdleTimeout = 60 * time.Second
		}
	}
	cfg.Network = normalizeNetworkHooks(cfg.Network, cfg.TargetDialTimeout)
	if cfg.QUICConfig == nil {
		cfg.QUICConfig = &quic.Config{
			HandshakeIdleTimeout:  5 * time.Second,
			MaxIdleTimeout:        60 * time.Second,
			KeepAlivePeriod:       20 * time.Second,
			MaxIncomingStreams:    128,
			MaxIncomingUniStreams: 16,
		}
	} else {
		cfg.QUICConfig = cfg.QUICConfig.Clone()
	}
	if cfg.EnableUDPRelay {
		cfg.QUICConfig.EnableDatagrams = true
	}
	return cfg, nil
}

func normalizeClientConfig(cfg ClientConfig) (ClientConfig, error) {
	cfg.ServerAddr = strings.TrimSpace(cfg.ServerAddr)
	if cfg.ServerAddr == "" {
		return ClientConfig{}, errors.New("quicx: server address is required")
	}
	cfg.ServerName = strings.ToLower(strings.TrimSpace(cfg.ServerName))
	if cfg.ServerName == "" {
		return ClientConfig{}, errors.New("quicx: server name is required")
	}
	if len(cfg.AuthKey) != authKeyLen {
		return ClientConfig{}, errors.New("quicx: authentication key must be exactly 32 bytes")
	}
	if strings.TrimSpace(cfg.CertFingerprint) == "" {
		return ClientConfig{}, errors.New("quicx: certificate fingerprint is required")
	}
	if cfg.EnableDatagrams {
		if cfg.UDPMaxPacketSize <= 0 {
			cfg.UDPMaxPacketSize = defaultUDPMaxPacketSize
		}
	}
	if cfg.QUICConfig == nil {
		cfg.QUICConfig = &quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       60 * time.Second,
			KeepAlivePeriod:      20 * time.Second,
			MaxIncomingStreams:   -1,
		}
	} else {
		cfg.QUICConfig = cfg.QUICConfig.Clone()
	}
	if cfg.EnableDatagrams {
		cfg.QUICConfig.EnableDatagrams = true
	}
	return cfg, nil
}

func normalizeNetworkHooks(hooks NetworkHooks, timeout time.Duration) NetworkHooks {
	if hooks.LookupIP == nil {
		hooks.LookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	if hooks.DialContext == nil {
		dialer := &net.Dialer{Timeout: timeout}
		hooks.DialContext = dialer.DialContext
	}
	if hooks.ListenPacket == nil {
		hooks.ListenPacket = func(_ context.Context, network, address string) (net.PacketConn, error) {
			return net.ListenPacket(network, address)
		}
	}
	return hooks
}
