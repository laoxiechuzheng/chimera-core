package quicx

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/chimera-proxy/chimera-core/internal/chimera"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Server struct {
	h3          *http3.Server
	listener    http3.QUICListener
	packetConn  net.PacketConn
	auth        *Authenticator
	decoy       *Decoy
	limiter     *Limiter
	serverName  string
	network     NetworkHooks
	dialTimeout time.Duration
	now         func() time.Time

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func ListenServerWithConfig(ctx context.Context, cfg ServerConfig) (*Server, ServerInfo, error) {
	cfg, err := normalizeServerConfig(cfg)
	if err != nil {
		return nil, ServerInfo{}, err
	}
	cert, fingerprint, err := loadServerCertificate(cfg, time.Now())
	if err != nil {
		return nil, ServerInfo{}, err
	}
	auth, err := NewAuthenticator(cfg.AuthKeys, cfg.AuthenticationSkew, cfg.ReplayCapacity)
	if err != nil {
		return nil, ServerInfo{}, err
	}
	if cfg.DecoyOptions.Fetch == nil && cfg.DecoyOptions.HTTPClient == nil {
		cfg.DecoyOptions.HTTPClient = guardedHTTPClient(cfg.Network, 5*time.Second)
	}
	decoy, err := NewDecoy(cfg.DecoyTarget, cfg.DecoyOptions)
	if err != nil {
		return nil, ServerInfo{}, err
	}
	refreshCtx, refreshCancel := context.WithTimeout(ctx, 5*time.Second)
	_ = decoy.Refresh(refreshCtx)
	refreshCancel()

	packetConn, err := net.ListenPacket("udp", cfg.ListenAddr)
	if err != nil {
		return nil, ServerInfo{}, err
	}
	tlsConfig := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	listener, err := quic.ListenEarly(packetConn, tlsConfig, cfg.QUICConfig)
	if err != nil {
		_ = packetConn.Close()
		return nil, ServerInfo{}, err
	}
	server := &Server{
		listener:    listener,
		packetConn:  packetConn,
		auth:        auth,
		decoy:       decoy,
		limiter:     NewLimiter(cfg.Limits),
		serverName:  cfg.ServerName,
		network:     cfg.Network,
		dialTimeout: cfg.TargetDialTimeout,
		now:         time.Now,
		closed:      make(chan struct{}),
	}
	server.h3 = &http3.Server{
		Addr:           listener.Addr().String(),
		TLSConfig:      tlsConfig,
		QUICConfig:     cfg.QUICConfig,
		Handler:        server,
		MaxHeaderBytes: 16 << 10,
		IdleTimeout:    60 * time.Second,
	}
	go func() {
		_ = server.h3.ServeListener(listener)
	}()
	go server.refreshDecoy(ctx, cfg.DecoyRefreshInterval)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-server.closed:
		}
	}()
	return server, ServerInfo{Addr: listener.Addr().String(), Fingerprint: fingerprint}, nil
}

func (s *Server) Addr() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.h3 != nil {
			if err := s.h3.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.closeErr = err
			}
		}
		if s.listener != nil {
			if err := s.listener.Close(); err != nil && !errors.Is(err, quic.ErrServerClosed) && s.closeErr == nil {
				s.closeErr = err
			}
		}
		if s.packetConn != nil {
			if err := s.packetConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && s.closeErr == nil {
				s.closeErr = err
			}
		}
	})
	return s.closeErr
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authenticated := r.Method == http.MethodConnect && s.auth.Validate(r.Header.Get("Authorization"), r.Method, r.Host, s.serverName, s.now())
	release, ok := s.limiter.Allow(r.RemoteAddr, authenticated)
	if !ok {
		writeRateLimited(w)
		return
	}
	defer release()
	if r.Method != http.MethodConnect {
		s.decoy.ServeHTTP(w, r)
		return
	}
	if !authenticated {
		s.serveUnauthenticated(w, r)
		return
	}
	validatedTarget, err := chimera.ResolveAndValidateAuthority(r.Context(), r.Host, s.network.LookupIP)
	if err != nil {
		writeConnectFailure(w)
		return
	}
	dialCtx, cancel := context.WithTimeout(r.Context(), s.dialTimeout)
	target, err := s.network.DialContext(dialCtx, "tcp", validatedTarget)
	cancel()
	if err != nil {
		writeConnectFailure(w)
		return
	}
	defer target.Close()
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		writeConnectFailure(w)
		return
	}
	w.WriteHeader(http.StatusOK)
	stream := streamer.HTTPStream()
	relayH3Stream(stream, target)
}

func (s *Server) serveUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.decoy.serveStatus(w, r, http.StatusNotFound)
		return
	}
	s.decoy.ServeHTTP(w, r)
}

func (s *Server) refreshDecoy(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = s.decoy.Refresh(refreshCtx)
			cancel()
		case <-ctx.Done():
			return
		case <-s.closed:
			return
		}
	}
}

func guardedHTTPClient(network NetworkHooks, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, dialNetwork, authority string) (net.Conn, error) {
			validated, err := chimera.ResolveAndValidateAuthority(ctx, authority, network.LookupIP)
			if err != nil {
				return nil, err
			}
			return network.DialContext(ctx, dialNetwork, validated)
		},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func writeConnectFailure(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Retry-After", "60")
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}

func relayH3Stream(stream *http3.Stream, target net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(target, stream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, target)
		done <- struct{}{}
	}()
	<-done
	_ = stream.SetDeadline(time.Now())
	_ = target.SetDeadline(time.Now())
	<-done
	stream.CancelRead(0)
	_ = stream.Close()
}
