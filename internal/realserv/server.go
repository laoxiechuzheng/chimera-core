package realserv

import (
	"context"
	"net"

	"github.com/xtls/reality"
)

type ServerConfig struct {
	ListenAddr  string
	Target      string
	ServerNames []string
	PrivateKey  []byte
	ShortIds    [][]byte
	Show        bool
}

func Listen(config *ServerConfig) (net.Listener, error) {
	rc := &reality.Config{
		Show:                   config.Show,
		Type:                   "tcp",
		Dest:                   config.Target,
		SessionTicketsDisabled: true,
		ServerNames:            make(map[string]bool),
		PrivateKey:             config.PrivateKey,
		ShortIds:               make(map[[8]byte]bool),
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	}
	for _, sn := range config.ServerNames {
		rc.ServerNames[sn] = true
	}
	for _, sid := range config.ShortIds {
		var s [8]byte
		copy(s[:], sid)
		rc.ShortIds[s] = true
	}
	inner, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return nil, err
	}
	return reality.NewListener(inner, rc), nil
}
