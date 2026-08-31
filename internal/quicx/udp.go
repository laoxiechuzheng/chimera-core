package quicx

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/laoxiechuzheng/chimera-core/internal/chimera"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const udpHeaderName = "Connect-Protocol"

func (s *Server) SupportsUDPRelay() bool {
	return s != nil && s.udpSlots != nil
}

func (s *Server) serveUDPSession(w http.ResponseWriter, r *http.Request) {
	if !s.SupportsUDPRelay() {
		writeConnectFailure(w)
		return
	}
	select {
	case s.udpSlots <- struct{}{}:
		defer func() { <-s.udpSlots }()
	default:
		writeRateLimited(w)
		return
	}
	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		writeConnectFailure(w)
		return
	}
	validatedTarget, err := chimera.ResolveAndValidateAuthority(r.Context(), r.Host, s.network.LookupIP)
	if err != nil {
		writeConnectFailure(w)
		return
	}
	targetAddr, err := net.ResolveUDPAddr("udp", validatedTarget)
	if err != nil || targetAddr.IP == nil || targetAddr.Port == 0 {
		writeConnectFailure(w)
		return
	}
	pc, err := s.network.ListenPacket(r.Context(), "udp", ":0")
	if err != nil {
		writeConnectFailure(w)
		return
	}
	defer pc.Close()
	w.WriteHeader(http.StatusOK)
	stream := streamer.HTTPStream()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	fromClient := newUDPFragmentDecoder(s.udpMaxPacket)
	toClient := newUDPFragmentEncoder(s.udpMaxPacket)
	activity := make(chan struct{}, 1)
	signal := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	done := make(chan error, 2)
	go func() {
		for {
			data, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				done <- err
				return
			}
			packet, err := fromClient.Decode(data)
			if err != nil {
				done <- err
				return
			}
			if packet == nil {
				continue
			}
			if _, err := pc.WriteTo(packet, targetAddr); err != nil {
				done <- err
				return
			}
			signal()
		}
	}()
	go func() {
		buf := make([]byte, s.udpMaxPacket+1)
		for {
			n, source, err := pc.ReadFrom(buf)
			if err != nil {
				done <- err
				return
			}
			if n == 0 || n > s.udpMaxPacket {
				continue
			}
			if !udpSourceMatchesTarget(source, targetAddr) {
				continue
			}
			frames, err := toClient.Encode(buf[:n])
			if err != nil {
				done <- err
				return
			}
			for _, frame := range frames {
				if err := stream.SendDatagram(frame); err != nil {
					done <- err
					return
				}
			}
			signal()
		}
	}()
	timer := time.NewTimer(s.udpIdleTimeout)
	defer timer.Stop()
	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(s.udpIdleTimeout)
	}
	for {
		select {
		case <-r.Context().Done():
			closeUDPSessionStream(stream)
			return
		case <-done:
			closeUDPSessionStream(stream)
			return
		case <-activity:
			resetTimer()
		case <-timer.C:
			closeUDPSessionStream(stream)
			return
		}
	}
}

func udpSourceMatchesTarget(source net.Addr, target *net.UDPAddr) bool {
	if target == nil || target.IP == nil || target.Port == 0 {
		return false
	}
	udpSource, ok := source.(*net.UDPAddr)
	if !ok || udpSource.IP == nil || udpSource.Port != target.Port {
		return false
	}
	return udpSource.IP.Equal(target.IP)
}

func closeUDPSessionStream(stream *http3.Stream) {
	if stream == nil {
		return
	}
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	_ = stream.Close()
}
