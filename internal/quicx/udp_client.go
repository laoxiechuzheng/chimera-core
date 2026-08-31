package quicx

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// UDPConn is a single-target UDP association carried by HTTP/3 Datagrams.
// The association owns only its request stream; the parent QUIC connection
// remains available for other streams until Client.Close is called.
type UDPConn struct {
	stream    *http3.RequestStream
	local     net.Addr
	remote    net.Addr
	target    net.Addr
	maxPacket int
	ctx       context.Context
	cancel    context.CancelFunc
	encoder   *udpFragmentEncoder
	decoder   *udpFragmentDecoder

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	closeOnce     sync.Once
	closeErr      error
}

type udpTargetAddr struct {
	authority string
}

func (a udpTargetAddr) Network() string { return "udp" }
func (a udpTargetAddr) String() string  { return a.authority }

func newUDPConn(stream *http3.RequestStream, local, remote, target net.Addr, maxPacket int) *UDPConn {
	if maxPacket <= 0 {
		maxPacket = defaultUDPMaxPacketSize
	}
	ctx, cancel := context.WithCancel(stream.Context())
	return &UDPConn{
		stream:    stream,
		local:     local,
		remote:    remote,
		target:    target,
		maxPacket: maxPacket,
		ctx:       ctx,
		cancel:    cancel,
		encoder:   newUDPFragmentEncoder(maxPacket),
		decoder:   newUDPFragmentDecoder(maxPacket),
	}
}

func (c *UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c == nil || c.stream == nil {
		return 0, nil, net.ErrClosed
	}
	ctx, cancel := c.readContext()
	defer cancel()
	for {
		data, err := c.stream.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			return 0, nil, err
		}
		packet, err := c.decoder.Decode(data)
		if err != nil {
			return 0, nil, err
		}
		if packet == nil {
			continue
		}
		n := copy(p, packet)
		return n, c.target, nil
	}
}

func (c *UDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c == nil || c.stream == nil {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, errors.New("quicx: empty UDP datagram")
	}
	if len(p) > c.maxPacket {
		return 0, errors.New("quicx: UDP datagram exceeds configured size")
	}
	deadline := c.getWriteDeadline()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if err := c.stream.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	frames, err := c.encoder.Encode(p)
	if err != nil {
		return 0, err
	}
	for _, frame := range frames {
		if err := c.stream.SendDatagram(frame); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *UDPConn) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.cancel()
		if c.stream != nil {
			c.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			c.stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			c.closeErr = c.stream.Close()
		}
	})
	return c.closeErr
}

func (c *UDPConn) LocalAddr() net.Addr  { return c.local }
func (c *UDPConn) RemoteAddr() net.Addr { return c.remote }

func (c *UDPConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.mu.Unlock()
	if c.stream == nil {
		return net.ErrClosed
	}
	return c.stream.SetDeadline(deadline)
}

func (c *UDPConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	if c.stream == nil {
		return net.ErrClosed
	}
	return c.stream.SetReadDeadline(deadline)
}

func (c *UDPConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	if c.stream == nil {
		return net.ErrClosed
	}
	return c.stream.SetWriteDeadline(deadline)
}

func (c *UDPConn) readContext() (context.Context, context.CancelFunc) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()
	if deadline.IsZero() {
		return context.WithCancel(c.ctx)
	}
	return context.WithDeadline(c.ctx, deadline)
}

func (c *UDPConn) getWriteDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDeadline
}

var _ net.PacketConn = (*UDPConn)(nil)
