package quicx

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"sync/atomic"
	"time"
)

// WireGuard-style UDP framing for anti-QoS disguise.
// Real WireGuard data packet: [type(1)][reserved(3)][receiver_idx(4)][counter(8)][encrypted_data]
// Type 4 = Data, Type 1 = Handshake Init, Type 2 = Handshake Response, Type 3 = Cookie
// We wrap our QUIC packets in this framing so DPI sees WireGuard traffic.

const (
	WGTypeHandshakeInit     = 1
	WGTypeHandshakeResponse = 2
	WGTypeCookieReply       = 3
	WGTypeData              = 4
)

type WGFramer struct {
	receiverIdx uint32 // random but stable per session
	counter     uint64
	jitterMin   time.Duration
	jitterMax   time.Duration
	// Adaptive pacing
	baseRate    uint64 // bytes per second
	currentRate uint64
	rateEpoch   int64
	pacingOn    bool
}

func NewWGFramer(jitter bool) *WGFramer {
	idx, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	return &WGFramer{
		receiverIdx: uint32(idx.Int64()),
		jitterMin:   0,
		jitterMax:   3 * time.Millisecond,
		baseRate:    10 * 1024 * 1024, // 10MB/s
		currentRate: 10 * 1024 * 1024,
		pacingOn:    jitter,
	}
}

// Frame wraps a QUIC packet in WireGuard data-packet framing.
func (w *WGFramer) Frame(quicPacket []byte) []byte {
	buf := make([]byte, 16+len(quicPacket))
	buf[0] = WGTypeData
	// reserved 3 bytes = 0
	binary.BigEndian.PutUint32(buf[4:8], w.receiverIdx)
	binary.BigEndian.PutUint64(buf[8:16], atomic.AddUint64(&w.counter, 1))
	copy(buf[16:], quicPacket)
	return buf
}

// Unframe extracts the QUIC packet from WireGuard framing.
func (w *WGFramer) Unframe(wgPacket []byte) ([]byte, error) {
	if len(wgPacket) < 16 || wgPacket[0] != WGTypeData {
		return nil, errors.New("not a WG data packet")
	}
	return wgPacket[16:], nil
}

// Jitter returns a random delay to inject before sending.
func (w *WGFramer) Jitter() time.Duration {
	if !w.pacingOn {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(w.jitterMax)))
	return time.Duration(n.Int64())
}

// AdaptRate implements sawtooth congestion mimicry:
// Periodically drops to 30% for 1-3 seconds, then linearly recovers to base rate.
// This makes the traffic pattern look like a TCP flow experiencing congestion,
// rather than hy2's constant-rate which QoS flags as "non-TCP UDP flow".
func (w *WGFramer) AdaptRate(now time.Time) {
	phase := (now.Unix() % 30)
	if phase < 2 {
		// congestion phase: drop to 30%
		w.currentRate = w.baseRate * 30 / 100
	} else {
		// recovery: linear ramp from 30% to 100% over remaining seconds
		progress := float64(phase-2) / 28.0
		w.currentRate = uint64(float64(w.baseRate) * (0.3 + 0.7*progress))
	}
}

// CurrentRate returns the adapted rate for this moment.
func (w *WGFramer) CurrentRate() uint64 { return w.currentRate }
