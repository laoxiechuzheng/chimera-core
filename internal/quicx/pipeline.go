package quicx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"net"
	"time"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// Pipeline wraps a UDP PacketConn with:
// 1. WireGuard-style packet framing (anti-QoS disguise)
// 2. AES-CTR XOR encryption (obfuscation layer, not security layer)
// 3. Timing jitter (breaks flow periodicity)
// 4. Adaptive rate (sawtooth congestion mimicry)
type Pipeline struct {
	net.PacketConn
	framer  *WGFramer
	key     []byte
	pacing  bool
	lastSend time.Time
}

func (p *Pipeline) SetReadBuffer(bytes int) error {
	if udp, ok := p.PacketConn.(*net.UDPConn); ok {
		return udp.SetReadBuffer(bytes)
	}
	return nil
}

func (p *Pipeline) SetWriteBuffer(bytes int) error {
	if udp, ok := p.PacketConn.(*net.UDPConn); ok {
		return udp.SetWriteBuffer(bytes)
	}
	return nil
}

func NewPipeline(pc net.PacketConn, password string, antiQoS bool) *Pipeline {
	key := make([]byte, 32)
	hkdf.New(sha256.New, []byte(password), nil, []byte("chimera-pipeline-v2")).Read(key)
	return &Pipeline{
		PacketConn: pc,
		framer:     NewWGFramer(antiQoS),
		key:        key,
		pacing:     antiQoS,
	}
}

func (p *Pipeline) keystream(n int) []byte {
	block, _ := aes.NewCipher(p.key)
	iv := make([]byte, 16)
	stream := cipher.NewCTR(block, iv)
	out := make([]byte, n)
	stream.XORKeyStream(out, out)
	return out
}

func (p *Pipeline) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	if n < 16 {
		return 0, addr, nil
	}
	fmt.Printf("PIPELINE READ: n=%d b[0]=%02x b[1]=%02x\n", n, b[0], b[1])
	ks := p.keystream(n)
	for i := 0; i < n; i++ {
		b[i] ^= ks[i]
	}
	// Check WG type byte after decrypt
	if b[0] != WGTypeData {
		fmt.Printf("PIPELINE: WG type mismatch after decrypt: b[0]=%02x expected=%02x\n", b[0], WGTypeData)
		return 0, addr, nil
	}
	quicData, err := p.framer.Unframe(b[:n])
	if err != nil {
		return 0, addr, err
	}
	copy(b, quicData)
	return len(quicData), addr, nil
}

func (p *Pipeline) WriteTo(b []byte, addr net.Addr) (int, error) {
	fmt.Printf("PIPELINE WRITE: len=%d b[0]=%02x\n", len(b), b[0])
	// WG frame
	framed := p.framer.Frame(b)
	// encrypt XOR
	ks := p.keystream(len(framed))
	buf := make([]byte, len(framed))
	for i := range framed {
		buf[i] = framed[i] ^ ks[i]
	}
	// pacing jitter
	if p.pacing {
		time.Sleep(p.framer.Jitter())
	}
	_, err := p.PacketConn.WriteTo(buf, addr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
