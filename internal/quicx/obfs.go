package quicx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"net"

	"golang.org/x/crypto/hkdf"
)

// obfsPacketConn wraps a UDP PacketConn with length-preserving AES-CTR XOR.
// Both directions use the same keystream (fixed nonce); packets are stateless
// (fresh counter per packet), so UDP loss cannot desync the streams.
type obfsPacketConn struct {
	net.PacketConn
	key []byte
}

func NewObfsPacketConn(pc net.PacketConn, password string) net.PacketConn {
	key := make([]byte, 32)
	hkdf.New(sha256.New, []byte(password), nil, []byte("chimera-obfs-v1")).Read(key)
	return &obfsPacketConn{PacketConn: pc, key: key}
}

func (c *obfsPacketConn) keystream(n int) []byte {
	block, _ := aes.NewCipher(c.key)
	iv := make([]byte, 16)
	stream := cipher.NewCTR(block, iv)
	out := make([]byte, n)
	stream.XORKeyStream(out, out)
	return out
}

func (c *obfsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	ks := c.keystream(n)
	for i := 0; i < n; i++ {
		b[i] ^= ks[i]
	}
	return n, addr, nil
}

func (c *obfsPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ks := c.keystream(len(b))
	buf := make([]byte, len(b))
	for i := range b {
		buf[i] = b[i] ^ ks[i]
	}
	return c.PacketConn.WriteTo(buf, addr)
}
