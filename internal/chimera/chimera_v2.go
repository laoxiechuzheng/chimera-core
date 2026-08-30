package chimera

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// QUIC auth protocol (v2, matches chimera-spec.md "Mode U"):
// [0]     magic "CHIM"
// [4]     version 0x02
// [5]     cmd (1 = connect)
// [6]     nonce length (8)
// [7-14]  nonce
// [15-46] HMAC-SHA256(auth_password, nonce)
// [47]    address type + address + port (same encoding as TCP mode)

const (
	QUICVersion  = 0x02
	QUICNonceLen = 8
	QUICHMACLen  = 32
	// QUICHeaderLen covers everything before the address.
	QUICHeaderLen = 4 + 1 + 1 + 1 + QUICNonceLen + QUICHMACLen
)

var ErrQUICAuth = errors.New("chimera: quic auth failed")

// DeriveQUICPassword derives the QUIC auth password from server credentials so
// both sides agree without a second secret being configured. It binds the
// password to the REALITY short ID + public key, so rotating either rotates it.
func DeriveQUICPassword(shortID, publicKey []byte) string {
	h := hmac.New(sha256.New, []byte("chimera-quic-key-v2"))
	h.Write(shortID)
	h.Write(publicKey)
	return string(h.Sum(nil))
}

func WriteQUICConnect(w io.Writer, cmd byte, password string, addr *Address) error {
	nonce := make([]byte, QUICNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(nonce)
	auth := mac.Sum(nil)

	buf := make([]byte, 0, QUICHeaderLen+5+len(addr.Domain))
	buf = append(buf, MagicByte0, MagicByte1, MagicByte2, MagicByte3)
	buf = append(buf, QUICVersion)
	buf = append(buf, cmd)
	buf = append(buf, QUICNonceLen)
	buf = append(buf, nonce...)
	buf = append(buf, auth...)
	var addrBuf bytes.Buffer
	if err := WriteAddress(&addrBuf, addr); err != nil {
		return err
	}
	buf = append(buf, addrBuf.Bytes()...)
	_, err := w.Write(buf)
	return err
}

func ReadQUICConnect(r io.Reader, password string) (byte, *Address, error) {
	return ReadQUICConnectWithCache(r, password, nil)
}

// ReadQUICConnectWithCache additionally enforces replay protection when cache
// is non-nil.
func ReadQUICConnectWithCache(r io.Reader, password string, cache *ReplayCache) (byte, *Address, error) {
	head := make([]byte, QUICHeaderLen)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, nil, err
	}
	if head[0] != MagicByte0 || head[1] != MagicByte1 || head[2] != MagicByte2 || head[3] != MagicByte3 {
		return 0, nil, ErrBadMagic
	}
	if head[4] != QUICVersion {
		return 0, nil, ErrVersionMismatch
	}
	cmd := head[5]
	nonceLen := int(head[6])
	if nonceLen != QUICNonceLen {
		return 0, nil, fmt.Errorf("chimera: bad nonce length %d", nonceLen)
	}
	nonce := head[7 : 7+nonceLen]
	auth := head[7+nonceLen : 7+nonceLen+QUICHMACLen]
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(nonce)
	if !hmac.Equal(mac.Sum(nil), auth) {
		return 0, nil, ErrQUICAuth
	}
	if cache != nil && !cache.Add(nonce) {
		return 0, nil, ErrQUICAuth
	}
	addr, err := ReadAddress(r)
	return cmd, addr, err
}

// Status codes for the QUIC connect-result frame.
const (
	QUICStatusOK        = 0x00
	QUICStatusDialError = 0x01
)

// WriteQUICResult writes the post-dial result frame (8 bytes, same shape as TCP
// session response but with its own status namespace).
func WriteQUICResult(w io.Writer, status byte) error {
	resp := make([]byte, 8)
	resp[0] = MagicByte0
	resp[1] = MagicByte1
	resp[2] = MagicByte2
	resp[3] = MagicByte3
	resp[4] = QUICVersion
	resp[5] = status
	_, err := w.Write(resp)
	return err
}

func ReadQUICResult(r io.Reader) (byte, error) {
	resp := make([]byte, 8)
	if _, err := io.ReadFull(r, resp); err != nil {
		return 0, err
	}
	if resp[0] != MagicByte0 || resp[1] != MagicByte1 || resp[2] != MagicByte2 || resp[3] != MagicByte3 {
		return 0, ErrBadMagic
	}
	if resp[4] != QUICVersion {
		return 0, ErrVersionMismatch
	}
	return resp[5], nil
}

// ReplayCache tracks recently seen nonces to reject replayed QUIC connect
// frames. Entries expire after window; pruning happens lazily on insert.
type ReplayCache struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	window time.Duration
}

func NewReplayCache(window time.Duration) *ReplayCache {
	return &ReplayCache{seen: make(map[string]time.Time), window: window}
}

// Add returns false if the nonce was already seen inside the window.
func (c *ReplayCache) Add(nonce []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	// Amortized pruning: do a full sweep only when the map grows past the
	// high-water mark. Entry lifetime is bounded by the window, so between
	// sweeps the map holds at most window-rate entries.
	if len(c.seen) >= replayCacheMax {
		for k, t := range c.seen {
			if now.Sub(t) > c.window {
				delete(c.seen, k)
			}
		}
	}
	key := string(nonce)
	if _, ok := c.seen[key]; ok {
		return false
	}
	c.seen[key] = now
	return true
}

const replayCacheMax = 4096
