package quicx

import (
	"bytes"
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	authVersion  byte = 5
	authKeyLen        = 32
	authNonceLen      = 16
	authMACLen        = sha256.Size
	authTokenLen      = 1 + 8 + authNonceLen + authMACLen
	authScheme        = "Bearer"
)

var authKeyInfo = []byte("chimera-h3-auth-v1")

type Authenticator struct {
	keys    [][]byte
	maxSkew time.Duration
	replay  *replayCache
	rand    io.Reader
}

func DeriveAuthKey(psk, publicKey, shortID []byte) ([]byte, error) {
	if len(psk) != authKeyLen {
		return nil, errors.New("quicx: QUIC PSK must be exactly 32 bytes")
	}
	if len(publicKey) != 32 {
		return nil, errors.New("quicx: REALITY public key must be exactly 32 bytes")
	}
	if len(shortID) == 0 || len(shortID) > 8 {
		return nil, errors.New("quicx: short ID must contain 1 to 8 bytes")
	}
	salt := make([]byte, 0, len(publicKey)+len(shortID))
	salt = append(salt, publicKey...)
	salt = append(salt, shortID...)
	reader := hkdf.New(sha256.New, psk, salt, authKeyInfo)
	key := make([]byte, authKeyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func NewAuthenticator(keys [][]byte, maxSkew time.Duration, replayCapacity int) (*Authenticator, error) {
	if len(keys) == 0 {
		return nil, errors.New("quicx: at least one authentication key is required")
	}
	if maxSkew <= 0 {
		return nil, errors.New("quicx: authentication clock skew must be positive")
	}
	if replayCapacity <= 0 {
		return nil, errors.New("quicx: replay capacity must be positive")
	}
	copied := make([][]byte, len(keys))
	for i, key := range keys {
		if len(key) != authKeyLen {
			return nil, errors.New("quicx: authentication keys must be exactly 32 bytes")
		}
		copied[i] = append([]byte(nil), key...)
	}
	return &Authenticator{
		keys:    copied,
		maxSkew: maxSkew,
		replay:  newReplayCache(replayCapacity, 2*maxSkew+time.Second),
		rand:    rand.Reader,
	}, nil
}

func (a *Authenticator) Sign(method, authority, serverName string, now time.Time) (string, error) {
	method, authority, serverName, err := normalizeAuthFields(method, authority, serverName)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, authNonceLen)
	if _, err := io.ReadFull(a.rand, nonce); err != nil {
		return "", err
	}
	timestamp := now.Unix()
	input, err := canonicalAuthInput(timestamp, nonce, method, authority, serverName)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, a.keys[0])
	_, _ = mac.Write(input)

	token := make([]byte, 0, authTokenLen)
	token = append(token, authVersion)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))
	token = append(token, ts[:]...)
	token = append(token, nonce...)
	token = append(token, mac.Sum(nil)...)
	return authScheme + " " + base64.RawURLEncoding.EncodeToString(token), nil
}

func (a *Authenticator) Validate(header, method, authority, serverName string, now time.Time) bool {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], authScheme) {
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(token) != authTokenLen || token[0] != authVersion {
		return false
	}
	timestamp := int64(binary.BigEndian.Uint64(token[1:9]))
	issuedAt := time.Unix(timestamp, 0)
	if issuedAt.Before(now.Add(-a.maxSkew)) || issuedAt.After(now.Add(a.maxSkew)) {
		return false
	}
	nonce := token[9 : 9+authNonceLen]
	providedMAC := token[9+authNonceLen:]
	method, authority, serverName, err = normalizeAuthFields(method, authority, serverName)
	if err != nil {
		return false
	}
	input, err := canonicalAuthInput(timestamp, nonce, method, authority, serverName)
	if err != nil {
		return false
	}
	matched := false
	for _, key := range a.keys {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(input)
		if hmac.Equal(mac.Sum(nil), providedMAC) {
			matched = true
		}
	}
	if !matched {
		return false
	}
	return a.replay.Add(nonce, now)
}

func normalizeAuthFields(method, authority, serverName string) (string, string, string, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	authority = strings.ToLower(strings.TrimSpace(authority))
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	if method == "" || authority == "" || serverName == "" {
		return "", "", "", errors.New("quicx: method, authority and server name are required")
	}
	if len(method) > 65535 || len(authority) > 65535 || len(serverName) > 65535 {
		return "", "", "", errors.New("quicx: authentication field is too long")
	}
	return method, authority, serverName, nil
}

func canonicalAuthInput(timestamp int64, nonce []byte, method, authority, serverName string) ([]byte, error) {
	if len(nonce) != authNonceLen {
		return nil, errors.New("quicx: invalid authentication nonce length")
	}
	var buf bytes.Buffer
	buf.Grow(1 + 8 + authNonceLen + 6 + len(method) + len(authority) + len(serverName))
	buf.WriteByte(authVersion)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))
	buf.Write(ts[:])
	buf.Write(nonce)
	for _, field := range []string{method, authority, serverName} {
		if len(field) > 65535 {
			return nil, errors.New("quicx: authentication field is too long")
		}
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(field)))
		buf.Write(size[:])
		buf.WriteString(field)
	}
	return buf.Bytes(), nil
}

type replayEntry struct {
	key       string
	expiresAt time.Time
}

type replayCache struct {
	mu       sync.Mutex
	capacity int
	window   time.Duration
	items    map[string]*list.Element
	order    *list.List
}

func newReplayCache(capacity int, window time.Duration) *replayCache {
	return &replayCache{
		capacity: capacity,
		window:   window,
		items:    make(map[string]*list.Element, capacity),
		order:    list.New(),
	}
}

func (c *replayCache) Add(nonce []byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneExpired(now)
	key := string(nonce)
	if _, exists := c.items[key]; exists {
		return false
	}
	for len(c.items) >= c.capacity {
		c.removeElement(c.order.Front())
	}
	elem := c.order.PushBack(replayEntry{key: key, expiresAt: now.Add(c.window)})
	c.items[key] = elem
	return true
}

func (c *replayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *replayCache) pruneExpired(now time.Time) {
	for elem := c.order.Front(); elem != nil; elem = c.order.Front() {
		entry := elem.Value.(replayEntry)
		if entry.expiresAt.After(now) {
			return
		}
		c.removeElement(elem)
	}
}

func (c *replayCache) removeElement(elem *list.Element) {
	if elem == nil {
		return
	}
	entry := elem.Value.(replayEntry)
	delete(c.items, entry.key)
	c.order.Remove(elem)
}
