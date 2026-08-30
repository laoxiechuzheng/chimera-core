package quicx

import (
	"net"
	"strings"
	"sync"
	"time"
)

type LimitConfig struct {
	MaxConcurrent int
	PerIPBurst    int
	PerIPWindow   time.Duration
	MaxTrackedIPs int
}

type ipLimitState struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type Limiter struct {
	sem chan struct{}

	mu            sync.Mutex
	perIPBurst    int
	perIPWindow   time.Duration
	maxTrackedIPs int
	ips           map[string]*ipLimitState
	now           func() time.Time
}

func NewLimiter(cfg LimitConfig) *Limiter {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 128
	}
	if cfg.PerIPBurst <= 0 {
		cfg.PerIPBurst = 20
	}
	if cfg.PerIPWindow <= 0 {
		cfg.PerIPWindow = time.Minute
	}
	if cfg.MaxTrackedIPs <= 0 {
		cfg.MaxTrackedIPs = 4096
	}
	return &Limiter{
		sem:           make(chan struct{}, cfg.MaxConcurrent),
		perIPBurst:    cfg.PerIPBurst,
		perIPWindow:   cfg.PerIPWindow,
		maxTrackedIPs: cfg.MaxTrackedIPs,
		ips:           make(map[string]*ipLimitState, cfg.MaxTrackedIPs),
		now:           time.Now,
	}
}

func (l *Limiter) Allow(remoteAddr string, authenticated bool) (func(), bool) {
	select {
	case l.sem <- struct{}{}:
	default:
		return nil, false
	}
	var once sync.Once
	releaseSemaphore := func() {
		once.Do(func() { <-l.sem })
	}
	if authenticated {
		return releaseSemaphore, true
	}
	now := l.now()
	ip := remoteIP(remoteAddr)
	l.mu.Lock()
	state := l.ips[ip]
	if state == nil {
		if len(l.ips) >= l.maxTrackedIPs {
			l.evictOldestIP()
		}
		state = &ipLimitState{tokens: float64(l.perIPBurst), updated: now}
		l.ips[ip] = state
	}
	if now.After(state.updated) {
		elapsed := now.Sub(state.updated)
		state.tokens += elapsed.Seconds() / l.perIPWindow.Seconds() * float64(l.perIPBurst)
		if state.tokens > float64(l.perIPBurst) {
			state.tokens = float64(l.perIPBurst)
		}
		state.updated = now
	}
	state.lastSeen = now
	if state.tokens < 1 {
		l.mu.Unlock()
		releaseSemaphore()
		return nil, false
	}
	state.tokens--
	l.mu.Unlock()
	return releaseSemaphore, true
}

func (l *Limiter) trackedIPs() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ips)
}

func (l *Limiter) evictOldestIP() {
	var oldestKey string
	var oldestTime time.Time
	for key, state := range l.ips {
		if oldestKey == "" || state.lastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = state.lastSeen
		}
	}
	delete(l.ips, oldestKey)
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil && host != "" {
		return strings.ToLower(host)
	}
	return strings.ToLower(strings.TrimSpace(remoteAddr))
}
