package quicx

import (
	"testing"
	"time"
)

func TestLimiterBoundsGlobalConcurrency(t *testing.T) {
	now := time.Unix(1_788_000_000, 0)
	l := NewLimiter(LimitConfig{MaxConcurrent: 1, PerIPBurst: 10, PerIPWindow: time.Minute, MaxTrackedIPs: 4})
	l.now = func() time.Time { return now }
	release, ok := l.Allow("192.0.2.1:1000", true)
	if !ok {
		t.Fatal("first request rejected")
	}
	if _, ok := l.Allow("192.0.2.2:1000", true); ok {
		t.Fatal("global concurrency limit bypassed")
	}
	release()
	releaseAgain, ok := l.Allow("192.0.2.2:1000", true)
	if !ok {
		t.Fatal("request rejected after release")
	}
	releaseAgain()
}

func TestLimiterEnforcesPerIPBurstAndRefill(t *testing.T) {
	now := time.Unix(1_788_000_000, 0)
	l := NewLimiter(LimitConfig{MaxConcurrent: 2, PerIPBurst: 1, PerIPWindow: time.Minute, MaxTrackedIPs: 4})
	l.now = func() time.Time { return now }
	release, ok := l.Allow("192.0.2.1:1000", false)
	if !ok {
		t.Fatal("first request rejected")
	}
	release()
	if _, ok := l.Allow("192.0.2.1:1001", false); ok {
		t.Fatal("per-IP burst limit bypassed")
	}
	now = now.Add(time.Minute)
	release, ok = l.Allow("192.0.2.1:1002", false)
	if !ok {
		t.Fatal("token did not refill")
	}
	release()
}

func TestLimiterTrackedIPMapHasHardBound(t *testing.T) {
	now := time.Unix(1_788_000_000, 0)
	l := NewLimiter(LimitConfig{MaxConcurrent: 4, PerIPBurst: 1, PerIPWindow: time.Minute, MaxTrackedIPs: 2})
	l.now = func() time.Time { return now }
	for _, remote := range []string{"192.0.2.1:1", "192.0.2.2:1", "192.0.2.3:1"} {
		release, ok := l.Allow(remote, false)
		if !ok {
			t.Fatalf("request for %s rejected", remote)
		}
		release()
		now = now.Add(time.Second)
	}
	if got := l.trackedIPs(); got != 2 {
		t.Fatalf("tracked IPs = %d, want 2", got)
	}
}

func TestLimiterReleaseIsIdempotent(t *testing.T) {
	l := NewLimiter(LimitConfig{MaxConcurrent: 1, PerIPBurst: 2, PerIPWindow: time.Minute, MaxTrackedIPs: 2})
	release, ok := l.Allow("192.0.2.1:1000", true)
	if !ok {
		t.Fatal("first request rejected")
	}
	release()
	release()
	release2, ok := l.Allow("192.0.2.2:1000", true)
	if !ok {
		t.Fatal("idempotent release corrupted semaphore")
	}
	release2()
}
