package server

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3, 100*time.Millisecond)
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("attempt %d: should have been allowed", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Error("4th attempt within window should be blocked")
	}
	if !rl.allow("5.6.7.8") {
		t.Error("different key should not be blocked")
	}
	time.Sleep(110 * time.Millisecond)
	if !rl.allow("1.2.3.4") {
		t.Error("after window, should be allowed again")
	}
}

// The hits map must stay bounded even when every key is live inside the
// window (an attacker rotating IPv6 source addresses creates fresh keys
// faster than expiry can drain them). Before the hard cap this grew without
// limit — a memory-exhaustion DoS on a RAM-constrained router.
func TestRateLimiterBoundedUnderKeyFlood(t *testing.T) {
	rl := newRateLimiter(3, time.Hour)
	for i := 0; i < 50000; i++ {
		rl.allow(fmt.Sprintf("2001:db8::%x", i))
	}
	rl.mu.Lock()
	n := len(rl.hits)
	rl.mu.Unlock()
	if n > 8192 {
		t.Errorf("hits map grew to %d entries under key flood; want <= 8192", n)
	}
}

func TestRateLimiterEmptyKey(t *testing.T) {
	rl := newRateLimiter(1, time.Hour)
	if !rl.allow("") {
		t.Error("empty key should always be allowed (no rate-limit)")
	}
	if !rl.allow("") {
		t.Error("empty key should always be allowed (no rate-limit) - second call")
	}
}
