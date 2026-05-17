package server

import (
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

func TestRateLimiterEmptyKey(t *testing.T) {
	rl := newRateLimiter(1, time.Hour)
	if !rl.allow("") {
		t.Error("empty key should always be allowed (no rate-limit)")
	}
	if !rl.allow("") {
		t.Error("empty key should always be allowed (no rate-limit) - second call")
	}
}
