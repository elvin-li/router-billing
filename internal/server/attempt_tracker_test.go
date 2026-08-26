package server

import (
	"fmt"
	"testing"
	"time"
)

func TestAttemptTrackerCountsAndResets(t *testing.T) {
	tr := newAttemptTracker(time.Minute)
	if n := tr.next("tok"); n != 1 {
		t.Errorf("first attempt = %d", n)
	}
	if n := tr.next("tok"); n != 2 {
		t.Errorf("second attempt = %d", n)
	}
	tr.reset("tok")
	if n := tr.next("tok"); n != 1 {
		t.Errorf("post-reset attempt = %d", n)
	}
}

func TestAttemptTrackerSweepsAbandonedEntries(t *testing.T) {
	// Abandoned pending-2FA logins (never a success, never a lockout) used
	// to leak one map entry each, forever. With the TTL sweep, flooding the
	// tracker with expired entries must not grow the map without bound.
	tr := newAttemptTracker(10 * time.Millisecond)
	for i := 0; i < attemptSweepThreshold+50; i++ {
		tr.next(fmt.Sprintf("stale-%d", i))
	}
	time.Sleep(20 * time.Millisecond) // everything above is now past TTL

	// Fresh inserts past the threshold trigger the sweep of stale entries.
	for i := 0; i < 10; i++ {
		tr.next(fmt.Sprintf("fresh-%d", i))
	}
	if got := tr.size(); got > attemptSweepThreshold {
		t.Errorf("tracker holds %d entries; stale ones were not swept", got)
	}
	// Fresh (non-expired) entries must survive the sweep with their counts.
	if n := tr.next("fresh-0"); n != 2 {
		t.Errorf("fresh entry count = %d, want 2 (sweep must not evict live entries)", n)
	}
}

func TestAttemptTrackerKeepsCountWithinTTL(t *testing.T) {
	tr := newAttemptTracker(time.Hour)
	for i := 0; i < 5; i++ {
		tr.next("victim")
	}
	if n := tr.next("victim"); n != 6 {
		t.Errorf("count = %d, want 6 — TTL sweep must not reset live brute-force counters", n)
	}
}
