package sightings

import (
	"context"
	"testing"
	"time"
)

// TestTrackerHonoursContextCancel: with Iface="" the scan path is a no-op
// (early return). We rely on this to test that Run() exits cleanly when
// the parent ctx is canceled.
func TestTrackerHonoursContextCancel(t *testing.T) {
	tr := &Tracker{
		Iface:    "", // no-op scan
		Interval: 10 * time.Millisecond,
		Retain:   1 * time.Minute,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tr.Run(ctx)
		close(done)
	}()

	// Let a few ticks fire (each is a no-op due to empty Iface).
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run did not exit promptly after cancel")
	}
}

func TestTrackerDefaultsApplied(t *testing.T) {
	tr := &Tracker{Iface: ""}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	tr.Run(ctx)

	if tr.Interval != 30*time.Second {
		t.Errorf("default Interval should be 30s, got %s", tr.Interval)
	}
	if tr.Retain != 24*time.Hour {
		t.Errorf("default Retain should be 24h, got %s", tr.Retain)
	}
}

// scan is a no-op when Iface is empty — covered indirectly above, but a
// direct call makes the intent obvious in coverage tools.
func TestScanNoIfaceIsNoOp(t *testing.T) {
	tr := &Tracker{Iface: ""}
	// Pass a nil DB on purpose — the early return means we never dereference.
	tr.scan(context.Background())
}
