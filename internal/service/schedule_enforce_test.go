package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"router-billing/internal/models"
)

// scheduleJSONAround builds a schedule window that either includes or
// excludes `now`, on today's ISO weekday, so tests don't depend on when
// they run.
func scheduleJSONAround(t *testing.T, now time.Time, includeNow bool) string {
	t.Helper()
	wd := int(now.Weekday())
	if wd == 0 {
		wd = 7
	}
	nowMin := now.Hour()*60 + now.Minute()
	var s models.MacSchedule
	if includeNow {
		// Window wraps midnight around now so it is always active today.
		s = models.MacSchedule{Days: []int{wd}, StartMin: (nowMin + 720) % 1440, EndMin: (nowMin + 719) % 1440}
	} else {
		// One-minute window as far from now as possible.
		s = models.MacSchedule{Days: []int{wd}, StartMin: (nowMin + 720) % 1440, EndMin: (nowMin + 721) % 1440}
	}
	// Sanity: the constructed schedule must parse and have the intended
	// activity — otherwise the test asserts nothing.
	b, _ := json.Marshal(s)
	parsed, err := models.ParseSchedule(string(b))
	if err != nil {
		t.Fatalf("constructed schedule invalid: %v", err)
	}
	if parsed.Active(now) != includeNow {
		t.Fatalf("constructed schedule Active(now)=%v, want %v (%s)", parsed.Active(now), includeNow, b)
	}
	return string(b)
}

func TestEnforceSchedulesAddsInWindow(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()

	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "kid-tablet", 30, nil)
	if err := dbx.SetMACSchedule(ctx, "AA:BB:CC:DD:EE:FF", scheduleJSONAround(t, now, true)); err != nil {
		t.Fatal(err)
	}
	// Simulate the window having been closed earlier.
	fw.mu.Lock()
	fw.set = map[string]bool{}
	fw.mu.Unlock()

	svc.enforceSchedulesOnce(ctx)

	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("in-window MAC should be re-added to firewall")
	}
	// DB status must be untouched — schedules only gate the firewall.
	m, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:FF")
	if m == nil || m.Status != models.MACActive {
		t.Errorf("status must stay active; got %+v", m)
	}
}

func TestEnforceSchedulesRemovesOutOfWindow(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()

	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "kid-tablet", 30, nil)
	if err := dbx.SetMACSchedule(ctx, "AA:BB:CC:DD:EE:FF", scheduleJSONAround(t, now, false)); err != nil {
		t.Fatal(err)
	}
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Fatal("setup: mac should start in fw")
	}

	svc.enforceSchedulesOnce(ctx)

	if fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("out-of-window MAC should be removed from firewall")
	}
	m, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:FF")
	if m == nil || m.Status != models.MACActive {
		t.Errorf("status must stay active (schedule is not a revoke); got %+v", m)
	}
}

func TestEnforceSchedulesSkipsUnscheduledAndInvalid(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	// No schedule → untouched.
	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:01", "plain", 30, nil)
	// Corrupt schedule JSON → logged + skipped, never removed.
	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:02", "corrupt", 30, nil)
	if err := dbx.SetMACSchedule(ctx, "AA:BB:CC:DD:EE:02", "{not json"); err != nil {
		t.Fatal(err)
	}

	before := len(fw.addCalls) + len(fw.removeCalls)
	svc.enforceSchedulesOnce(ctx)

	if got := len(fw.addCalls) + len(fw.removeCalls); got != before {
		t.Errorf("unscheduled/corrupt MACs must not trigger fw calls; %d new calls", got-before)
	}
	if !fw.set["AA:BB:CC:DD:EE:01"] || !fw.set["AA:BB:CC:DD:EE:02"] {
		t.Error("both MACs should remain in fw set")
	}
}

// EnforceSchedules (the loop) must exit promptly on ctx cancel and apply an
// initial pass before the first tick.
func TestEnforceSchedulesLoopHonoursCancel(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()

	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "x", 30, nil)
	_ = dbx.SetMACSchedule(ctx, "AA:BB:CC:DD:EE:FF", scheduleJSONAround(t, now, false))

	done := make(chan struct{})
	go func() {
		svc.EnforceSchedules(ctx)
		close(done)
	}()

	// The initial pass (pre-tick) should remove the out-of-window MAC.
	deadline := time.After(2 * time.Second)
	for {
		fw.mu.Lock()
		gone := !fw.set["AA:BB:CC:DD:EE:FF"]
		fw.mu.Unlock()
		if gone {
			break
		}
		select {
		case <-deadline:
			t.Fatal("initial enforce pass never ran")
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("EnforceSchedules did not exit after cancel")
	}
}
