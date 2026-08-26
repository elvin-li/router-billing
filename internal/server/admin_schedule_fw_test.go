package server

import (
	"context"
	"net/url"
	"sync"
	"testing"

	"router-billing/internal/firewall"
	"router-billing/internal/models"
)

// recordFW is a firewall.API fake that records Add/Remove calls so tests
// can assert exactly which MACs a handler pushed into (or pulled out of)
// the paid set. The dry-run nftables manager only logs, so it can't be
// used for these assertions.
type recordFW struct {
	mu      sync.Mutex
	added   []string
	removed []string
}

func (f *recordFW) EnsureSet(ctx context.Context) error { return nil }
func (f *recordFW) Add(ctx context.Context, mac string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, mac)
	return nil
}
func (f *recordFW) Remove(ctx context.Context, mac string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, mac)
	return nil
}
func (f *recordFW) Sync(ctx context.Context, macs []string) error { return nil }
func (f *recordFW) List(ctx context.Context) ([]string, error)    { return nil, nil }
func (f *recordFW) Counters(ctx context.Context) (map[string]firewall.MACCounter, error) {
	return map[string]firewall.MACCounter{}, nil
}

func (f *recordFW) didAdd(mac string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.added {
		if m == mac {
			return true
		}
	}
	return false
}

func (f *recordFW) didRemove(mac string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.removed {
		if m == mac {
			return true
		}
	}
	return false
}

// Clearing a schedule on a BLOCKED MAC must not re-add it to the firewall.
// Pre-v0.108 the clear branch called FW.Add unconditionally, so a blocked
// (or expired) MAC came back online until the next resync.
func TestScheduleClearDoesNotReAddBlockedMAC(t *testing.T) {
	app := setupTestApp(t)
	fw := &recordFW{}
	app.MACSvc.FW = fw
	ctx := context.Background()

	const mac = "AA:BB:CC:00:33:01"
	if _, err := app.DB.UpsertMAC(ctx, mac, "abuser", 30, nil); err != nil {
		t.Fatal(err)
	}
	sched := models.MacSchedule{Days: []int{1, 2, 3, 4, 5, 6, 7}, StartMin: 0, EndMin: 1439}
	if err := app.DB.SetMACSchedule(ctx, mac, sched.JSON()); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.SetMACStatus(ctx, mac, models.MACBlocked); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/macs/schedule",
		url.Values{"_csrf": {csrf}, "mac": {mac}, "clear": {"1"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if fw.didAdd(mac) {
		t.Error("clearing a schedule on a BLOCKED MAC must not FW.Add it")
	}
	m, _ := app.DB.GetMAC(ctx, mac)
	if m == nil || m.ScheduleJSON != "" {
		t.Error("schedule should still be cleared in the DB")
	}
}

// Clearing a schedule on a healthy active MAC re-adds it (24x7 access).
func TestScheduleClearReAddsActiveMAC(t *testing.T) {
	app := setupTestApp(t)
	fw := &recordFW{}
	app.MACSvc.FW = fw
	ctx := context.Background()

	const mac = "AA:BB:CC:00:33:02"
	if _, err := app.DB.UpsertMAC(ctx, mac, "kid-tablet", 30, nil); err != nil {
		t.Fatal(err)
	}
	sched := models.MacSchedule{Days: []int{1, 2, 3, 4, 5}, StartMin: 18 * 60, EndMin: 22 * 60}
	if err := app.DB.SetMACSchedule(ctx, mac, sched.JSON()); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/macs/schedule",
		url.Values{"_csrf": {csrf}, "mac": {mac}, "clear": {"1"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !fw.didAdd(mac) {
		t.Error("clearing a schedule on an active MAC should FW.Add it back")
	}
}

// applyOneSchedule (the immediate-apply path after a schedule save) must not
// add an expired MAC even when the schedule window is currently open.
func TestApplyOneScheduleSkipsExpiredMAC(t *testing.T) {
	app := setupTestApp(t)
	fw := &recordFW{}
	app.MACSvc.FW = fw
	ctx := context.Background()

	const mac = "AA:BB:CC:00:33:03"
	// Negative days → expires_at in the past.
	if _, err := app.DB.UpsertMAC(ctx, mac, "long-gone", -5, nil); err != nil {
		t.Fatal(err)
	}
	sched := models.MacSchedule{Days: []int{1, 2, 3, 4, 5, 6, 7}, StartMin: 0, EndMin: 1439}
	app.applyOneSchedule(mac, sched)

	if fw.didAdd(mac) {
		t.Error("expired MAC must not be added by a schedule save")
	}
	if !fw.didRemove(mac) {
		t.Error("ineligible MAC should be defensively removed")
	}
}

// Sanity: an active, unexpired MAC inside its window IS added.
func TestApplyOneScheduleAddsEligibleMACInWindow(t *testing.T) {
	app := setupTestApp(t)
	fw := &recordFW{}
	app.MACSvc.FW = fw
	ctx := context.Background()

	const mac = "AA:BB:CC:00:33:04"
	if _, err := app.DB.UpsertMAC(ctx, mac, "office", 30, nil); err != nil {
		t.Fatal(err)
	}
	// 00:00–23:59 every day: always inside the window (except the final
	// minute of the day, which Active() treats as outside; acceptable for
	// a smoke assertion).
	sched := models.MacSchedule{Days: []int{1, 2, 3, 4, 5, 6, 7}, StartMin: 0, EndMin: 1439}
	if !sched.Active(timeNow()) {
		t.Skip("running inside the one-minute 23:59 gap; skip")
	}
	app.applyOneSchedule(mac, sched)
	if !fw.didAdd(mac) {
		t.Error("eligible MAC inside its schedule window should be added")
	}
}
