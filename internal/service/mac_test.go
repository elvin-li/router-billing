package service

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"router-billing/internal/db"
	"router-billing/internal/firewall"
	"router-billing/internal/models"
)

// fakeFW records calls + returns canned errors on request, satisfying
// firewall.API. Operations are kept in-memory so we can assert end state.
type fakeFW struct {
	mu       sync.Mutex
	set      map[string]bool
	counters map[string]firewall.MACCounter
	addErr   error
	rmErr    error
	syncErr  error

	addCalls    []string
	removeCalls []string
	syncCalls   [][]string
	ensured     bool
}

func newFakeFW() *fakeFW {
	return &fakeFW{
		set:      map[string]bool{},
		counters: map[string]firewall.MACCounter{},
	}
}

func (f *fakeFW) EnsureSet(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = true
	return nil
}

func (f *fakeFW) Add(_ context.Context, mac string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls = append(f.addCalls, mac)
	if f.addErr != nil {
		return f.addErr
	}
	f.set[mac] = true
	return nil
}

func (f *fakeFW) Remove(_ context.Context, mac string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls = append(f.removeCalls, mac)
	if f.rmErr != nil {
		return f.rmErr
	}
	delete(f.set, mac)
	return nil
}

func (f *fakeFW) Sync(_ context.Context, macs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	dup := make([]string, len(macs))
	copy(dup, macs)
	f.syncCalls = append(f.syncCalls, dup)
	if f.syncErr != nil {
		return f.syncErr
	}
	f.set = map[string]bool{}
	for _, m := range macs {
		f.set[m] = true
	}
	return nil
}

func (f *fakeFW) List(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.set))
	for m := range f.set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeFW) Counters(_ context.Context) (map[string]firewall.MACCounter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]firewall.MACCounter, len(f.counters))
	for k, v := range f.counters {
		out[k] = v
	}
	return out, nil
}

// helpers ----------------------------------------------------------------

func newTestSvc(t *testing.T) (*MACService, *db.DB, *fakeFW) {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	fw := newFakeFW()
	return New(d, fw), d, fw
}

// tests ------------------------------------------------------------------

func TestGrantFromOrderAddsToFirewall(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	o := &models.Order{
		OrderNo:     "B-1",
		Mac:         "AA:BB:CC:DD:EE:FF",
		Plan:        "month",
		Days:        30,
		AmountCents: 100,
	}
	if err := svc.GrantFromOrder(ctx, o); err != nil {
		t.Fatal(err)
	}

	// DB row created
	m, err := dbx.GetMAC(ctx, o.Mac)
	if err != nil || m == nil {
		t.Fatalf("expected MAC row; err=%v", err)
	}
	if m.Label != "paid-month" {
		t.Errorf("label = %q", m.Label)
	}
	// Firewall set updated
	if !fw.set[o.Mac] {
		t.Error("mac not in firewall set")
	}
	if len(fw.addCalls) != 1 || fw.addCalls[0] != o.Mac {
		t.Errorf("addCalls = %+v", fw.addCalls)
	}
}

// A firewall Add failure must NOT fail the grant: the DB row is committed
// (source of truth) and the service falls back to a full Resync. Failing
// here used to 500 the payment webhook, whose retries then no-oped because
// the order was already paid — the customer stayed offline with no signal.
func TestGrantToleratesFirewallAddErrorViaResync(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	fw.addErr = errors.New("nft EBADF")
	err := svc.GrantFromOrder(context.Background(), &models.Order{
		OrderNo: "B-2", Mac: "11:22:33:44:55:66", Plan: "month", Days: 1,
	})
	if err != nil {
		t.Fatalf("fw add failure should not fail the grant; got %v", err)
	}
	// DB grant landed.
	if m, err := dbx.GetMAC(context.Background(), "11:22:33:44:55:66"); err != nil || m == nil {
		t.Fatalf("expected MAC row despite fw error; err=%v", err)
	}
	// Resync fallback ran and converged the set.
	if len(fw.syncCalls) != 1 {
		t.Errorf("expected 1 Resync fallback, got %d", len(fw.syncCalls))
	}
	if !fw.set["11:22:33:44:55:66"] {
		t.Error("mac should be in fw set after resync fallback")
	}
}

// If BOTH the Add and the fallback Resync fail, the grant still succeeds
// (DB is authoritative; convergence happens on the next resync) — but the
// upsert error path must still propagate.
func TestGrantStillSucceedsWhenResyncAlsoFails(t *testing.T) {
	svc, _, fw := newTestSvc(t)
	fw.addErr = errors.New("nft EBADF")
	fw.syncErr = errors.New("nft ENOENT")
	err := svc.GrantFromOrder(context.Background(), &models.Order{
		OrderNo: "B-3", Mac: "11:22:33:44:55:77", Plan: "month", Days: 1,
	})
	if err != nil {
		t.Fatalf("grant should survive fw+resync failure; got %v", err)
	}
}

func TestExtendAddsThenUpdatesFW(t *testing.T) {
	svc, _, fw := newTestSvc(t)
	ctx := context.Background()

	_, err := svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "manual", 30, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("mac not added to fw")
	}
	// Extend again — fw.Add should be called once more (idempotent on the fake).
	_, err = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fw.addCalls) != 2 {
		t.Errorf("expected 2 Add calls, got %d (%+v)", len(fw.addCalls), fw.addCalls)
	}
}

func TestDeleteRemovesFromBoth(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "x", 30, nil)
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Fatal("setup: fw missing")
	}
	if err := svc.Delete(ctx, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Fatal(err)
	}
	if fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("fw still has mac after Delete")
	}
	if m, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:FF"); m != nil {
		t.Error("db still has mac after Delete")
	}
}

func TestRevokeMarksBlockedAndRemoves(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "x", 30, nil)
	if err := svc.Revoke(ctx, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Fatal(err)
	}
	if fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("fw should not contain blocked mac")
	}
	m, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:FF")
	if m == nil || m.Status != models.MACBlocked {
		t.Errorf("expected status=blocked; got %+v", m)
	}
}

func TestReplaceTransfersFirewallEntry(t *testing.T) {
	svc, _, fw := newTestSvc(t)
	ctx := context.Background()

	// Create a user + grant them an old MAC
	dbx := svc.DB
	u, _ := dbx.CreateUser(ctx, "13800138000", "h")
	_, _ = svc.Extend(ctx, "11:22:33:44:55:66", "old-phone", 365, &u.ID)

	if _, err := svc.Replace(ctx, u.ID, "11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF", "new-phone"); err != nil {
		t.Fatal(err)
	}
	if fw.set["11:22:33:44:55:66"] {
		t.Error("old MAC should be out of fw set")
	}
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("new MAC should be in fw set")
	}
	if len(fw.removeCalls) < 1 || len(fw.addCalls) < 2 {
		t.Errorf("expected ≥1 Remove + ≥2 Add; got %d / %d", len(fw.removeCalls), len(fw.addCalls))
	}
}

func TestResyncMirrorsActiveMACs(t *testing.T) {
	svc, _, fw := newTestSvc(t)
	ctx := context.Background()

	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "a", 30, nil)
	_, _ = svc.Extend(ctx, "11:22:33:44:55:66", "b", 30, nil)
	// Manually drift the fw set (simulating a router reboot losing state).
	fw.mu.Lock()
	fw.set = map[string]bool{"DE:AD:BE:EF:00:00": true}
	fw.mu.Unlock()

	if err := svc.Resync(ctx); err != nil {
		t.Fatal(err)
	}
	if fw.set["DE:AD:BE:EF:00:00"] {
		t.Error("stale entry should be gone after Resync")
	}
	for _, want := range []string{"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"} {
		if !fw.set[want] {
			t.Errorf("missing %s after Resync", want)
		}
	}
	if got := len(fw.syncCalls); got != 1 {
		t.Errorf("Resync should call Sync once; got %d", got)
	}
}

// Resync must exclude MACs whose time-of-day schedule window is currently
// closed — otherwise a resync (boot / admin / periodic reconcile) would
// grant a schedule-blocked device access until the next EnforceSchedules
// tick removed it again.
func TestResyncRespectsSchedules(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "always-on", 30, nil)
	_, _ = svc.Extend(ctx, "11:22:33:44:55:66", "night-only", 30, nil)

	// Build a schedule whose window is provably CLOSED right now: allow
	// only a 1-minute slot starting 2 hours from now, today.
	now := time.Now()
	start := (now.Hour()*60 + now.Minute() + 120) % 1440
	wd := int(now.Weekday())
	if wd == 0 {
		wd = 7
	}
	closed := models.MacSchedule{Days: []int{wd}, StartMin: start, EndMin: (start + 1) % 1440}
	if closed.Active(now) {
		t.Fatal("test setup: schedule should be closed now")
	}
	if err := dbx.SetMACSchedule(ctx, "11:22:33:44:55:66", closed.JSON()); err != nil {
		t.Fatal(err)
	}

	if err := svc.Resync(ctx); err != nil {
		t.Fatal(err)
	}
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("unscheduled MAC missing after Resync")
	}
	if fw.set["11:22:33:44:55:66"] {
		t.Error("schedule-closed MAC must NOT be in fw set after Resync")
	}
}

func TestExpireDueRemovesFromFirewall(t *testing.T) {
	svc, _, fw := newTestSvc(t)
	ctx := context.Background()

	// Negative days → instantly expired.
	_, _ = svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "", -1, nil)
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Fatal("setup: should be in fw before expire")
	}
	// Wait a millisecond — current time must be past expiry.
	time.Sleep(2 * time.Millisecond)

	n, err := svc.ExpireDue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 expired; got %d", n)
	}
	if fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("expired MAC should be removed from fw")
	}
}
