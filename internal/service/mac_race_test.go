package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"router-billing/internal/db"
	"router-billing/internal/models"
)

// These tests pin the v0.110 service-level serialization: every composite
// (DB + firewall) operation must be atomic relative to the others. Each
// test freezes one actor INSIDE its firewall call via a one-shot gate,
// runs a conflicting actor, and asserts the final firewall membership
// matches the DB. Without MACService.mu each scenario ends with the
// firewall contradicting the DB until the next resync.

// fwGate is a one-shot rendezvous: the first goroutine that calls pass()
// signals `entered` and blocks until `release` is closed. Later callers
// (and a nil gate) pass straight through.
type fwGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newFWGate() *fwGate {
	return &fwGate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *fwGate) pass() {
	if g == nil {
		return
	}
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})
}

// gatedFW wraps fakeFW so tests can freeze an actor at the entrance of a
// specific firewall operation (before the fake mutates its state).
type gatedFW struct {
	*fakeFW
	syncGate   *fwGate
	addGate    *fwGate
	removeGate *fwGate
}

func (g *gatedFW) Sync(ctx context.Context, macs []string) error {
	g.syncGate.pass()
	return g.fakeFW.Sync(ctx, macs)
}

func (g *gatedFW) Add(ctx context.Context, mac string) error {
	g.addGate.pass()
	return g.fakeFW.Add(ctx, mac)
}

func (g *gatedFW) Remove(ctx context.Context, mac string) error {
	g.removeGate.pass()
	return g.fakeFW.Remove(ctx, mac)
}

// has reads the fake's set under its lock.
func (f *fakeFW) has(mac string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.set[mac]
}

func newGatedSvc(t *testing.T) (*MACService, *db.DB, *gatedFW) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	g := &gatedFW{fakeFW: newFakeFW()}
	return New(d, g), d, g
}

// A grant landing while a resync is between its DB read and its full set
// rebuild must not be flushed out of the firewall: the paying customer
// would stay offline until the NEXT resync (potentially hours).
func TestResyncDoesNotDropConcurrentGrant(t *testing.T) {
	svc, _, g := newGatedSvc(t)
	ctx := context.Background()

	if _, err := svc.Extend(ctx, "AA:BB:CC:DD:EE:01", "seed", 30, nil); err != nil {
		t.Fatal(err)
	}
	g.syncGate = newFWGate()

	resyncDone := make(chan struct{})
	go func() {
		defer close(resyncDone)
		_ = svc.Resync(ctx)
	}()
	<-g.syncGate.entered // resync has read the active list, is inside FW.Sync

	grantDone := make(chan struct{})
	go func() {
		defer close(grantDone)
		_ = svc.GrantFromOrder(ctx, &models.Order{
			OrderNo: "B-race-1", Mac: "AA:BB:CC:DD:EE:02", Plan: "month", Days: 30,
		})
	}()

	// Give the grant time to (wrongly) slip in between the resync's DB
	// read and its rebuild. With the service lock it blocks instead.
	time.Sleep(150 * time.Millisecond)
	close(g.syncGate.release)
	<-resyncDone
	<-grantDone

	if !g.has("AA:BB:CC:DD:EE:02") {
		t.Error("freshly granted MAC was flushed from the firewall set by a concurrent resync")
	}
	if !g.has("AA:BB:CC:DD:EE:01") {
		t.Error("pre-existing active MAC should survive the resync")
	}
}

// A payment that re-activates a MAC while the expiry sweep is between its
// DB flip and its firewall removals must not have its firewall entry
// yanked by the sweep.
func TestExpireSweepDoesNotRemoveConcurrentGrant(t *testing.T) {
	svc, dbx, g := newGatedSvc(t)
	ctx := context.Background()
	const mac = "AA:BB:CC:DD:EE:03"

	// Active row whose expiry is already in the past → due for the sweep.
	if _, err := svc.Extend(ctx, mac, "x", -1, nil); err != nil {
		t.Fatal(err)
	}
	g.removeGate = newFWGate()

	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		_, _ = svc.ExpireDue(ctx)
	}()
	<-g.removeGate.entered // rows flipped to expired; sweep mid-Remove

	grantDone := make(chan struct{})
	go func() {
		defer close(grantDone)
		_ = svc.GrantFromOrder(ctx, &models.Order{
			OrderNo: "B-race-2", Mac: mac, Plan: "month", Days: 30,
		})
	}()

	time.Sleep(150 * time.Millisecond)
	close(g.removeGate.release)
	<-sweepDone
	<-grantDone

	if !g.has(mac) {
		t.Error("MAC paid during the expiry sweep was yanked from the firewall")
	}
	m, err := dbx.GetMAC(ctx, mac)
	if err != nil || m == nil || m.Status != models.MACActive {
		t.Errorf("DB row should be active after the grant; got %+v (err=%v)", m, err)
	}
}

// The minute schedule enforcer must not re-add a MAC that a concurrent
// admin Revoke just blocked and removed.
func TestScheduleEnforceDoesNotResurrectConcurrentRevoke(t *testing.T) {
	svc, dbx, g := newGatedSvc(t)
	ctx := context.Background()
	const mac = "AA:BB:CC:DD:EE:04"

	if _, err := svc.Extend(ctx, mac, "kid-tablet", 30, nil); err != nil {
		t.Fatal(err)
	}
	if err := dbx.SetMACSchedule(ctx, mac, scheduleJSONAround(t, time.Now(), true)); err != nil {
		t.Fatal(err)
	}
	g.addGate = newFWGate()

	enforceDone := make(chan struct{})
	go func() {
		defer close(enforceDone)
		svc.enforceSchedulesOnce(ctx)
	}()
	<-g.addGate.entered // enforcer listed active MACs, mid in-window Add

	revokeDone := make(chan struct{})
	go func() {
		defer close(revokeDone)
		_ = svc.Revoke(ctx, mac)
	}()

	time.Sleep(150 * time.Millisecond)
	close(g.addGate.release)
	<-enforceDone
	<-revokeDone

	if g.has(mac) {
		t.Error("revoked MAC was re-added to the firewall by the concurrent schedule enforcer")
	}
	m, _ := dbx.GetMAC(ctx, mac)
	if m == nil || m.Status != models.MACBlocked {
		t.Errorf("DB row should be blocked; got %+v", m)
	}
}

// ApplyScheduleNow behavior: eligibility is re-checked under the lock and
// ineligible rows are defensively removed, never added.
func TestApplyScheduleNowRespectsEligibility(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	const mac = "AA:BB:CC:DD:EE:05"

	if _, err := svc.Extend(ctx, mac, "x", 30, nil); err != nil {
		t.Fatal(err)
	}

	// Empty schedule (restriction cleared) on an eligible MAC → added.
	fw.mu.Lock()
	fw.set = map[string]bool{}
	fw.mu.Unlock()
	if err := svc.ApplyScheduleNow(ctx, mac, models.MacSchedule{}); err != nil {
		t.Fatal(err)
	}
	if !fw.has(mac) {
		t.Error("eligible MAC with no restriction should be added back")
	}

	// Eligible but out-of-window → removed.
	var outOfWindow models.MacSchedule
	if err := json.Unmarshal([]byte(scheduleJSONAround(t, time.Now(), false)), &outOfWindow); err != nil {
		t.Fatal(err)
	}
	if err := svc.ApplyScheduleNow(ctx, mac, outOfWindow); err != nil {
		t.Fatal(err)
	}
	if fw.has(mac) {
		t.Error("out-of-window MAC should be removed")
	}

	// Blocked → removed even when the schedule window is open.
	if err := dbx.SetMACStatus(ctx, mac, models.MACBlocked); err != nil {
		t.Fatal(err)
	}
	var inWindow models.MacSchedule
	if err := json.Unmarshal([]byte(scheduleJSONAround(t, time.Now(), true)), &inWindow); err != nil {
		t.Fatal(err)
	}
	if err := svc.ApplyScheduleNow(ctx, mac, inWindow); err != nil {
		t.Fatal(err)
	}
	if fw.has(mac) {
		t.Error("blocked MAC must never be added by a schedule apply")
	}
}
