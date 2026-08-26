package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"router-billing/internal/models"
)

// The grant/extend paths must respect a MAC's time-of-day schedule: paying
// for (or extending) a device whose window is currently CLOSED must not put
// it online until the window opens. Pre-v0.119 every grant path called
// FW.Add unconditionally, granting up to a minute of out-of-window access
// per grant (until the next EnforceSchedules tick) — the same class v0.108
// fixed for Resync.

func TestGrantFromOrderRespectsClosedSchedule(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()

	mac := "AA:BB:CC:DD:EE:F1"
	_, _ = svc.Extend(ctx, mac, "kid-tablet", 30, nil)
	if err := dbx.SetMACSchedule(ctx, mac, scheduleJSONAround(t, now, false)); err != nil {
		t.Fatal(err)
	}
	// Enforcer has already taken it out of the set for the closed window.
	svc.enforceSchedulesOnce(ctx)
	if fw.set[mac] {
		t.Fatal("setup: enforcer should have removed the out-of-window MAC")
	}
	addsBefore := len(fw.addCalls)

	err := svc.GrantFromOrder(ctx, &models.Order{
		OrderNo: "B-sched-1", Mac: mac, Plan: "month", Days: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fw.set[mac] {
		t.Error("schedule-closed MAC must not enter the firewall set on grant")
	}
	if len(fw.addCalls) != addsBefore {
		t.Errorf("no FW.Add expected for a closed window; got %+v", fw.addCalls[addsBefore:])
	}
	// The DB grant itself must land (days added, still active).
	m, _ := dbx.GetMAC(ctx, mac)
	if m == nil || m.Status != models.MACActive {
		t.Fatalf("grant should still extend the DB row; got %+v", m)
	}
}

func TestGrantFromOrderAddsWhenScheduleOpen(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()

	mac := "AA:BB:CC:DD:EE:F2"
	_, _ = svc.Extend(ctx, mac, "x", 30, nil)
	if err := dbx.SetMACSchedule(ctx, mac, scheduleJSONAround(t, now, true)); err != nil {
		t.Fatal(err)
	}
	fw.mu.Lock()
	fw.set = map[string]bool{}
	fw.mu.Unlock()

	if err := svc.GrantFromOrder(ctx, &models.Order{
		OrderNo: "B-sched-2", Mac: mac, Plan: "month", Days: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if !fw.set[mac] {
		t.Error("in-window MAC should be added on grant")
	}
}

func TestGrantFromVoucherRespectsClosedSchedule(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()

	mac := "AA:BB:CC:DD:EE:F3"
	_, _ = svc.Extend(ctx, mac, "x", 30, nil)
	_ = dbx.SetMACSchedule(ctx, mac, scheduleJSONAround(t, now, false))
	svc.enforceSchedulesOnce(ctx)

	if _, err := svc.GrantFromVoucher(ctx, mac, "voucher", 7, nil); err != nil {
		t.Fatal(err)
	}
	if fw.set[mac] {
		t.Error("schedule-closed MAC must not enter the firewall set on voucher grant")
	}
}

func TestExtendRespectsClosedSchedule(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()

	mac := "AA:BB:CC:DD:EE:F4"
	_, _ = svc.Extend(ctx, mac, "x", 30, nil)
	_ = dbx.SetMACSchedule(ctx, mac, scheduleJSONAround(t, now, false))
	svc.enforceSchedulesOnce(ctx)

	m, err := svc.Extend(ctx, mac, "", 10, nil)
	if err != nil || m == nil {
		t.Fatalf("extend should succeed; m=%v err=%v", m, err)
	}
	if fw.set[mac] {
		t.Error("schedule-closed MAC must not re-enter the firewall set on admin extend")
	}
}

func TestExtendOwnedRespectsClosedSchedule(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()
	now := time.Now()

	u, err := dbx.CreateUser(ctx, "13800138001", "h")
	if err != nil {
		t.Fatal(err)
	}
	mac := "AA:BB:CC:DD:EE:F5"
	_, _ = svc.Extend(ctx, mac, "x", 30, &u.ID)
	_ = dbx.SetMACSchedule(ctx, mac, scheduleJSONAround(t, now, false))
	svc.enforceSchedulesOnce(ctx)

	m, err := svc.ExtendOwned(ctx, mac, "", 10, u.ID)
	if err != nil || m == nil {
		t.Fatalf("extend-owned should succeed; m=%v err=%v", m, err)
	}
	if fw.set[mac] {
		t.Error("schedule-closed MAC must not re-enter the firewall set on user grant fan-out")
	}
}

// A corrupt schedule must fail OPEN on grant (matching EnforceSchedules and
// Resync) — a bad row must never lock a paying customer out.
func TestGrantFailsOpenOnCorruptSchedule(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	mac := "AA:BB:CC:DD:EE:F6"
	_, _ = svc.Extend(ctx, mac, "x", 30, nil)
	_ = dbx.SetMACSchedule(ctx, mac, "{not json")
	fw.mu.Lock()
	fw.set = map[string]bool{}
	fw.mu.Unlock()

	if err := svc.GrantFromOrder(ctx, &models.Order{
		OrderNo: "B-sched-3", Mac: mac, Plan: "month", Days: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if !fw.set[mac] {
		t.Error("corrupt schedule must fail open — MAC should be added")
	}
}

// --- rule leak after revoke: Remove failures must self-heal via resync ---

func TestRevokeSelfHealsViaResyncWhenRemoveFails(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	mac := "AA:BB:CC:DD:EE:E1"
	_, _ = svc.Extend(ctx, mac, "x", 30, nil)
	fw.rmErr = errors.New("nft: netlink timeout")

	if err := svc.Revoke(ctx, mac); err != nil {
		t.Fatalf("revoke should succeed via the resync fallback; got %v", err)
	}
	// DB is blocked and the resync (rebuild from active MACs) flushed the
	// device out of the kernel set despite the failed direct Remove.
	m, _ := dbx.GetMAC(ctx, mac)
	if m == nil || m.Status != models.MACBlocked {
		t.Fatalf("expected blocked row; got %+v", m)
	}
	if fw.set[mac] {
		t.Error("revoked MAC must not survive in the firewall set (rule leak)")
	}
	if len(fw.syncCalls) != 1 {
		t.Errorf("expected exactly one resync fallback; got %d", len(fw.syncCalls))
	}
}

func TestRevokeReturnsErrorWhenRemoveAndResyncFail(t *testing.T) {
	svc, _, fw := newTestSvc(t)
	ctx := context.Background()

	mac := "AA:BB:CC:DD:EE:E2"
	_, _ = svc.Extend(ctx, mac, "x", 30, nil)
	fw.rmErr = errors.New("nft: netlink timeout")
	fw.syncErr = errors.New("nft: still down")

	if err := svc.Revoke(ctx, mac); err == nil {
		t.Error("when both Remove and the resync fallback fail, the caller must see an error")
	}
}

func TestDeleteSelfHealsViaResyncWhenRemoveFails(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	mac := "AA:BB:CC:DD:EE:E3"
	_, _ = svc.Extend(ctx, mac, "x", 30, nil)
	fw.rmErr = errors.New("nft: netlink timeout")

	if err := svc.Delete(ctx, mac); err != nil {
		t.Fatalf("delete should succeed via the resync fallback; got %v", err)
	}
	if m, _ := dbx.GetMAC(ctx, mac); m != nil {
		t.Fatalf("row should be gone; got %+v", m)
	}
	if fw.set[mac] {
		t.Error("deleted MAC must not survive in the firewall set")
	}
}

func TestExpireDueSelfHealsViaResyncWhenRemoveFails(t *testing.T) {
	svc, _, fw := newTestSvc(t)
	ctx := context.Background()

	mac := "AA:BB:CC:DD:EE:E4"
	_, _ = svc.Extend(ctx, mac, "x", -1, nil) // instantly expired
	time.Sleep(2 * time.Millisecond)
	fw.rmErr = errors.New("nft: netlink timeout")

	n, err := svc.ExpireDue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired; got %d", n)
	}
	if fw.set[mac] {
		t.Error("expired MAC must not survive in the firewall set after the resync fallback")
	}
	if len(fw.syncCalls) != 1 {
		t.Errorf("expected exactly one resync fallback; got %d", len(fw.syncCalls))
	}
}
