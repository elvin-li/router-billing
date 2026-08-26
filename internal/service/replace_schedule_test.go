package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"router-billing/internal/models"
)

// closedScheduleNow builds a schedule whose window is provably CLOSED at
// the current moment (a 1-minute slot 2 hours from now, today).
func closedScheduleNow(t *testing.T) models.MacSchedule {
	t.Helper()
	now := time.Now()
	start := (now.Hour()*60 + now.Minute() + 120) % 1440
	wd := int(now.Weekday())
	if wd == 0 {
		wd = 7
	}
	s := models.MacSchedule{Days: []int{wd}, StartMin: start, EndMin: (start + 1) % 1440}
	if s.Active(now) {
		t.Fatal("test setup: schedule should be closed now")
	}
	return s
}

// v0.125: ReplaceMAC dropped schedule_json and notes — a user could shed an
// admin-imposed time-of-day restriction just by replacing the device with a
// fresh randomized MAC via self-service /user/macs/replace.
func TestReplaceCarriesScheduleAndNotes(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	u, _ := dbx.CreateUser(ctx, "13800138000", "h")
	_, _ = svc.Extend(ctx, "11:22:33:44:55:66", "kid-phone", 365, &u.ID)

	closed := closedScheduleNow(t)
	if err := dbx.SetMACSchedule(ctx, "11:22:33:44:55:66", closed.JSON()); err != nil {
		t.Fatal(err)
	}
	if err := dbx.SetMACNotes(ctx, "11:22:33:44:55:66", "curfew per parent request"); err != nil {
		t.Fatal(err)
	}
	// Enforce once so the closed window has taken the old MAC offline.
	svc.enforceSchedulesOnce(ctx)
	if fw.set["11:22:33:44:55:66"] {
		t.Fatal("setup: schedule-closed MAC should be out of the fw set")
	}

	m, err := svc.Replace(ctx, u.ID, "11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF", "")
	if err != nil {
		t.Fatal(err)
	}
	if m.ScheduleJSON == "" {
		t.Error("schedule_json must transfer to the replacement MAC")
	}
	if m.Notes != "curfew per parent request" {
		t.Errorf("notes must transfer to the replacement MAC; got %q", m.Notes)
	}
	// The inherited window is closed — the new MAC must NOT be online.
	if fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("replacement MAC must not be added to the firewall while its inherited schedule window is closed")
	}
}

// v0.125: a transient FW failure during Replace must self-heal via resync
// (the DB already committed) instead of surfacing "replace failed" while
// leaving the kernel set stale.
func TestReplaceSelfHealsOnFirewallFailure(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	u, _ := dbx.CreateUser(ctx, "13800138000", "h")
	_, _ = svc.Extend(ctx, "11:22:33:44:55:66", "old", 365, &u.ID)

	fw.mu.Lock()
	fw.addErr = errors.New("nft timeout")
	fw.rmErr = errors.New("nft timeout")
	fw.mu.Unlock()

	if _, err := svc.Replace(ctx, u.ID, "11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF", ""); err != nil {
		t.Fatalf("replace must succeed once the DB committed (self-heal path); got %v", err)
	}
	// Sync (resync fallback) is not gated on addErr/rmErr in the fake, so
	// the end state must have converged to the DB truth.
	if fw.set["11:22:33:44:55:66"] {
		t.Error("old MAC should be gone after the resync fallback")
	}
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("new MAC should be present after the resync fallback")
	}
}
