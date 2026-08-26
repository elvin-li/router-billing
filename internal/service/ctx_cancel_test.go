package service

import (
	"context"
	"testing"
	"time"
)

// v0.128: every mutating MACService entry point must survive its caller's
// context being canceled (the net/http server cancels r.Context() the
// moment the client disconnects). Before the detachCancel fix, a
// cancellation landing after the DB commit made the firewall half — AND
// the self-heal resync — fail on the dead context, leaving the kernel set
// contradicting the DB for up to a full scheduler interval (1h default):
// a replaced/revoked/deleted device stayed online, and Extend returned an
// error for a grant that actually landed (post-commit re-read failed),
// inviting the double-grant retry v0.126 closed for firewall failures.
//
// Passing an already-canceled context exercises the strictest version of
// the same property: the operation must still complete both halves.

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestExtendCompletesOnCanceledContext(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)

	m, err := svc.Extend(canceledCtx(), "AA:BB:CC:DD:EE:FF", "x", 30, nil)
	if err != nil {
		t.Fatalf("extend must not abort on a canceled caller context: %v", err)
	}
	if m == nil {
		t.Fatal("extend returned nil MAC")
	}
	if !fw.has("AA:BB:CC:DD:EE:FF") {
		t.Error("MAC missing from firewall set after extend with canceled ctx")
	}
	got, err := dbx.GetMAC(context.Background(), "AA:BB:CC:DD:EE:FF")
	if err != nil || got == nil {
		t.Fatalf("DB row missing after extend: %v", err)
	}
	if until := time.Until(got.ExpiresAt); until > 31*24*time.Hour || until < 29*24*time.Hour {
		t.Errorf("expected ~30 days of validity; got %v", until)
	}
}

func TestReplaceCompletesOnCanceledContext(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	u, err := dbx.CreateUser(ctx, "13800138000", "h")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Extend(ctx, "AA:BB:CC:DD:EE:01", "old", 30, &u.ID); err != nil {
		t.Fatal(err)
	}

	// Simulate the user dropping the connection right after POSTing
	// /user/macs/replace: DB transfer + old-MAC firewall removal + new-MAC
	// add must all still land, or the retired device keeps full access
	// (both devices online on one subscription until the next reconcile).
	if _, err := svc.Replace(canceledCtx(), u.ID, "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", ""); err != nil {
		t.Fatalf("replace must not abort on a canceled caller context: %v", err)
	}
	if fw.has("AA:BB:CC:DD:EE:01") {
		t.Error("old MAC still in firewall set — retired device kept access")
	}
	if !fw.has("AA:BB:CC:DD:EE:02") {
		t.Error("new MAC missing from firewall set")
	}
	if old, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:01"); old != nil {
		t.Error("old DB row should be gone")
	}
	if fresh, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:02"); fresh == nil {
		t.Error("new DB row should exist")
	}
}

func TestRevokeAndDeleteCompleteOnCanceledContext(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	for _, mac := range []string{"AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:04"} {
		if _, err := svc.Extend(ctx, mac, "x", 30, nil); err != nil {
			t.Fatal(err)
		}
	}

	if err := svc.Revoke(canceledCtx(), "AA:BB:CC:DD:EE:03"); err != nil {
		t.Fatalf("revoke must not abort on a canceled caller context: %v", err)
	}
	if fw.has("AA:BB:CC:DD:EE:03") {
		t.Error("revoked MAC still in firewall set")
	}
	if m, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:03"); m == nil || m.Status != "blocked" {
		t.Errorf("revoked row should be blocked; got %+v", m)
	}

	if err := svc.Delete(canceledCtx(), "AA:BB:CC:DD:EE:04"); err != nil {
		t.Fatalf("delete must not abort on a canceled caller context: %v", err)
	}
	if fw.has("AA:BB:CC:DD:EE:04") {
		t.Error("deleted MAC still in firewall set")
	}
	if m, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:04"); m != nil {
		t.Error("deleted row should be gone")
	}
}

func TestExpireDueCompletesOnCanceledContext(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	if _, err := svc.Extend(ctx, "AA:BB:CC:DD:EE:05", "x", 30, nil); err != nil {
		t.Fatal(err)
	}
	// Force the row into the past so the sweep picks it up.
	if _, err := dbx.Exec(ctx,
		`UPDATE macs SET expires_at = datetime('now', '-1 hour') WHERE mac = ?`,
		"AA:BB:CC:DD:EE:05"); err != nil {
		t.Fatal(err)
	}

	n, err := svc.ExpireDue(canceledCtx())
	if err != nil {
		t.Fatalf("expire sweep must not abort on a canceled caller context: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 expired MAC, got %d", n)
	}
	if fw.has("AA:BB:CC:DD:EE:05") {
		t.Error("expired MAC still in firewall set")
	}
}
