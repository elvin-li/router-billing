package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
)

// The claim path must be atomic: eligibility (active, unexpired, unowned or
// self-owned) is enforced inside ClaimMAC's WHERE clause, not by a separate
// GetMAC check. These tests pin the semantics the old check-then-UpsertMAC
// sequence violated under concurrency.

// mkUser creates a real users row (macs.user_id is a foreign key) and
// returns its id.
func mkUser(t *testing.T, app *App, phone string) int64 {
	t.Helper()
	u, err := app.DB.CreateUser(context.Background(), phone, "x")
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestClaimMACTakesUnownedActiveMAC(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	mac := "AA:BB:CC:00:11:22"
	if _, err := app.DB.UpsertMAC(ctx, mac, "walk-in", 30, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := app.DB.GetMAC(ctx, mac)

	uid := mkUser(t, app, "13800152010")
	claimed, err := app.DB.ClaimMAC(ctx, mac, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatal("claim of unowned active MAC should succeed")
	}
	after, _ := app.DB.GetMAC(ctx, mac)
	if after.UserID == nil || *after.UserID != uid {
		t.Errorf("user_id = %v, want %d", after.UserID, uid)
	}
	// A claim is pure ownership transfer — status/expiry/label untouched.
	if after.Status != models.MACActive {
		t.Errorf("status = %s, want active", after.Status)
	}
	if !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Errorf("expires_at changed: %s -> %s", before.ExpiresAt, after.ExpiresAt)
	}
	if after.Label != "walk-in" {
		t.Errorf("label changed: %q", after.Label)
	}
}

func TestClaimMACIdempotentForSameOwner(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	mac := "AA:BB:CC:00:11:33"
	uid := mkUser(t, app, "13800152011")
	if _, err := app.DB.UpsertMAC(ctx, mac, "", 30, &uid); err != nil {
		t.Fatal(err)
	}
	claimed, err := app.DB.ClaimMAC(ctx, mac, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Error("re-claim by the current owner should succeed (no-op)")
	}
}

func TestClaimMACRefusesOtherUsersMAC(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	mac := "AA:BB:CC:00:11:44"
	owner := mkUser(t, app, "13800152012")
	thief := mkUser(t, app, "13800152013")
	if _, err := app.DB.UpsertMAC(ctx, mac, "", 30, &owner); err != nil {
		t.Fatal(err)
	}
	claimed, err := app.DB.ClaimMAC(ctx, mac, thief)
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("claim must not steal a MAC owned by another user")
	}
	m, _ := app.DB.GetMAC(ctx, mac)
	if m.UserID == nil || *m.UserID != owner {
		t.Errorf("ownership changed to %v", m.UserID)
	}
}

func TestClaimMACNeverResurrectsBlockedMAC(t *testing.T) {
	// The old path called UpsertMAC, whose UPDATE branch stamps
	// status='active' — so a claim racing an admin Revoke flipped the
	// blocked row back to active and the next resync re-opened the
	// firewall for it. ClaimMAC must refuse and leave the row blocked.
	app := setupTestApp(t)
	ctx := context.Background()
	mac := "AA:BB:CC:00:11:55"
	if _, err := app.DB.UpsertMAC(ctx, mac, "", 30, nil); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.SetMACStatus(ctx, mac, models.MACBlocked); err != nil {
		t.Fatal(err)
	}
	claimed, err := app.DB.ClaimMAC(ctx, mac, mkUser(t, app, "13800152014"))
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("claim of a blocked MAC must fail")
	}
	m, _ := app.DB.GetMAC(ctx, mac)
	if m.Status != models.MACBlocked {
		t.Errorf("status = %s, want blocked (claim must not resurrect)", m.Status)
	}
	if m.UserID != nil {
		t.Errorf("blocked MAC gained an owner: %v", *m.UserID)
	}
}

func TestClaimMACRefusesExpired(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	mac := "AA:BB:CC:00:11:66"
	if _, err := app.DB.UpsertMAC(ctx, mac, "", 30, nil); err != nil {
		t.Fatal(err)
	}
	// Force expires_at into the past while status stays 'active' —
	// the pre-ExpireDue window.
	if _, err := app.DB.Exec(ctx,
		`UPDATE macs SET expires_at = ? WHERE mac = ?`,
		time.Now().UTC().Add(-time.Hour), mac); err != nil {
		t.Fatal(err)
	}
	claimed, err := app.DB.ClaimMAC(ctx, mac, mkUser(t, app, "13800152015"))
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("claim of an expired MAC must fail")
	}
}

func TestSetMACLabelOwnedGuardsOwnership(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	mac := "AA:BB:CC:00:11:77"
	owner := mkUser(t, app, "13800152016")
	stranger := mkUser(t, app, "13800152017")
	if _, err := app.DB.UpsertMAC(ctx, mac, "orig", 30, &owner); err != nil {
		t.Fatal(err)
	}
	// Wrong owner: no write.
	ok, err := app.DB.SetMACLabelOwned(ctx, mac, "hijack", stranger)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("rename by non-owner should be refused")
	}
	m, _ := app.DB.GetMAC(ctx, mac)
	if m.Label != "orig" {
		t.Errorf("label = %q, want orig", m.Label)
	}
	// Right owner: write lands.
	ok, err = app.DB.SetMACLabelOwned(ctx, mac, "mine", owner)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("rename by owner should succeed")
	}
	m, _ = app.DB.GetMAC(ctx, mac)
	if m.Label != "mine" {
		t.Errorf("label = %q, want mine", m.Label)
	}
}

func TestUserLabelMACHandlerRefusesForeignMAC(t *testing.T) {
	// End-to-end: a logged-in user posting /user/macs/label for a MAC that
	// belongs to someone else gets bounced with replace_failed and the
	// label is untouched.
	app := setupTestApp(t)
	h := app.Routes()
	ctx := context.Background()

	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800152001"}, "password": {"claim-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register: %d", res.StatusCode)
	}
	jar := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/me", nil, jar)
	for k, v := range cookieJar(res2) {
		jar[k] = v
	}
	csrf := jar[csrfCookieName]

	// A second real user owns the MAC (macs.user_id is a foreign key).
	otherUser, err := app.DB.CreateUser(ctx, "13800152002", "x")
	if err != nil {
		t.Fatal(err)
	}
	mac := "AA:BB:CC:00:11:88"
	if _, err := app.DB.UpsertMAC(ctx, mac, "theirs", 30, &otherUser.ID); err != nil {
		t.Fatal(err)
	}

	res3, _ := do(t, h, "POST", "/user/macs/label",
		url.Values{"_csrf": {csrf}, "mac": {mac}, "label": {"stolen"}}, jar)
	if res3.StatusCode != 303 {
		t.Fatalf("label post: %d", res3.StatusCode)
	}
	if loc := res3.Header.Get("Location"); !strings.Contains(loc, "err=replace_failed") {
		t.Errorf("expected replace_failed redirect, got %s", loc)
	}
	m, _ := app.DB.GetMAC(ctx, mac)
	if m.Label != "theirs" {
		t.Errorf("label = %q, want theirs", m.Label)
	}
}
