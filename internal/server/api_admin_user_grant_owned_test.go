package server

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"router-billing/internal/config"
)

// Regression (v0.106): the user-grant fan-outs (/api/admin/users/grant and
// /api/admin/users/grant-by-phone) listed a user's MACs and then extended
// each via the unconditional UpsertMAC path, which OVERWRITES user_id. A
// device transferred to a different user between the list and the write
// was silently reassigned back to the granted user. ExtendOwned guards the
// update with WHERE user_id = ?, so a stale row is skipped, never stolen.
func TestExtendOwnedSkipsTransferredMAC(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	userA, _ := app.DB.CreateUser(ctx, "13800130001", "h")
	userB, _ := app.DB.CreateUser(ctx, "13800130002", "h")
	// MAC currently owned by B (simulates the transfer landing between
	// the handler's ListMACsForUser(A) and its per-MAC write).
	before, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:30:01", "tv", 30, &userB.ID)
	if err != nil {
		t.Fatal(err)
	}

	m, err := app.MACSvc.ExtendOwned(ctx, "AA:BB:CC:00:30:01", "steal-attempt", 365, userA.ID)
	if err != nil {
		t.Fatalf("ExtendOwned: %v", err)
	}
	if m != nil {
		t.Fatalf("ExtendOwned must skip a MAC owned by another user; got %+v", m)
	}

	after, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:30:01")
	if after.UserID == nil || *after.UserID != userB.ID {
		t.Errorf("ownership must stay with user B; got %v", after.UserID)
	}
	if !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Errorf("expiry must be unchanged; before=%v after=%v", before.ExpiresAt, after.ExpiresAt)
	}
	if after.Label != "tv" {
		t.Errorf("label must be unchanged; got %q", after.Label)
	}
}

func TestExtendOwnedSkipsUnownedMAC(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	userA, _ := app.DB.CreateUser(ctx, "13800130003", "h")
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:30:02", "orphan", 30, nil); err != nil {
		t.Fatal(err)
	}
	m, err := app.MACSvc.ExtendOwned(ctx, "AA:BB:CC:00:30:02", "", 7, userA.ID)
	if err != nil {
		t.Fatalf("ExtendOwned: %v", err)
	}
	if m != nil {
		t.Errorf("ExtendOwned must skip a MAC with no owner; got %+v", m)
	}
	after, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:30:02")
	if after.UserID != nil {
		t.Errorf("unowned MAC must stay unowned; got %v", *after.UserID)
	}
}

func TestExtendOwnedExtendsMatchingOwner(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	userA, _ := app.DB.CreateUser(ctx, "13800130004", "h")
	before, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:30:03", "phone", 30, &userA.ID)
	if err != nil {
		t.Fatal(err)
	}
	m, err := app.MACSvc.ExtendOwned(ctx, "AA:BB:CC:00:30:03", "support-extend", 7, userA.ID)
	if err != nil {
		t.Fatalf("ExtendOwned: %v", err)
	}
	if m == nil {
		t.Fatal("matching owner must extend")
	}
	if !m.ExpiresAt.After(before.ExpiresAt) {
		t.Errorf("expiry must grow; before=%v after=%v", before.ExpiresAt, m.ExpiresAt)
	}
	if m.UserID == nil || *m.UserID != userA.ID {
		t.Errorf("ownership must stay with user A; got %v", m.UserID)
	}
	if m.Label != "support-extend" {
		t.Errorf("non-empty label should be applied; got %q", m.Label)
	}
}

// End-to-end sanity: the grant fan-out still extends every MAC the user
// owns and reports the correct count after the ExtendOwned switch.
func TestAPIUserGrantByPhoneStillExtendsOwnMACs(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800130005", "h")
	other, _ := app.DB.CreateUser(ctx, "13800130006", "h")
	for _, m := range []string{"AA:BB:CC:00:30:04", "AA:BB:CC:00:30:05"} {
		if _, err := app.DB.UpsertMAC(ctx, m, "mine", 30, &u.ID); err != nil {
			t.Fatal(err)
		}
	}
	otherBefore, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:30:06", "theirs", 30, &other.ID)
	if err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant-by-phone", "rb_w",
		`{"phone":"13800130005","days":7}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		UserID       int64 `json:"user_id"`
		MACsExtended int   `json:"macs_extended"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.UserID != u.ID || resp.MACsExtended != 2 {
		t.Errorf("expected user %s with 2 MACs extended; got %+v",
			strconv.FormatInt(u.ID, 10), resp)
	}

	// The other user's device is untouched.
	otherAfter, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:30:06")
	if otherAfter.UserID == nil || *otherAfter.UserID != other.ID {
		t.Errorf("other user's MAC ownership changed: %v", otherAfter.UserID)
	}
	if !otherAfter.ExpiresAt.Equal(otherBefore.ExpiresAt) {
		t.Errorf("other user's MAC expiry changed: before=%v after=%v",
			otherBefore.ExpiresAt, otherAfter.ExpiresAt)
	}
}
