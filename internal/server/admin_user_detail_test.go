package server

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
)

func TestAdminUserDetailRendersFullProfile(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// Seed a user with a MAC + paid order + active session.
	u, _ := app.DB.CreateUser(ctx, "13800140000", "h")
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:F0", "phone", 30, &u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('ORD-DETAIL-1', 'AA:BB:CC:DD:EE:F0', 'month', 30, 100, 'paid', 'wechat', ?, ?, ?)`,
		u.ID, time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.CreateSession(ctx, "tok-detail-1", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	app.DB.Audit(ctx, "user:"+u.Phone, "login", "", "ip=10.0.0.99")

	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/users/detail?id="+strconv.FormatInt(u.ID, 10), nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	for _, want := range []string{
		"13800140000",       // phone
		"AA:BB:CC:DD:EE:F0", // MAC
		"ORD-DETAIL-1",      // order
		"tok-deta",          // session token prefix (slice 0:8 = "tok-deta")
		"10.0.0.99",         // IP from audit
		"最近 30 条审计",
		"活动会话",
		"MAC (",
		"订单 (",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestAdminUserDetailShowsTOTPStateAndBackupRemaining(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800140001", "h")
	_ = app.DB.SetUserTOTPPending(ctx, u.ID, "JBSWY3DPEHPK3PXP")
	_ = app.DB.ConfirmUserTOTP(ctx, u.ID)
	// Seed 8 unused backup codes (out of 10).
	hashes := []string{}
	for i := 0; i < 8; i++ {
		hashes = append(hashes, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfakehash")
	}
	if err := app.DB.ReplaceBackupCodes(ctx, u.ID, hashes); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/users/detail?id="+strconv.FormatInt(u.ID, 10), nil, jar)
	if !strings.Contains(body, "2FA 已开启") {
		t.Error("page should show 2FA enabled pill")
	}
	if !strings.Contains(body, "备用码剩 8/10") {
		t.Errorf("expected '备用码剩 8/10' in body; got: %s", truncate(body, 800))
	}
	if !strings.Contains(body, "重置 2FA") {
		t.Error("reset 2FA button should be visible for enrolled user")
	}
}

func TestAdminUserDetailMissingIDRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/users/detail", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("missing id: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "/admin/users") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}
}

func TestAdminUserDetailNonexistentUserRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/users/detail?id=99999", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("nonexistent: %d", res.StatusCode)
	}
}

func TestAdminUserDetailListsTrustedDevicesWhenEnrolled(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800140002", "h")
	_ = app.DB.SetUserTOTPPending(ctx, u.ID, "JBSWY3DPEHPK3PXP")
	_ = app.DB.ConfirmUserTOTP(ctx, u.ID)
	if _, err := app.DB.CreateTrustedDevice(ctx, u.ID, "tok-trusted-1", "Safari/iPhone", time.Hour); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/users/detail?id="+strconv.FormatInt(u.ID, 10), nil, jar)
	if !strings.Contains(body, "受信任设备") {
		t.Error("page should have 受信任设备 section for enrolled user with devices")
	}
	if !strings.Contains(body, "Safari/iPhone") {
		t.Errorf("device label missing: %s", truncate(body, 800))
	}
}

func TestAdminUsersListLinksToDetail(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800140003", "h")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/users", nil, jar)
	if !strings.Contains(body, "/admin/users/detail?id="+strconv.FormatInt(u.ID, 10)) {
		t.Errorf("users list should link to detail page; body=%s", truncate(body, 800))
	}
}

func TestListSessionsForUserOnlyReturnsLiveUserSessions(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800140004", "h")
	// 1 live user session.
	if err := app.DB.CreateSession(ctx, "tok-live", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	// 1 expired user session — patch expires_at into the past.
	if err := app.DB.CreateSession(ctx, "tok-stale", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(ctx, `UPDATE sessions SET expires_at = ? WHERE token = 'tok-stale'`,
		time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	// 1 admin session that happens to also have a user_id (shouldn't surface).
	if err := app.DB.CreateSession(ctx, "tok-admin", "admin", "admin", &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}

	sessions, err := app.DB.ListSessionsForUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 live user session; got %d (%+v)", len(sessions), sessions)
	}
	if sessions[0].Token != "tok-live" {
		t.Errorf("wrong session returned: %s", sessions[0].Token)
	}
}

// silence unused — placeholder so future detail-page tests can grow the file
// without adding imports.
var _ = models.MACActive
var _ = url.Values{}
