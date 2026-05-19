package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSidebarBadgesAppearForAttention(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// Seed conditions that the Attention() query picks up:
	// - one expiring-soon MAC (≤7 days)
	// - one stale-pending order (>10 min old)
	// - one suspended user
	soon := time.Now().UTC().Add(48 * time.Hour)
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:16:01", "soon", 0, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = app.DB.Exec(ctx, `UPDATE macs SET expires_at = ? WHERE mac = ?`, soon, "AA:BB:CC:00:16:01")

	stale := time.Now().UTC().Add(-30 * time.Minute)
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('STALE-PEND', 'AA:BB:CC:00:16:02', 'm', 30, 100, 'pending', 'wechat', ?)`, stale)

	u, _ := app.DB.CreateUser(ctx, "13800250001", "h")
	_ = app.DB.SuspendUser(ctx, u.ID, true)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/dashboard", nil, jar)

	if !strings.Contains(body, "sidebar-badge") {
		t.Error("dashboard sidebar should render badges for attention items")
	}
	// Specific badges: macs (expiring), users (suspended), orders (stale)
	for _, want := range []string{
		"即将过期",       // MAC badge title
		"已停用账户",      // user badge title
		"滞留 pending", // order badge title text
	} {
		if !strings.Contains(body, want) {
			t.Errorf("badge title %q missing", want)
		}
	}
}

func TestSidebarBadgesAbsentWhenClean(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/dashboard", nil, jar)
	if strings.Contains(body, "sidebar-badge") {
		t.Error("badges should be hidden when attention counts are zero")
	}
}
