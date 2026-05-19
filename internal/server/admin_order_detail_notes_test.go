package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

// /admin/orders/detail should surface the linked MAC's notes so support
// sees customer context as soon as they open an order.
func TestAdminOrderDetailShowsMACNotes(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:29:01", "phone", 30, nil)
	_ = app.DB.SetMACNotes(ctx, "AA:BB:CC:00:29:01", "VIP customer - escalate quickly")
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('ORD-NOTES-1', 'AA:BB:CC:00:29:01', 'm', 30, 500, 'paid', 'wechat', ?, ?)`, now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders/detail?order_no=ORD-NOTES-1", nil, jar)
	if !strings.Contains(body, "客服备注") {
		t.Error("page should show 客服备注 row")
	}
	if !strings.Contains(body, "VIP customer - escalate quickly") {
		t.Error("notes content should be rendered")
	}
}

// No notes: row is hidden (no empty space noise).
func TestAdminOrderDetailHidesNotesRowWhenEmpty(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:29:02", "phone", 30, nil)
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('ORD-NOTES-2', 'AA:BB:CC:00:29:02', 'm', 30, 500, 'paid', 'wechat', ?, ?)`, now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders/detail?order_no=ORD-NOTES-2", nil, jar)
	if strings.Contains(body, "客服备注") {
		t.Error("notes row should be hidden when MAC has no notes")
	}
}
