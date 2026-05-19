package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAdminOrderDetailRendersWebhookDeliveries(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('WH-ORD-1', 'AA:BB:CC:00:1D:01', 'm', 30, 500, 'paid', 'wechat', ?, ?)`, now, now)
	_ = app.DB.LogWebhookDelivery(ctx, "order_paid", "AA:BB:CC:00:1D:01", 0, 200, true, 7, "")
	_ = app.DB.LogWebhookDelivery(ctx, "order_paid", "AA:BB:CC:00:1D:01", 1, 500, false, 12, "http 500")
	// Unrelated MAC delivery — should NOT appear.
	_ = app.DB.LogWebhookDelivery(ctx, "order_paid", "AA:BB:CC:DD:EE:FF", 0, 200, true, 5, "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders/detail?order_no=WH-ORD-1", nil, jar)

	if !strings.Contains(body, "Webhook 投递") {
		t.Error("page should show webhook section header")
	}
	// Both rows for our MAC should appear.
	if !strings.Contains(body, "7ms") || !strings.Contains(body, "12ms") {
		t.Error("duration_ms should be rendered for both rows")
	}
	// FAIL row should expose error tooltip.
	if !strings.Contains(body, `title="http 500"`) {
		t.Error("FAIL row should expose error_msg via title attribute")
	}
	// Link to filtered webhook-log. html/template's URL-context escape
	// encodes `:` as `%3a` — accept either form.
	if !strings.Contains(body, "/admin/webhook-log?mac=AA:BB:CC:00:1D:01") &&
		!strings.Contains(body, "/admin/webhook-log?mac=AA%3aBB%3aCC%3a00%3a1D%3a01") &&
		!strings.Contains(body, "/admin/webhook-log?mac=AA%3ABB%3ACC%3A00%3A1D%3A01") {
		t.Error("page should link to the MAC-filtered webhook-log")
	}
}

func TestAdminOrderDetailHidesWebhookSectionWhenEmpty(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('WH-NONE-1', 'AA:BB:CC:00:1D:02', 'm', 30, 500, 'paid', 'wechat', ?, ?)`, now, now)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders/detail?order_no=WH-NONE-1", nil, jar)
	if strings.Contains(body, "Webhook 投递") {
		t.Error("webhook section should be hidden when no rows exist for this MAC")
	}
}
