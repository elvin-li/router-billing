package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAdminOrderDetailRendersFullProfile(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// Seed a paid order + linked MAC + a few audit rows tagging order_no.
	u, _ := app.DB.CreateUser(ctx, "13800180001", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:08:01", "phone", 30, &u.ID)
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('ORD-DETAIL-X', 'AA:BB:CC:00:08:01', 'month', 30, 500, 'paid', 'wechat', ?, ?, ?)`,
		u.ID, now, now)

	app.DB.Audit(ctx, "wechat-notify", "order_paid", "ORD-DETAIL-X", "trade_no=W12345")
	app.DB.Audit(ctx, "admin", "manual_note", "ORD-DETAIL-X", "customer called to confirm")

	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/orders/detail?order_no=ORD-DETAIL-X", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	for _, want := range []string{
		"ORD-DETAIL-X",      // order number
		"AA:BB:CC:00:08:01", // MAC
		"已支付",               // status pill
		"wechat-notify",     // first audit row actor
		"order_paid",        // audit action
		"customer called",   // audit detail
		"manual_note",       // audit action
		"trade_no=W12345",   // audit detail #1
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q; body=%s", want, truncate(body, 1500))
		}
	}
}

func TestAdminOrderDetailMissingOrderRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/orders/detail?order_no=NOPE", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("missing order should 303; got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "err=not_found") {
		t.Errorf("redirect should signal not_found; got %s", res.Header.Get("Location"))
	}
}

func TestAdminOrderDetailMissingParamRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/orders/detail", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("missing param should 303; got %d", res.StatusCode)
	}
	if res.Header.Get("Location") != "/admin/orders" {
		t.Errorf("redirect should go to /admin/orders; got %s", res.Header.Get("Location"))
	}
}

func TestAdminOrderDetailWithMissingMACShowsBanner(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// Order references a MAC that doesn't exist in the macs table.
	_, _ = app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('ORD-NOMAC-1', 'AA:BB:CC:DD:DE:AD', 'month', 30, 500, 'paid', 'wechat', ?, ?)`,
		now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders/detail?order_no=ORD-NOMAC-1", nil, jar)
	if !strings.Contains(body, "已不存在") {
		t.Error("missing MAC should show the banner; body did not include the warning")
	}
	// Order itself still rendered.
	if !strings.Contains(body, "ORD-NOMAC-1") {
		t.Error("order details should still render even with missing MAC")
	}
}

// /admin/orders should link to the detail page via the order_no cell.
func TestAdminOrdersListLinksToDetail(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('ORD-LINK-1', 'AA:BB:CC:00:08:09', 'month', 30, 100, 'paid', 'wechat', ?, ?)`,
		now, now)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders", nil, jar)
	if !strings.Contains(body, "/admin/orders/detail?order_no=ORD-LINK-1") {
		t.Error("orders list should link to the detail page")
	}
}
