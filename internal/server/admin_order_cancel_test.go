package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminOrderCancelHappyPath(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('UI-CANCEL-1', 'AA:BB:CC:00:12:01', 'month', 30, 500, 'pending', 'wechat', ?)`, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/orders/cancel",
		url.Values{"_csrf": {csrf}, "order_no": {"UI-CANCEL-1"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=canceled") {
		t.Errorf("redirect should signal canceled; got %s", res.Header.Get("Location"))
	}
	// DB state
	o, _ := app.DB.GetOrder(ctx, "UI-CANCEL-1")
	if string(o.Status) != "failed" {
		t.Errorf("order should be failed; got %s", o.Status)
	}
	// Audit via=ui (distinct from API)
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "order_canceled" && strings.Contains(e.Detail, "via=ui") {
			found = true
		}
	}
	if !found {
		t.Error("order_canceled audit via=ui missing")
	}
}

func TestAdminOrderCancelAlreadyPaidRedirects(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('UI-PAID-1', 'AA:BB:CC:00:12:02', 'month', 30, 500, 'paid', 'wechat', ?, ?)`, now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/orders/cancel",
		url.Values{"_csrf": {csrf}, "order_no": {"UI-PAID-1"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=not_pending") {
		t.Errorf("paid order should give err=not_pending; got %s", res.Header.Get("Location"))
	}
	// Status must not have changed.
	o, _ := app.DB.GetOrder(ctx, "UI-PAID-1")
	if string(o.Status) != "paid" {
		t.Errorf("paid order should still be paid; got %s", o.Status)
	}
}

func TestAdminOrderCancelMissingOrderRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/orders/cancel",
		url.Values{"_csrf": {csrf}, "order_no": {"NOPE-99"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=not_found") {
		t.Errorf("missing order should give err=not_found; got %s", res.Header.Get("Location"))
	}
}

func TestAdminOrderCancelGETRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/orders/cancel?order_no=X", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("GET should redirect; got %d", res.StatusCode)
	}
	if res.Header.Get("Location") != "/admin/orders" {
		t.Errorf("GET should redirect to /admin/orders; got %s", res.Header.Get("Location"))
	}
}

// /admin/orders should render a cancel button next to each pending order.
func TestAdminOrdersListShowsCancelButtonForPending(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('UI-LIST-PEND', 'AA:BB:CC:00:12:03', 'month', 30, 100, 'pending', 'wechat', ?)`, now)
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('UI-LIST-PAID', 'AA:BB:CC:00:12:04', 'month', 30, 100, 'paid', 'wechat', ?, ?)`, now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders", nil, jar)
	// Pending order should have a cancel form.
	if !strings.Contains(body, "/admin/orders/cancel") {
		t.Error("orders list should render the cancel form for pending orders")
	}
	if !strings.Contains(body, "UI-LIST-PEND") {
		t.Error("pending order should appear in the listing")
	}
}
