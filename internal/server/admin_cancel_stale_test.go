package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminOrderCancelStaleUIHappy(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('UI-STALE-1', 'AA:BB:CC:00:15:01', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-48*time.Hour))
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('UI-FRESH-1', 'AA:BB:CC:00:15:02', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-1*time.Hour))

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/orders/cancel-stale",
		url.Values{"_csrf": {csrf}, "hours": {"24"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=cancel_stale") || !strings.Contains(loc, "count=1") {
		t.Errorf("redirect should signal count=1; got %s", loc)
	}

	// Only the 48h-old one flipped.
	stale, _ := app.DB.GetOrder(ctx, "UI-STALE-1")
	if string(stale.Status) != "failed" {
		t.Errorf("stale should be failed; got %s", stale.Status)
	}
	fresh, _ := app.DB.GetOrder(ctx, "UI-FRESH-1")
	if string(fresh.Status) != "pending" {
		t.Errorf("fresh should remain pending; got %s", fresh.Status)
	}

	// Audit row with via=ui.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "orders_cancel_stale" && strings.Contains(e.Detail, "via=ui") {
			found = true
		}
	}
	if !found {
		t.Error("orders_cancel_stale via=ui audit row missing")
	}
}

func TestAdminOrderCancelStaleClampsToCap(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	// hours=99999 → clamped to 720 internally; verify redirect carries the
	// clamped value (or at least doesn't 500).
	res, _ := do(t, h, "POST", "/admin/orders/cancel-stale",
		url.Values{"_csrf": {csrf}, "hours": {"99999"}}, jar)
	if res.StatusCode != 303 {
		t.Errorf("oversize hours should still 303 (clamp); got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "hours=720") {
		t.Errorf("redirect should reflect clamped hours=720; got %s", res.Header.Get("Location"))
	}
}

func TestAdminOrderCancelStaleGETRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/orders/cancel-stale", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("GET should redirect; got %d", res.StatusCode)
	}
}

func TestAdminOrdersPageHasCancelStaleButton(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders", nil, jar)
	if !strings.Contains(body, "/admin/orders/cancel-stale") {
		t.Error("orders page should expose the cancel-stale form")
	}
	if !strings.Contains(body, "清理过期订单") {
		t.Error("button should be labeled '清理过期订单'")
	}
}
