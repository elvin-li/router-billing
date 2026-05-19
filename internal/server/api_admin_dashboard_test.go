package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPIDashboardShape(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "GET", "/api/admin/dashboard", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Snapshot  map[string]int `json:"snapshot"`
		Attention map[string]int `json:"attention"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// Snapshot has all 13 keys.
	for _, k := range []string{
		"today_revenue_cents", "today_paid_orders", "today_new_users", "today_new_macs",
		"week7_revenue_cents", "week7_paid_orders",
		"month30_revenue_cents", "month30_paid_orders", "month30_new_users",
		"prev_month30_revenue_cents", "prev_month30_paid_orders", "prev_month30_new_users",
		"active_sessions",
	} {
		if _, ok := resp.Snapshot[k]; !ok {
			t.Errorf("snapshot missing key %q", k)
		}
	}
	// Attention has the 6 known counter keys.
	for _, k := range []string{
		"expiring_soon", "stale_pending", "suspended_users", "failed_today",
		"sms_failures_24h", "webhook_failures_24h",
	} {
		if _, ok := resp.Attention[k]; !ok {
			t.Errorf("attention missing key %q", k)
		}
	}
}

func TestAPIDashboardReflectsSeededData(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('TODAY-1', 'AA:BB:CC:00:1A:01', 'm', 30, 12345, 'paid', 'wechat', ?, ?)`,
		now, now)
	_ = app.DB.LogSMS(ctx, "console", "13800280001", "fail", false, "boom")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/dashboard", "rb_w", "")
	var resp struct {
		Snapshot  map[string]int `json:"snapshot"`
		Attention map[string]int `json:"attention"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Snapshot["today_revenue_cents"] != 12345 {
		t.Errorf("today_revenue_cents not seeded: %d", resp.Snapshot["today_revenue_cents"])
	}
	if resp.Attention["sms_failures_24h"] != 1 {
		t.Errorf("sms_failures_24h not seeded: %d", resp.Attention["sms_failures_24h"])
	}
}

func TestAPIDashboardReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/dashboard", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly should be 200; got %d", rr.Code)
	}
}

func TestAPIDashboardRejectsPOST(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/dashboard", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("POST should be 405; got %d", rr.Code)
	}
}
