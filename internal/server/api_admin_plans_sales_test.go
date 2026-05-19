package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPIPlansSalesReturnsAggregates(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()
	// 2 paid orders for plan "month", 1 for "year"
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('SLS-1', 'AA:BB:CC:00:2D:01', 'month', 30, 500, 'paid', 'wechat', ?, ?)`, now, now)
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('SLS-2', 'AA:BB:CC:00:2D:02', 'month', 30, 600, 'paid', 'wechat', ?, ?)`, now, now)
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('SLS-3', 'AA:BB:CC:00:2D:03', 'year', 365, 5000, 'paid', 'wechat', ?, ?)`, now, now)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/plans/sales?days=30", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Plans []struct {
			Plan         string `json:"plan"`
			Orders       int    `json:"orders"`
			RevenueCents int    `json:"revenue_cents"`
		} `json:"plans"`
		Days int `json:"days"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Days != 30 {
		t.Errorf("days echo wrong: %d", resp.Days)
	}
	got := map[string]int{}
	gotOrders := map[string]int{}
	for _, p := range resp.Plans {
		got[p.Plan] = p.RevenueCents
		gotOrders[p.Plan] = p.Orders
	}
	if got["month"] != 1100 || gotOrders["month"] != 2 {
		t.Errorf("month aggregate wrong: revenue=%d orders=%d", got["month"], gotOrders["month"])
	}
	if got["year"] != 5000 || gotOrders["year"] != 1 {
		t.Errorf("year aggregate wrong: revenue=%d orders=%d", got["year"], gotOrders["year"])
	}
}

// Results sorted DESC by revenue → year (5000) should land before month (1100).
func TestAPIPlansSalesSortedByRevenue(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('S-A', 'AA:BB:CC:00:2D:10', 'cheap', 30, 100, 'paid', 'wechat', ?, ?)`, now, now)
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('S-B', 'AA:BB:CC:00:2D:11', 'expensive', 30, 99999, 'paid', 'wechat', ?, ?)`, now, now)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/plans/sales", "rb_w", "")
	var resp struct {
		Plans []struct {
			Plan string `json:"plan"`
		} `json:"plans"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Plans) < 2 {
		t.Fatal("expected ≥2 plans")
	}
	// First should be "expensive" since it has higher revenue.
	if resp.Plans[0].Plan != "expensive" {
		t.Errorf("expected expensive first; got %+v", resp.Plans)
	}
}

func TestAPIPlansSalesReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/plans/sales", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly should be 200; got %d", rr.Code)
	}
}

func TestAPIPlansSalesRejectsPOST(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/plans/sales", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("POST should be 405; got %d", rr.Code)
	}
}
