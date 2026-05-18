package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"router-billing/internal/config"
	"router-billing/internal/models"
)

// seedOrder inserts a row directly via DB.Exec so the test can control
// status / created_at without going through the full pay flow.
func seedOrder(t *testing.T, app *App, orderNo, mac, plan string, days, cents int, status models.OrderStatus) {
	t.Helper()
	ctx := context.Background()
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 'wechat', ?)`,
		orderNo, mac, plan, days, cents, string(status), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestAPIOrderListReturnsRecentOrders(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ord_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()

	seedOrder(t, app, "ORD-1", "AA:BB:CC:00:00:01", "month", 30, 100, models.OrderPaid)
	seedOrder(t, app, "ORD-2", "AA:BB:CC:00:00:02", "year", 365, 1000, models.OrderPending)

	rr := apiReq(t, h, "GET", "/api/admin/orders", "rb_ord_ro", "")
	if rr.Code != 200 {
		t.Fatalf("got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Orders []models.Order `json:"orders"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Orders) != 2 {
		t.Fatalf("expected 2 orders; got %d", len(resp.Orders))
	}
}

func TestAPIOrderListStatusFilter(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ord_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()

	seedOrder(t, app, "ORD-A", "AA:BB:CC:00:00:01", "month", 30, 100, models.OrderPaid)
	seedOrder(t, app, "ORD-B", "AA:BB:CC:00:00:02", "year", 365, 1000, models.OrderPending)
	seedOrder(t, app, "ORD-C", "AA:BB:CC:00:00:03", "month", 30, 100, models.OrderPaid)

	rr := apiReq(t, h, "GET", "/api/admin/orders?status=paid", "rb_ord_ro", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var resp struct {
		Orders []models.Order `json:"orders"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Orders) != 2 {
		t.Errorf("paid filter should return 2; got %d", len(resp.Orders))
	}
	for _, o := range resp.Orders {
		if o.Status != models.OrderPaid {
			t.Errorf("expected paid only; got %s", o.Status)
		}
	}
}

func TestAPIOrderListLimitParam(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ord_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	// Seed 5.
	for i := 0; i < 5; i++ {
		seedOrder(t, app, "ORD-x"+itoaSmall(i), "AA:BB:CC:00:00:0"+itoaSmall(i),
			"month", 30, 100, models.OrderPaid)
	}
	rr := apiReq(t, h, "GET", "/api/admin/orders?limit=3", "rb_ord_ro", "")
	var resp struct {
		Orders []models.Order `json:"orders"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Orders) != 3 {
		t.Errorf("limit=3 should return 3; got %d", len(resp.Orders))
	}
}

func TestAPIOrderListReadOnlyTokenAccepted(t *testing.T) {
	// Regression guard: orders are a read-only endpoint, so a readonly
	// token must work on GET.
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ord_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/orders", "rb_ord_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly token should work on GET; got %d", rr.Code)
	}
}

func TestAPIOrderListRejectsNoToken(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ord", Label: "x"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/orders", "", "")
	if rr.Code != 401 {
		t.Errorf("no token: %d", rr.Code)
	}
}
