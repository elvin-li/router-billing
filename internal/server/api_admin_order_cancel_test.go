package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPIOrderCancelHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('CANCEL-1', 'AA:BB:CC:00:11:01', 'month', 30, 500, 'pending', 'wechat', ?)`, now)

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel", "rb_w",
		`{"order_no":"CANCEL-1"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status  string `json:"status"`
		OrderNo string `json:"order_no"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "canceled" || resp.OrderNo != "CANCEL-1" {
		t.Errorf("unexpected response: %+v", resp)
	}
	// DB state should be 'failed' now.
	o, _ := app.DB.GetOrder(ctx, "CANCEL-1")
	if o == nil || string(o.Status) != "failed" {
		t.Errorf("order should be failed; got %+v", o)
	}
	// Audit row with via=api.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "order_canceled" && e.Target == "CANCEL-1" {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit detail missing via=api; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("order_canceled audit row missing")
	}
}

func TestAPIOrderCancelNotFound(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel", "rb_w",
		`{"order_no":"NOPE-123"}`)
	if rr.Code != 404 {
		t.Errorf("missing order should be 404; got %d", rr.Code)
	}
}

func TestAPIOrderCancelAlreadyPaid409(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('PAID-1', 'AA:BB:CC:00:11:02', 'month', 30, 500, 'paid', 'wechat', ?, ?)`, now, now)
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel", "rb_w",
		`{"order_no":"PAID-1"}`)
	if rr.Code != 409 {
		t.Errorf("paid order should be 409; got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "only pending orders") {
		t.Errorf("error should explain the constraint; got %s", rr.Body.String())
	}
	// Status should not have changed.
	o, _ := app.DB.GetOrder(ctx, "PAID-1")
	if string(o.Status) != "paid" {
		t.Errorf("paid order should still be paid; got %s", o.Status)
	}
}

func TestAPIOrderCancelMissingParam(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel", "rb_w", `{}`)
	if rr.Code != 400 {
		t.Errorf("missing order_no should be 400; got %d", rr.Code)
	}
}

func TestAPIOrderCancelReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel", "rb_ro",
		`{"order_no":"X"}`)
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

// DB-level: CancelPendingOrder is atomic. Call it twice in a row — first
// transitions; second should report not-pending.
func TestCancelPendingOrderIdempotenceCheck(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('DOUBLE-1', 'AA:BB:CC:00:11:03', 'month', 30, 500, 'pending', 'wechat', ?)`, now)

	o, err := app.DB.CancelPendingOrder(ctx, "DOUBLE-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(o.Status) != "failed" {
		t.Errorf("first call should transition to failed; got %s", o.Status)
	}
	// Second call: order is no longer pending.
	_, err = app.DB.CancelPendingOrder(ctx, "DOUBLE-1")
	if err == nil {
		t.Error("second call should error (order no longer pending)")
	}
}
