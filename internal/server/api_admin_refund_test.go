package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/models"
)

func TestAPIOrderRefundHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	seedPaidOrderWithMAC(t, app, "API-REFUND-1", "AA:BB:CC:DD:F0:01", 30, 1000)

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/refund", "rb_w",
		`{"order_no":"API-REFUND-1","reason":"chargeback"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "refunded" {
		t.Errorf("response: %+v", resp)
	}

	o, _ := app.DB.GetOrder(context.Background(), "API-REFUND-1")
	if o.Status != models.OrderRefunded {
		t.Errorf("order status = %s", o.Status)
	}
	// Audit entry has via=api marker.
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "order_refunded" && e.Target == "API-REFUND-1" {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit should include via=api; got %q", e.Detail)
			}
			if !strings.Contains(e.Actor, "api:") {
				t.Errorf("actor should be api:label; got %q", e.Actor)
			}
		}
	}
	if !found {
		t.Error("audit entry missing")
	}
}

func TestAPIOrderRefundMissingOrder(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/refund", "rb_w",
		`{"order_no":"DOES-NOT-EXIST"}`)
	if rr.Code != 404 {
		t.Errorf("expected 404; got %d", rr.Code)
	}
}

func TestAPIOrderRefundPendingReturns409(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	seedOrder(t, app, "API-PENDING", "AA:BB:CC:DD:F0:02", "month", 30, 100, models.OrderPending)
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/refund", "rb_w",
		`{"order_no":"API-PENDING"}`)
	if rr.Code != 409 {
		t.Errorf("expected 409 conflict; got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAPIOrderRefundReadOnlyTokenRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	seedPaidOrderWithMAC(t, app, "API-REFUND-RO", "AA:BB:CC:DD:F0:03", 30, 1000)
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/refund", "rb_ro",
		`{"order_no":"API-REFUND-RO"}`)
	if rr.Code != 403 {
		t.Errorf("expected 403; got %d", rr.Code)
	}
	// Confirm order is still paid (NOT refunded by a readonly token).
	o, _ := app.DB.GetOrder(context.Background(), "API-REFUND-RO")
	if o.Status != models.OrderPaid {
		t.Errorf("readonly token shouldn't have refunded; status=%s", o.Status)
	}
}

func TestAPIOrderRefundMissingOrderNoReturns400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/refund", "rb_w",
		`{"reason":"empty"}`)
	if rr.Code != 400 {
		t.Errorf("missing order_no: %d", rr.Code)
	}
}

func TestAPIOrderRefundReasonInBody(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	seedPaidOrderWithMAC(t, app, "API-REFUND-REASON", "AA:BB:CC:DD:F0:04", 30, 1000)
	h := app.Routes()
	apiReq(t, h, "POST", "/api/admin/orders/refund", "rb_w",
		`{"order_no":"API-REFUND-REASON","reason":"duplicate-charge-from-stripe"}`)

	o, _ := app.DB.GetOrder(context.Background(), "API-REFUND-REASON")
	if !strings.Contains(o.TradeNo, "duplicate-charge-from-stripe") {
		t.Errorf("trade_no should embed reason; got %q", o.TradeNo)
	}
}
