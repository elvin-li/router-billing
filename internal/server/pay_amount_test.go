package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/models"
	"router-billing/internal/pay"
)

// TestFinalizeOrderRejectsAmountMismatch pins the paid-amount cross-check:
// a signed provider notification whose amount differs from the order total
// must not flip the order to paid or grant the MAC any time.
func TestFinalizeOrderRejectsAmountMismatch(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedOrder(t, app, "ORD-AMT-1", "AA:BB:CC:00:00:11", "month", 30, 500, models.OrderPending)

	err := app.finalizeOrder(ctx, &pay.PaidNotice{
		OrderNo: "ORD-AMT-1", TradeNo: "TX-1", Provider: "wechat", AmountCents: 100,
	})
	if err == nil || !strings.Contains(err.Error(), "amount mismatch") {
		t.Fatalf("want amount-mismatch error, got %v", err)
	}

	o, err := app.DB.GetOrder(ctx, "ORD-AMT-1")
	if err != nil || o == nil {
		t.Fatal(err)
	}
	if o.Status != models.OrderPending {
		t.Errorf("order status = %s, want pending (must not be marked paid)", o.Status)
	}
	if m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:00:11"); m != nil {
		t.Errorf("MAC must not be granted on mismatch; got %+v", m)
	}

	entries, _ := app.DB.ListAudit(ctx, 50)
	found := false
	for _, e := range entries {
		if e.Action == "pay_amount_mismatch" {
			found = true
		}
	}
	if !found {
		t.Error("expected a pay_amount_mismatch audit row")
	}
}

// TestFinalizeOrderAcceptsMatchingAmount verifies the happy path still works
// end-to-end when the provider reports the exact order total.
func TestFinalizeOrderAcceptsMatchingAmount(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedOrder(t, app, "ORD-AMT-2", "AA:BB:CC:00:00:12", "month", 30, 500, models.OrderPending)

	err := app.finalizeOrder(ctx, &pay.PaidNotice{
		OrderNo: "ORD-AMT-2", TradeNo: "TX-2", Provider: "wechat", AmountCents: 500,
	})
	if err != nil {
		t.Fatalf("finalize with matching amount: %v", err)
	}
	o, _ := app.DB.GetOrder(ctx, "ORD-AMT-2")
	if o == nil || o.Status != models.OrderPaid {
		t.Fatalf("order not paid: %+v", o)
	}
	if m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:00:12"); m == nil {
		t.Error("MAC should be granted after a matching payment")
	}
}

// TestFinalizeOrderSkipsCheckWhenAmountUnknown: AmountCents==0 means the
// provider payload carried no parseable amount — the check is skipped so a
// legitimate payment isn't dead-locked by an upstream format change.
func TestFinalizeOrderSkipsCheckWhenAmountUnknown(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedOrder(t, app, "ORD-AMT-3", "AA:BB:CC:00:00:13", "month", 30, 500, models.OrderPending)

	err := app.finalizeOrder(ctx, &pay.PaidNotice{
		OrderNo: "ORD-AMT-3", TradeNo: "TX-3", Provider: "alipay",
	})
	if err != nil {
		t.Fatalf("finalize with unknown amount: %v", err)
	}
	o, _ := app.DB.GetOrder(ctx, "ORD-AMT-3")
	if o == nil || o.Status != models.OrderPaid {
		t.Fatalf("order not paid: %+v", o)
	}
}
