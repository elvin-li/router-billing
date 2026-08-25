package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
	"router-billing/internal/pay"
)

func seedPendingOrder(t *testing.T, app *App, orderNo, mac string, days, cents int) {
	t.Helper()
	err := app.DB.CreateOrder(context.Background(), &models.Order{
		OrderNo:       orderNo,
		Mac:           mac,
		Plan:          "month",
		Days:          days,
		AmountCents:   cents,
		Status:        models.OrderPending,
		PaymentMethod: "wechat",
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Regression (v0.105, HIGH): PSPs redeliver success notifications for up to
// ~24h. If an admin refunded the order in that window, the redelivered (or
// replayed) notification used to flip the order refunded→paid and re-grant
// the MAC days — the customer kept the refund AND the access. A notification
// for a refunded order must be acked (nil error, so the PSP stops retrying)
// without touching the order or the MAC.
func TestFinalizeDoesNotResurrectRefundedOrder(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedPaidOrderWithMAC(t, app, "ORD-REPLAY", "AA:BB:CC:DD:EE:21", 30, 1000)

	refundedMAC, err := app.DB.MarkOrderRefunded(ctx, "ORD-REPLAY", "customer request")
	if err != nil {
		t.Fatal(err)
	}

	// The PSP redelivers the original success notification.
	err = app.finalizeOrder(ctx, &pay.PaidNotice{
		OrderNo: "ORD-REPLAY", TradeNo: "TRADE-XYZ", Provider: "wechat", AmountCents: 1000,
	})
	if err != nil {
		t.Fatalf("redelivery for refunded order should be acked, got err: %v", err)
	}

	o, _ := app.DB.GetOrder(ctx, "ORD-REPLAY")
	if o.Status != models.OrderRefunded {
		t.Errorf("order status = %s, want refunded (replay resurrected the order)", o.Status)
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:21")
	if m == nil {
		t.Fatal("mac row disappeared")
	}
	if !m.ExpiresAt.Equal(refundedMAC.ExpiresAt) {
		t.Errorf("mac expiry moved from %s to %s — replay re-granted refunded days",
			refundedMAC.ExpiresAt, m.ExpiresAt)
	}
}

// Regression (v0.105, HIGH): the PSP-confirmed amount was never checked
// against the order (pay.ErrBadAmount existed but was unused). A notice
// whose amount doesn't match the order must not finalize.
func TestFinalizeRejectsAmountMismatch(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedPendingOrder(t, app, "ORD-AMT", "AA:BB:CC:DD:EE:22", 30, 1000)

	err := app.finalizeOrder(ctx, &pay.PaidNotice{
		OrderNo: "ORD-AMT", TradeNo: "TX-AMT", Provider: "alipay", AmountCents: 100,
	})
	if !errors.Is(err, pay.ErrBadAmount) {
		t.Fatalf("expected ErrBadAmount, got %v", err)
	}
	o, _ := app.DB.GetOrder(ctx, "ORD-AMT")
	if o.Status != models.OrderPending {
		t.Errorf("order status = %s, want pending", o.Status)
	}
	if m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:22"); m != nil {
		t.Error("MAC must not be granted on amount mismatch")
	}
	// The mismatch is audited so the operator can investigate.
	entries, _ := app.DB.ListAudit(ctx, 50)
	found := false
	for _, e := range entries {
		if e.Action == "pay_amount_mismatch" && strings.Contains(e.Detail, "ORD-AMT") {
			found = true
		}
	}
	if !found {
		t.Error("expected pay_amount_mismatch audit entry")
	}
}

func TestFinalizeGrantsOnceAndIsIdempotent(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedPendingOrder(t, app, "ORD-OK", "AA:BB:CC:DD:EE:23", 30, 1000)

	notice := &pay.PaidNotice{
		OrderNo: "ORD-OK", TradeNo: "TX-OK", Provider: "wechat", AmountCents: 1000,
	}
	if err := app.finalizeOrder(ctx, notice); err != nil {
		t.Fatal(err)
	}
	o, _ := app.DB.GetOrder(ctx, "ORD-OK")
	if o.Status != models.OrderPaid || o.TradeNo != "TX-OK" {
		t.Fatalf("order = %s/%s, want paid/TX-OK", o.Status, o.TradeNo)
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:23")
	if m == nil {
		t.Fatal("MAC not granted")
	}
	want := time.Now().Add(30 * 24 * time.Hour)
	if d := m.ExpiresAt.Sub(want); d < -time.Minute || d > time.Minute {
		t.Errorf("expiry %s not ~30d out", m.ExpiresAt)
	}
	firstExpiry := m.ExpiresAt

	// Duplicate notification: no error, no double grant.
	if err := app.finalizeOrder(ctx, notice); err != nil {
		t.Fatalf("duplicate finalize: %v", err)
	}
	m2, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:23")
	if !m2.ExpiresAt.Equal(firstExpiry) {
		t.Errorf("duplicate finalize extended expiry: %s → %s", firstExpiry, m2.ExpiresAt)
	}
}

// Poll paths from before v0.105 (and hypothetical payloads without a usable
// amount) report AmountCents=0 — that means "unknown", and must finalize
// rather than be treated as a zero-cost mismatch.
func TestFinalizeAcceptsUnknownAmount(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedPendingOrder(t, app, "ORD-NOAMT", "AA:BB:CC:DD:EE:24", 30, 1000)

	err := app.finalizeOrder(ctx, &pay.PaidNotice{
		OrderNo: "ORD-NOAMT", TradeNo: "TX-NA", Provider: "wechat",
	})
	if err != nil {
		t.Fatal(err)
	}
	o, _ := app.DB.GetOrder(ctx, "ORD-NOAMT")
	if o.Status != models.OrderPaid {
		t.Errorf("order status = %s, want paid", o.Status)
	}
}

// order_no doubles as the bearer token for /api/pay/status, /api/pay/wait
// and /receipt. Shape: "B" + 14-digit UTC timestamp + 16 hex chars (64
// random bits), 31 chars total — within WeChat's 32-char out_trade_no cap.
func TestNewOrderNoShapeAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		no := newOrderNo()
		if len(no) != 31 {
			t.Fatalf("len(%q) = %d, want 31", no, len(no))
		}
		if no[0] != 'B' {
			t.Fatalf("prefix of %q", no)
		}
		suffix := no[15:]
		if len(suffix) != 16 {
			t.Fatalf("suffix %q len %d, want 16", suffix, len(suffix))
		}
		for _, c := range suffix {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Fatalf("non-hex char %q in %q", c, no)
			}
		}
		if seen[no] {
			t.Fatalf("duplicate order no %q", no)
		}
		seen[no] = true
	}
}
