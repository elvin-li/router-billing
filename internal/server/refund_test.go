package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
)

// seedPaidOrderWithMAC inserts a paid order AND grants the MAC `days` of
// time so we have a realistic refund target. Returns the post-state MAC.
func seedPaidOrderWithMAC(t *testing.T, app *App, orderNo, mac string, days, cents int) *models.MAC {
	t.Helper()
	ctx := context.Background()
	paid := time.Now().UTC().Add(-time.Hour) // paid an hour ago
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, trade_no, paid_at, created_at)
		VALUES (?, ?, 'month', ?, ?, 'paid', 'wechat', 'TRADE-XYZ', ?, ?)`,
		orderNo, mac, days, cents, paid, paid); err != nil {
		t.Fatal(err)
	}
	m, err := app.DB.UpsertMAC(ctx, mac, "test", days, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRefundFlowDBRollsBackExpiry(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	m := seedPaidOrderWithMAC(t, app, "ORD-REFUND-1", "AA:BB:CC:DD:EE:01", 30, 1000)
	originalExpiry := m.ExpiresAt

	gotMac, err := app.DB.MarkOrderRefunded(ctx, "ORD-REFUND-1", "duplicate charge")
	if err != nil {
		t.Fatalf("MarkOrderRefunded: %v", err)
	}
	if gotMac == nil {
		t.Fatal("expected MAC to be returned")
	}
	// Expiry rolled back exactly 30 days.
	diff := originalExpiry.Sub(gotMac.ExpiresAt)
	want := 30 * 24 * time.Hour
	if diff < want-time.Minute || diff > want+time.Minute {
		t.Errorf("expected expiry rollback of ~30 days; got %s", diff)
	}
	// The order is now refunded.
	o, _ := app.DB.GetOrder(ctx, "ORD-REFUND-1")
	if o.Status != models.OrderRefunded {
		t.Errorf("order status = %s, want refunded", o.Status)
	}
	// Reason recorded.
	if !strings.Contains(o.TradeNo, "duplicate charge") {
		t.Errorf("trade_no should include reason; got %q", o.TradeNo)
	}
}

func TestRefundExpiresMACWhenRollbackPushesPast(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// 7-day order + 7-day MAC → refund rolls expiry to now-ish, status flips to expired.
	seedPaidOrderWithMAC(t, app, "ORD-REFUND-2", "AA:BB:CC:DD:EE:02", 7, 100)

	m, err := app.DB.MarkOrderRefunded(ctx, "ORD-REFUND-2", "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != models.MACExpired {
		t.Errorf("expected MAC to be expired after refund; got %s", m.Status)
	}
	// And the DB row reflects it too (not just the returned struct).
	row, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:02")
	if row.Status != models.MACExpired {
		t.Errorf("DB row status = %s; want expired", row.Status)
	}
}

func TestRefundRejectsUnpaidOrder(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('ORD-PENDING', 'AA:BB:CC:DD:EE:03', 'month', 30, 100, 'pending', 'wechat', ?)`,
		time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	_, err := app.DB.MarkOrderRefunded(ctx, "ORD-PENDING", "")
	if err == nil {
		t.Fatal("expected error refunding pending order")
	}
	if !strings.Contains(err.Error(), "only paid") {
		t.Errorf("error should mention 'only paid'; got %v", err)
	}
}

func TestRefundRejectsMissingOrder(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, err := app.DB.MarkOrderRefunded(ctx, "ORD-NONEXISTENT", "")
	if err == nil {
		t.Fatal("expected error for missing order")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found'; got %v", err)
	}
}

func TestRefundIdempotenceRefundedCannotRefundAgain(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedPaidOrderWithMAC(t, app, "ORD-REFUND-3", "AA:BB:CC:DD:EE:04", 30, 1000)

	if _, err := app.DB.MarkOrderRefunded(ctx, "ORD-REFUND-3", ""); err != nil {
		t.Fatal(err)
	}
	_, err := app.DB.MarkOrderRefunded(ctx, "ORD-REFUND-3", "")
	if err == nil {
		t.Fatal("expected error refunding already-refunded order")
	}
	if !strings.Contains(err.Error(), "only paid") {
		t.Errorf("error should mention 'only paid'; got %v", err)
	}
}

func TestRefundHandlerRequiresConfirmationMatch(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	seedPaidOrderWithMAC(t, app, "ORD-CONFIRM", "AA:BB:CC:DD:EE:05", 30, 1000)

	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	// Wrong confirmation.
	res, _ := do(t, h, "POST", "/admin/orders/refund",
		url.Values{
			"_csrf":            {csrf},
			"order_no":         {"ORD-CONFIRM"},
			"confirm_order_no": {"WRONG"},
		}, jar)
	if !strings.Contains(res.Header.Get("Location"), "refund_confirm") {
		t.Errorf("expected refund_confirm err; got %s", res.Header.Get("Location"))
	}
	// Order is still paid.
	o, _ := app.DB.GetOrder(context.Background(), "ORD-CONFIRM")
	if o.Status != models.OrderPaid {
		t.Errorf("order should still be paid; got %s", o.Status)
	}

	// Matching confirmation.
	res, _ = do(t, h, "POST", "/admin/orders/refund",
		url.Values{
			"_csrf":            {csrf},
			"order_no":         {"ORD-CONFIRM"},
			"confirm_order_no": {"ORD-CONFIRM"},
			"reason":           {"client requested"},
		}, jar)
	if !strings.Contains(res.Header.Get("Location"), "ok=refunded") {
		t.Errorf("expected ok=refunded; got %s", res.Header.Get("Location"))
	}
	o, _ = app.DB.GetOrder(context.Background(), "ORD-CONFIRM")
	if o.Status != models.OrderRefunded {
		t.Errorf("order should be refunded; got %s", o.Status)
	}
}

func TestRefundHandlerNotFoundSurfacesError(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/orders/refund",
		url.Values{
			"_csrf":            {csrf},
			"order_no":         {"ORD-DOES-NOT-EXIST"},
			"confirm_order_no": {"ORD-DOES-NOT-EXIST"},
		}, jar)
	if !strings.Contains(res.Header.Get("Location"), "refund_no_order") {
		t.Errorf("expected refund_no_order err; got %s", res.Header.Get("Location"))
	}
}

func TestRefundHandlerPendingSurfacesNotPaidError(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('ORD-NOT-PAID', 'AA:BB:CC:DD:EE:06', 'month', 30, 100, 'pending', 'wechat', ?)`,
		time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/orders/refund",
		url.Values{
			"_csrf":            {csrf},
			"order_no":         {"ORD-NOT-PAID"},
			"confirm_order_no": {"ORD-NOT-PAID"},
		}, jar)
	if !strings.Contains(res.Header.Get("Location"), "refund_not_paid") {
		t.Errorf("expected refund_not_paid err; got %s", res.Header.Get("Location"))
	}
}

func TestRefundAuditEntryRecorded(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	seedPaidOrderWithMAC(t, app, "ORD-AUDIT", "AA:BB:CC:DD:EE:07", 30, 1000)
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	do(t, h, "POST", "/admin/orders/refund",
		url.Values{
			"_csrf":            {csrf},
			"order_no":         {"ORD-AUDIT"},
			"confirm_order_no": {"ORD-AUDIT"},
			"reason":           {"test audit"},
		}, jar)

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "order_refunded" && e.Target == "ORD-AUDIT" {
			found = true
			if !strings.Contains(e.Detail, "test audit") {
				t.Errorf("audit detail should include reason; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("audit log should contain order_refunded entry")
	}
}

func TestRefundShowsRefundedPillInUI(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	seedPaidOrderWithMAC(t, app, "ORD-UI", "AA:BB:CC:DD:EE:08", 30, 1000)
	if _, err := app.DB.MarkOrderRefunded(context.Background(), "ORD-UI", "for-UI-test"); err != nil {
		t.Fatal(err)
	}
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders", nil, jar)
	if !strings.Contains(body, "已退款") {
		t.Errorf("admin/orders should show 已退款 pill; body=%s", truncate(body, 600))
	}
}
