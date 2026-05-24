package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
)

// TestPayQRReadsPayloadFromOrderRow pins the v0.97 security fix: the QR
// payload comes from orders.qr_payload, NOT from a URL parameter.
//
// Pre-v0.97 the handler did:
//
//	payload := r.URL.Query().Get("payload")
//	qr.Encode(payload, ...)
//
// — meaning anyone holding any valid order_no could ask the server to
// render an arbitrary string as a QR served from our domain. Phishing
// aid. This test asserts that:
//
//  1. With qr_payload stored on the order, the handler returns a PNG.
//  2. URL-supplied ?payload=... is ignored (we can't decode the QR back
//     directly here, but if the URL value were load-bearing, the response
//     bytes would change vs the no-URL case — they don't).
//  3. With NO qr_payload stored (mid-upgrade legacy order), the
//     handler 404s instead of falling back to the URL value.
func TestPayQRReadsPayloadFromOrderRow(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// Insert an order with stored qr_payload — simulating what the new
	// handlePayCreate does after Precreate.
	now := time.Now().UTC()
	const wantPayload = "weixin://wxpay/bizpayurl?pr=safe-real-payload"
	_, err := app.DB.Exec(ctx, `INSERT INTO orders
		(order_no, mac, plan, days, amount_cents, status, payment_method, qr_payload, created_at)
		VALUES (?, ?, 'month', 30, 1000, 'pending', 'wechat', ?, ?)`,
		"PAYQR-OK", "AA:BB:CC:00:01:01", wantPayload, now)
	if err != nil {
		t.Fatal(err)
	}

	h := app.Routes()

	// Case 1 — happy path, no URL payload param at all.
	res, body := do(t, h, "GET", "/api/pay/qr?order_no=PAYQR-OK", nil, nil)
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d (body=%q)", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	if !strings.HasPrefix(body, "\x89PNG") {
		t.Errorf("body doesn't look like PNG; first bytes = %q", body[:minInt(len(body), 8)])
	}

	// Case 2 — attacker passes ?payload=phishing. Pre-v0.97 this would
	// have rendered the phishing string. Now it MUST be ignored: the
	// handler reads o.QRPayload regardless. Without a QR decoder in the
	// test, the strongest available proof is that the response bytes
	// match case 1 (different payloads → very different PNG matrices).
	res2, body2 := do(t, h, "GET",
		"/api/pay/qr?order_no=PAYQR-OK&payload=PHISHING-ATTACKER-CONTROLLED-STRING-XYZ",
		nil, nil)
	if res2.StatusCode != http.StatusOK {
		t.Errorf("attacker case: expected 200, got %d", res2.StatusCode)
	}
	if body != body2 {
		t.Errorf("URL-supplied ?payload=... is load-bearing (different PNG bytes); v0.97 fix not effective. lens: %d vs %d",
			len(body), len(body2))
	}
}

// TestPayQR404WhenNoPayloadStored — for orders that were created by
// the pre-v0.97 binary and never got qr_payload populated, /api/pay/qr
// should return 404 rather than fall back to a URL-supplied value
// (which would re-introduce the open-encoder vector).
func TestPayQR404WhenNoPayloadStored(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	now := time.Now().UTC()
	_, err := app.DB.Exec(ctx, `INSERT INTO orders
		(order_no, mac, plan, days, amount_cents, status, payment_method, qr_payload, created_at)
		VALUES (?, ?, 'month', 30, 1000, 'pending', 'wechat', '', ?)`,
		"PAYQR-LEGACY", "AA:BB:CC:00:01:02", now)
	if err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	// Even with an attacker-supplied ?payload=, an empty qr_payload
	// column should produce 404, not a phishing PNG.
	res, body := do(t, h, "GET",
		"/api/pay/qr?order_no=PAYQR-LEGACY&payload=PHISHING-XYZ",
		nil, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("legacy-order: expected 404, got %d (body=%q)", res.StatusCode, body)
	}
	if strings.HasPrefix(body, "\x89PNG") {
		t.Error("legacy-order: handler rendered a PNG; v0.97 fix bypassed via URL payload")
	}
}

// TestPayQR404OnUnknownOrder — sanity: /api/pay/qr for a nonexistent
// order_no returns 404 and doesn't render anything.
func TestPayQR404OnUnknownOrder(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, body := do(t, h, "GET", "/api/pay/qr?order_no=DOES-NOT-EXIST", nil, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d (body=%q)", res.StatusCode, body)
	}
}

// TestSetOrderQRPayloadRoundTrip pins the producer side: SetOrderQRPayload
// is what handlePayCreate calls after Precreate so /api/pay/qr has
// something to read. This test sidesteps Precreate (which needs a real
// PSP credential) by inserting an order directly, then exercises the
// store + read API the handler depends on.
func TestSetOrderQRPayloadRoundTrip(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()

	order := &models.Order{
		OrderNo: "PAYQR-PERSIST",
		Mac:     "AA:BB:CC:00:01:03",
	}
	_, err := app.DB.Exec(ctx, `INSERT INTO orders
		(order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES (?, ?, 'month', 30, 1000, 'pending', 'wechat', ?)`,
		order.OrderNo, order.Mac, now)
	if err != nil {
		t.Fatal(err)
	}

	const want = "alipays://platformapi/startapp?saId=10000007&qrcode=https%3A%2F%2Fqr.alipay.com%2Fbax03937xxx"
	if err := app.DB.SetOrderQRPayload(ctx, order.OrderNo, want); err != nil {
		t.Fatal(err)
	}

	got, err := app.DB.GetOrder(ctx, order.OrderNo)
	if err != nil || got == nil {
		t.Fatalf("get order: err=%v", err)
	}
	if got.QRPayload != want {
		t.Errorf("QRPayload = %q, want %q", got.QRPayload, want)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
