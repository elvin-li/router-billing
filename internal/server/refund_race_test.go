package server

import (
	"context"
	"testing"
	"time"

	"router-billing/internal/models"
)

// Regression (v0.109): refunds used to call MarkOrderRefunded directly,
// bypassing the pollMu that serializes finalizeOrder. A refund (notably the
// programmatic /api/admin/orders/refund used by chargeback automation) could
// interleave between MarkOrderPaid and GrantFromOrder inside finalize: it
// saw status=paid, rolled back days that had not been granted yet, and then
// the grant landed anyway — a refunded order that kept its access. All
// refunds now go through App.refundOrder, which must block while finalize
// holds the lock and only roll back once the grant is complete.
func TestRefundSerializesWithFinalize(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedPaidOrderWithMAC(t, app, "ORD-RACE", "AA:BB:CC:DD:EE:41", 30, 1000)

	// Simulate finalizeOrder mid-flight: it holds pollMu between marking
	// the order paid and committing the grant.
	app.pollMu.Lock()

	done := make(chan struct{})
	var refundErr error
	var refundedMAC *models.MAC
	go func() {
		refundedMAC, refundErr = app.refundOrder(ctx, "ORD-RACE", "chargeback")
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("refund completed while finalize held pollMu — the refund/finalize race is open")
	case <-time.After(100 * time.Millisecond):
		// Expected: refund is waiting for finalize to finish.
	}

	app.pollMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refund never completed after finalize released the lock")
	}
	if refundErr != nil {
		t.Fatalf("refund after lock release: %v", refundErr)
	}
	if refundedMAC == nil {
		t.Fatal("refund should return the rolled-back MAC")
	}
	o, _ := app.DB.GetOrder(ctx, "ORD-RACE")
	if o.Status != models.OrderRefunded {
		t.Errorf("order status = %s, want refunded", o.Status)
	}
}
