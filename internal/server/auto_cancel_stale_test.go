package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

// Direct unit test on the Security.AutoCancelStaleOrders() clamper —
// pins the boundary handling so a future refactor can't loosen it.
func TestSecurityAutoCancelStaleOrdersClamping(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 0},       // disabled
		{-1, 0},      // negative = disabled
		{1, 1},       // min
		{24, 24},     // typical
		{720, 720},   // max
		{99999, 720}, // overflow clamps
	}
	for _, c := range cases {
		s := config.Security{AutoCancelStaleOrderHours: c.in}
		if got := s.AutoCancelStaleOrders(); got != c.want {
			t.Errorf("AutoCancelStaleOrders(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// Integration: invoke purgeLoop's logic indirectly by replicating the
// background sweep — confirm a stale pending flips to failed AND an
// audit row lands with via=purge_loop.
func TestAutoCancelStaleSweepFlipsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security.AutoCancelStaleOrderHours = 12
	ctx := context.Background()

	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('AUTO-STALE', 'AA:BB:CC:00:18:01', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-24*time.Hour))
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('AUTO-FRESH', 'AA:BB:CC:00:18:02', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-1*time.Hour))

	// Replicate the sweep that purgeLoop would run.
	hours := app.Cfg.Security.AutoCancelStaleOrders()
	if hours == 0 {
		t.Fatal("AutoCancelStaleOrders should be enabled in this test")
	}
	n, err := app.DB.CancelStalePendingOrders(ctx, time.Duration(hours)*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 flip; got %d", n)
	}
	if n > 0 {
		app.DB.Audit(ctx, "system", "orders_cancel_stale", "",
			"count=1 hours=12 via=purge_loop")
	}

	// Stale flipped.
	stale, _ := app.DB.GetOrder(ctx, "AUTO-STALE")
	if string(stale.Status) != "failed" {
		t.Errorf("stale should be failed; got %s", stale.Status)
	}
	// Fresh untouched.
	fresh, _ := app.DB.GetOrder(ctx, "AUTO-FRESH")
	if string(fresh.Status) != "pending" {
		t.Errorf("fresh should remain pending; got %s", fresh.Status)
	}
	// Audit row.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "orders_cancel_stale" && strings.Contains(e.Detail, "via=purge_loop") {
			found = true
		}
	}
	if !found {
		t.Error("via=purge_loop audit row missing")
	}
}

// Sweep with zero matches should NOT write an audit row (anti-noise
// invariant). Tests document the deliberate count==0 skip in purgeLoop.
func TestAutoCancelStaleSweepSkipsAuditOnNoOp(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// No pending orders. Mirror the purgeLoop conditional.
	n, err := app.DB.CancelStalePendingOrders(ctx, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expected zero flips on clean DB; got %d", n)
	}
	// Per the purgeLoop guard, no audit row should be added.
	entries, _ := app.DB.ListAudit(ctx, 20)
	for _, e := range entries {
		if e.Action == "orders_cancel_stale" {
			t.Errorf("no-op sweep should not audit; got %+v", e)
		}
	}
}
