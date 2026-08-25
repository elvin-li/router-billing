package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

// Seed 4 pending orders at varied ages + 1 paid order. Cancel-stale
// with hours=12 should only kill the >12h-old pending rows and leave
// the paid + recent rows untouched.
func TestAPIOrderCancelStaleOnlyHitsOldPending(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()

	// 2 stale pending (24h + 48h old).
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('STALE-A', 'AA:BB:CC:00:14:01', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-24*time.Hour))
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('STALE-B', 'AA:BB:CC:00:14:02', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-48*time.Hour))
	// 1 fresh pending (1h old).
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('FRESH', 'AA:BB:CC:00:14:03', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-1*time.Hour))
	// 1 old PAID — must NOT be touched.
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('OLD-PAID', 'AA:BB:CC:00:14:04', 'm', 30, 100, 'paid', 'wechat', ?, ?)`,
		now.Add(-48*time.Hour), now.Add(-48*time.Hour))

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel-stale", "rb_w",
		`{"older_than_hours":12}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Canceled int `json:"canceled"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Canceled != 2 {
		t.Errorf("expected 2 canceled; got %d", resp.Canceled)
	}

	// Stale ones flipped to failed.
	for _, no := range []string{"STALE-A", "STALE-B"} {
		o, _ := app.DB.GetOrder(ctx, no)
		if o == nil || string(o.Status) != "failed" {
			t.Errorf("%s should be failed; got %+v", no, o)
		}
	}
	// Fresh + paid untouched.
	fresh, _ := app.DB.GetOrder(ctx, "FRESH")
	if string(fresh.Status) != "pending" {
		t.Errorf("fresh order should still be pending; got %s", fresh.Status)
	}
	paid, _ := app.DB.GetOrder(ctx, "OLD-PAID")
	if string(paid.Status) != "paid" {
		t.Errorf("paid order should still be paid; got %s", paid.Status)
	}

	// Audit row.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "orders_cancel_stale" {
			found = true
			if !strings.Contains(e.Detail, "count=2") || !strings.Contains(e.Detail, "hours=12") {
				t.Errorf("audit detail wrong: %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("orders_cancel_stale audit row missing")
	}
}

func TestAPIOrderCancelStaleDefaultsTo24h(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('DEFAULT-OLD', 'AA:BB:CC:00:14:05', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-25*time.Hour))
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('DEFAULT-FRESH', 'AA:BB:CC:00:14:06', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-23*time.Hour))

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel-stale", "rb_w", `{}`)
	var resp struct {
		Canceled int `json:"canceled"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Canceled != 1 {
		t.Errorf("default 24h should give 1; got %d", resp.Canceled)
	}
}

func TestAPIOrderCancelStaleHoursTooLarge400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel-stale", "rb_w",
		`{"older_than_hours":999999}`)
	if rr.Code != 400 {
		t.Errorf("oversize hours should be 400; got %d", rr.Code)
	}
}

func TestAPIOrderCancelStaleReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel-stale", "rb_ro", `{}`)
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

// Empty body should be fine — the cron use case is `curl -XPOST` with
// no body at all.
func TestAPIOrderCancelStaleEmptyBodyOK(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/orders/cancel-stale", "rb_w", "")
	if rr.Code != 200 {
		t.Errorf("empty body should be 200 (use default); got %d", rr.Code)
	}
}

// Regression (v0.106): a malformed body used to be silently discarded and
// the sweep ran at the 24h default. `{"older_than_hours":"48"}` (string
// instead of int) would cancel a MORE aggressive window than the caller
// asked for. Malformed non-empty JSON must be a 400 with zero cancellations.
func TestAPIOrderCancelStaleMalformedJSON400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()
	// A 30h-old pending order: inside the 24h default window, outside the
	// intended 48h one. Silent-default behavior would kill it.
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES ('MALFORMED-GUARD', 'AA:BB:CC:00:14:07', 'm', 30, 100, 'pending', 'wechat', ?)`,
		now.Add(-30*time.Hour))

	h := app.Routes()
	for _, body := range []string{
		`{"older_than_hours":"48"}`, // type mismatch
		`{"older_than_hours":48`,    // truncated
		`not json`,
	} {
		rr := apiReq(t, h, "POST", "/api/admin/orders/cancel-stale", "rb_w", body)
		if rr.Code != 400 {
			t.Errorf("body %q: want 400; got %d (%s)", body, rr.Code, rr.Body.String())
		}
	}
	o, _ := app.DB.GetOrder(ctx, "MALFORMED-GUARD")
	if o == nil || string(o.Status) != "pending" {
		t.Errorf("order must be untouched after rejected requests; got %+v", o)
	}
}
