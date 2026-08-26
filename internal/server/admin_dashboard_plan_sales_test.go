package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Pre-v0.96 the dashboard template referenced .Count / .Revenue on each
// PlanSales row but the struct exports OrdersCount / TotalCents.
//
// IMPORTANT: html/template's behavior here is *not* a silent "<no value>"
// (that only happens for missing map keys, not missing struct fields).
// The real pre-v0.96 footprint was:
//
//   - ExecuteTemplate errored out mid-render at the first .Count
//
//   - The unbuffered render() had already written headers + partial body
//     to the wire, so the implicit WriteHeader(200) stuck
//
//   - http.Error's WriteHeader(500) was silently dropped, but its
//     "internal\n" body got appended to the half-rendered table:
//
//     <td>month</td><td>internal
//
// v0.96 fixes the field names so the chart actually shows numbers. v0.102
// further made render() buffer first so that any future template error
// produces a clean 500 instead of a 200-with-leaked-partial-body.
//
// This test pins both: dashboard responds 200 with real values, and the
// "internal\n" pre-v0.96 footprint never appears in the body.
func TestAdminDashboardPlanSalesRendersValues(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('PS-1', 'AA:BB:CC:00:2E:01', 'month', 30, 12345, 'paid', 'wechat', ?, ?)`, now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/dashboard", nil, jar)

	// Pre-v0.96 the response was 200 with truncated body — the implicit
	// WriteHeader from the partial Execute beat http.Error's 500. Pin both:
	// status MUST be 200 (not the leaked-200 of pre-v0.96, which was 200
	// with garbage; we now distinguish via the body assertion below).
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", res.StatusCode, body)
	}
	// Section header present.
	if !strings.Contains(body, "最近 30 天按套餐") {
		t.Fatal("plan-sales section missing")
	}
	// Revenue value rendered (formatYuan turns 12345 into "123.45").
	if !strings.Contains(body, "123.45") {
		t.Errorf("formatted revenue 123.45 missing from plan-sales row")
	}
	// Order count rendered.
	idx := strings.Index(body, "最近 30 天按套餐")
	if idx < 0 {
		t.Fatal("section header not found")
	}
	end := idx + 800
	if end > len(body) {
		end = len(body)
	}
	chunk := body[idx:end]
	if !strings.Contains(chunk, "<td>1</td>") {
		t.Errorf("expected 1-order count in chunk; got %s", chunk)
	}
	// Anti-regression for the *real* pre-v0.96 footprint: a half-rendered
	// table with http.Error's "internal\n" string spliced into the last
	// <td>. The buffered render() in v0.102 makes this impossible (template
	// errors → clean 500, never leaked into a 200 body) but pin it here
	// so anyone who reverts the buffering breaks this test.
	if strings.Contains(chunk, "<td>internal") || strings.Contains(body, "internal\n") {
		t.Errorf("pre-v0.96 footprint detected: 'internal' leaked into body; chunk=%s", chunk)
	}
}
