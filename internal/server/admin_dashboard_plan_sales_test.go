package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Pre-v0.96 the dashboard template referenced .Count / .Revenue on each
// PlanSales row but the struct exports OrdersCount / TotalCents — Go's
// html/template silently renders `<no value>` for unknown fields. v0.96
// fixes the field names so the chart actually shows numbers.
func TestAdminDashboardPlanSalesRendersValues(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('PS-1', 'AA:BB:CC:00:2E:01', 'month', 30, 12345, 'paid', 'wechat', ?, ?)`, now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/dashboard", nil, jar)

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
	// And critically — NO <no value> anywhere (pre-v0.96 footprint).
	if strings.Contains(chunk, "&lt;no value&gt;") || strings.Contains(chunk, "<no value>") {
		t.Errorf("template-key-miss: 'no value' rendered; chunk=%s", chunk)
	}
}
