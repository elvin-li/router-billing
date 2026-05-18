package server

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
)

func TestAdminExportOrdersHonorsFilter(t *testing.T) {
	app := setupTestApp(t)
	now := time.Now().UTC()
	seedOrderWithCreated(t, app, "PAID-RECENT", "AA:BB:CC:00:00:01", models.OrderPaid, now.AddDate(0, 0, -2))
	seedOrderWithCreated(t, app, "PENDING-RECENT", "AA:BB:CC:00:00:02", models.OrderPending, now.AddDate(0, 0, -2))
	seedOrderWithCreated(t, app, "PAID-OLD", "AA:BB:CC:00:00:03", models.OrderPaid, now.AddDate(0, 0, -30))

	h := app.Routes()
	jar := loginAdmin(t, h)

	q := url.Values{
		"status": {"paid"},
		"since":  {now.AddDate(0, 0, -7).Format("2006-01-02")},
	}
	res, body := do(t, h, "GET", "/admin/export/orders.csv?"+q.Encode(), nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "PAID-RECENT") {
		t.Error("CSV should include PAID-RECENT")
	}
	if strings.Contains(body, "PENDING-RECENT") {
		t.Error("CSV should exclude PENDING-RECENT (status filter)")
	}
	if strings.Contains(body, "PAID-OLD") {
		t.Error("CSV should exclude PAID-OLD (date filter)")
	}
}

func TestAdminExportOrdersUnfilteredReturnsAll(t *testing.T) {
	app := setupTestApp(t)
	now := time.Now().UTC()
	seedOrderWithCreated(t, app, "ORD-X1", "AA:BB:CC:00:00:01", models.OrderPaid, now)
	seedOrderWithCreated(t, app, "ORD-X2", "AA:BB:CC:00:00:02", models.OrderPending, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/export/orders.csv", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	for _, want := range []string{"ORD-X1", "ORD-X2"} {
		if !strings.Contains(body, want) {
			t.Errorf("unfiltered CSV should include %q", want)
		}
	}
}

func TestAdminOrdersPageLinksCSVWithFilter(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders?status=paid&since=2026-01-01", nil, jar)
	// html/template leaves literal `&` in template text alone (only escapes
	// `&` inside {{...}} values), so the rendered link uses raw `&` rather
	// than `&amp;`. Browsers parse both fine.
	if !strings.Contains(body, "/admin/export/orders.csv?q=&status=paid&since=2026-01-01") {
		t.Errorf("CSV link should carry the filter query; body=%s", truncate(body, 800))
	}
	if !strings.Contains(body, "导出筛选结果") {
		t.Error("CSV button label should change to 导出筛选结果 when filter is active")
	}
}
