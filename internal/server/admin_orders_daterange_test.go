package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"router-billing/internal/db"
	"router-billing/internal/models"
)

// seedOrderWithCreated inserts an order with a specific created_at so the
// date-range filter can be exercised deterministically.
func seedOrderWithCreated(t *testing.T, app *App, orderNo, mac string, status models.OrderStatus, createdAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, created_at)
		VALUES (?, ?, 'month', 30, 100, ?, 'wechat', ?)`,
		orderNo, mac, string(status), createdAt); err != nil {
		t.Fatal(err)
	}
}

func TestSearchOrdersFilteredSinceUntil(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// 10 days ago, 5 days ago, 1 day ago, today.
	now := time.Now().UTC()
	seedOrderWithCreated(t, app, "OLD-10", "AA:BB:CC:00:00:0A", models.OrderPaid, now.AddDate(0, 0, -10))
	seedOrderWithCreated(t, app, "OLD-5", "AA:BB:CC:00:00:0B", models.OrderPaid, now.AddDate(0, 0, -5))
	seedOrderWithCreated(t, app, "OLD-1", "AA:BB:CC:00:00:0C", models.OrderPaid, now.AddDate(0, 0, -1))
	seedOrderWithCreated(t, app, "TODAY", "AA:BB:CC:00:00:0D", models.OrderPaid, now)

	// Window: 7 days ago through 2 days ago — should include OLD-5 only.
	r, err := app.DB.SearchOrdersFiltered(ctx, db.OrderFilter{
		Since: now.AddDate(0, 0, -7).Format("2006-01-02"),
		Until: now.AddDate(0, 0, -2).Format("2006-01-02"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 1 || r[0].OrderNo != "OLD-5" {
		t.Errorf("date-range filter wrong; got %+v", r)
	}
}

func TestSearchOrdersFilteredSinceOnly(t *testing.T) {
	app := setupTestApp(t)
	now := time.Now().UTC()
	seedOrderWithCreated(t, app, "BEFORE", "AA:BB:CC:00:00:01", models.OrderPaid, now.AddDate(0, 0, -30))
	seedOrderWithCreated(t, app, "AFTER", "AA:BB:CC:00:00:02", models.OrderPaid, now.AddDate(0, 0, -1))

	r, _ := app.DB.SearchOrdersFiltered(context.Background(), db.OrderFilter{
		Since: now.AddDate(0, 0, -3).Format("2006-01-02"),
	})
	if len(r) != 1 || r[0].OrderNo != "AFTER" {
		t.Errorf("since filter wrong; got %+v", r)
	}
}

func TestSearchOrdersFilteredCombinedWithStatusAndQ(t *testing.T) {
	app := setupTestApp(t)
	now := time.Now().UTC()
	seedOrderWithCreated(t, app, "PAID-RECENT", "AA:BB:CC:00:00:01", models.OrderPaid, now.AddDate(0, 0, -1))
	seedOrderWithCreated(t, app, "PENDING-RECENT", "AA:BB:CC:00:00:02", models.OrderPending, now.AddDate(0, 0, -1))
	seedOrderWithCreated(t, app, "PAID-OLD", "AA:BB:CC:00:00:03", models.OrderPaid, now.AddDate(0, 0, -30))

	r, _ := app.DB.SearchOrdersFiltered(context.Background(), db.OrderFilter{
		Status: string(models.OrderPaid),
		Since:  now.AddDate(0, 0, -7).Format("2006-01-02"),
	})
	if len(r) != 1 || r[0].OrderNo != "PAID-RECENT" {
		t.Errorf("combined filter wrong; got %+v", r)
	}
}

func TestAdminOrdersPageHonorsDateRange(t *testing.T) {
	app := setupTestApp(t)
	now := time.Now().UTC()
	seedOrderWithCreated(t, app, "DATE-IN", "AA:BB:CC:00:00:01", models.OrderPaid, now.AddDate(0, 0, -2))
	seedOrderWithCreated(t, app, "DATE-OUT", "AA:BB:CC:00:00:02", models.OrderPaid, now.AddDate(0, 0, -10))

	h := app.Routes()
	jar := loginAdmin(t, h)
	since := now.AddDate(0, 0, -5).Format("2006-01-02")
	_, body := do(t, h, "GET", "/admin/orders?since="+since, nil, jar)
	if !strings.Contains(body, "DATE-IN") {
		t.Error("page should include DATE-IN (within window)")
	}
	if strings.Contains(body, "DATE-OUT") {
		t.Error("page should NOT include DATE-OUT (before window)")
	}
	if !strings.Contains(body, "已过滤") {
		t.Error("page should show 已过滤 indicator with date filter")
	}
}
