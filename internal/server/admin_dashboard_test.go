package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
)

func TestAdminDashboardRendersAllSections(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/dashboard", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	for _, want := range []string{"仪表盘", "今日营收", "最近 7 天", "最近 30 天", "累计", "最近活动", "快捷操作"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

func TestDashboardSnapshot30DayWindow(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800149000", "h")
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:E3:01", "", 30, &u.ID); err != nil {
		t.Fatal(err)
	}

	// Within window (5 days ago).
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('ORD-30D-1', 'AA:BB:CC:DD:E3:01', 'month', 30, 500, 'paid', 'wechat', ?, ?, ?)`,
		u.ID, time.Now().UTC().AddDate(0, 0, -5), time.Now().UTC().AddDate(0, 0, -5)); err != nil {
		t.Fatal(err)
	}
	// Outside window (45 days ago).
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('ORD-30D-2', 'AA:BB:CC:DD:E3:01', 'month', 30, 1000, 'paid', 'wechat', ?, ?, ?)`,
		u.ID, time.Now().UTC().AddDate(0, 0, -45), time.Now().UTC().AddDate(0, 0, -45)); err != nil {
		t.Fatal(err)
	}

	snap, err := app.DB.DashboardSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Month30RevenueCents != 500 {
		t.Errorf("Month30 revenue = %d; want 500 (only the 5-day-old order)", snap.Month30RevenueCents)
	}
	if snap.Month30PaidOrders != 1 {
		t.Errorf("Month30 paid orders = %d; want 1", snap.Month30PaidOrders)
	}
	if snap.Month30NewUsers != 1 {
		t.Errorf("Month30 new users = %d; want 1", snap.Month30NewUsers)
	}
}

func TestAdminRootRedirectsToDashboard(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin", nil, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/admin/dashboard" {
		t.Errorf("expected redirect to /admin/dashboard; got %s", loc)
	}
}

func TestAdminSidebarShowsDashboardLink(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs", nil, jar)
	if !strings.Contains(body, `href="/admin/dashboard"`) {
		t.Error("sidebar should link to /admin/dashboard")
	}
	if !strings.Contains(body, "仪表盘") {
		t.Error("sidebar should show 仪表盘 label")
	}
}

func TestDashboardSnapshotShape(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// Today: 1 paid order @ ¥10, 1 new user, 1 new MAC.
	u, _ := app.DB.CreateUser(ctx, "13800141000", "h")
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:01", "", 30, &u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('TD-1', 'AA:BB:CC:DD:EE:01', 'month', 30, 1000, 'paid', 'wechat', ?, ?, ?)`,
		u.ID, time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	snap, err := app.DB.DashboardSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.TodayRevenueCents != 1000 {
		t.Errorf("today revenue = %d; want 1000", snap.TodayRevenueCents)
	}
	if snap.TodayPaidOrders != 1 {
		t.Errorf("today paid orders = %d; want 1", snap.TodayPaidOrders)
	}
	if snap.TodayNewUsers != 1 {
		t.Errorf("today new users = %d; want 1", snap.TodayNewUsers)
	}
	if snap.TodayNewMACs != 1 {
		t.Errorf("today new MACs = %d; want 1", snap.TodayNewMACs)
	}
	if snap.Week7RevenueCents < 1000 {
		t.Errorf("week 7 revenue should include today; got %d", snap.Week7RevenueCents)
	}
}

func TestDashboardEmptyDBIsZeroes(t *testing.T) {
	app := setupTestApp(t)
	snap, err := app.DB.DashboardSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.TodayRevenueCents != 0 || snap.TodayPaidOrders != 0 ||
		snap.TodayNewUsers != 0 || snap.TodayNewMACs != 0 ||
		snap.Week7RevenueCents != 0 {
		t.Errorf("empty DB should give all zeros; got %+v", snap)
	}
}

// silence unused — keeps models import paid for future dashboard helpers.
var _ = models.OrderPaid
