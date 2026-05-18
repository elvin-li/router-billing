package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/models"
)

func TestAdminOrdersSearchByMAC(t *testing.T) {
	app := setupTestApp(t)
	seedOrder(t, app, "ORD-S-1", "AA:BB:CC:DD:EE:01", "month", 30, 100, models.OrderPaid)
	seedOrder(t, app, "ORD-S-2", "77:88:99:AA:BB:CC", "year", 365, 1000, models.OrderPaid)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders?q=77:88", nil, jar)
	if !strings.Contains(body, "ORD-S-2") {
		t.Error("filter should include ORD-S-2 (matches MAC)")
	}
	if strings.Contains(body, "ORD-S-1") {
		t.Error("ORD-S-1 should be hidden")
	}
}

func TestAdminOrdersStatusFilter(t *testing.T) {
	app := setupTestApp(t)
	seedOrder(t, app, "ORD-PD-1", "AA:BB:CC:00:00:01", "month", 30, 100, models.OrderPending)
	seedOrder(t, app, "ORD-PD-2", "AA:BB:CC:00:00:02", "year", 365, 1000, models.OrderPaid)
	seedOrder(t, app, "ORD-PD-3", "AA:BB:CC:00:00:03", "month", 30, 100, models.OrderRefunded)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders?status=refunded", nil, jar)
	if !strings.Contains(body, "ORD-PD-3") {
		t.Error("refunded filter missed refunded order")
	}
	for _, oth := range []string{"ORD-PD-1", "ORD-PD-2"} {
		if strings.Contains(body, oth) {
			t.Errorf("status=refunded should hide %s", oth)
		}
	}
}

func TestSearchOrdersDB(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	seedOrder(t, app, "ORD-DB-1", "AA:BB:CC:00:00:01", "month", 30, 100, models.OrderPaid)
	seedOrder(t, app, "ORD-DB-2", "11:22:33:44:55:66", "month", 30, 100, models.OrderPaid)

	// Substring by MAC.
	r, _ := app.DB.SearchOrders(ctx, "11:22", "", 100)
	if len(r) != 1 || r[0].OrderNo != "ORD-DB-2" {
		t.Errorf("MAC search got %+v", r)
	}

	// Substring by order_no.
	r2, _ := app.DB.SearchOrders(ctx, "DB-1", "", 100)
	if len(r2) != 1 || r2[0].OrderNo != "ORD-DB-1" {
		t.Errorf("order_no search got %+v", r2)
	}

	// Empty q lists all.
	all, _ := app.DB.SearchOrders(ctx, "", "", 100)
	if len(all) != 2 {
		t.Errorf("empty q should return all; got %d", len(all))
	}
}
