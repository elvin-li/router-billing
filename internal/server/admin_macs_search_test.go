package server

import (
	"context"
	"strings"
	"testing"
)

func TestAdminMACsSearchByMACSubstring(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:01", "alice phone", 30, nil); err != nil {
		t.Fatal(err)
	}
	// Use a MAC string that isn't anywhere in the template (the bulk-import
	// textarea placeholder mentions 11:22:33:44:55:66, so avoid that).
	if _, err := app.DB.UpsertMAC(ctx, "77:88:99:AA:BB:CC", "bob laptop", 30, nil); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs?q=DD", nil, jar)
	if !strings.Contains(body, "AA:BB:CC:DD:EE:01") {
		t.Error("filtered result missing the matching MAC")
	}
	if strings.Contains(body, "77:88:99:AA:BB:CC") {
		t.Error("non-matching MAC should be hidden by filter")
	}
	if !strings.Contains(body, "已过滤") {
		t.Error("page should show filtered indicator")
	}
	if !strings.Contains(body, "清除") {
		t.Error("clear filter link should appear")
	}
}

func TestAdminMACsSearchByLabelSubstring(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:02", "alice iphone", 30, nil)
	_, _ = app.DB.UpsertMAC(ctx, "11:22:33:44:55:67", "bob laptop", 30, nil)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs?q=laptop", nil, jar)
	if !strings.Contains(body, "bob laptop") {
		t.Error("label search missed the matching row")
	}
	if strings.Contains(body, "AA:BB:CC:DD:EE:02") {
		t.Error("non-matching label MAC should be hidden")
	}
}

func TestAdminMACsStatusFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:03", "active1", 30, nil)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:04", "active2", 30, nil)
	// Force one to expired by direct UPDATE.
	if _, err := app.DB.Exec(ctx, `UPDATE macs SET status = 'expired' WHERE mac = 'AA:BB:CC:DD:EE:04'`); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs?status=expired", nil, jar)
	if !strings.Contains(body, "AA:BB:CC:DD:EE:04") {
		t.Error("expired filter missed the expired MAC")
	}
	if strings.Contains(body, "AA:BB:CC:DD:EE:03") {
		t.Error("active row should be hidden by status=expired filter")
	}
}

func TestSearchMACsDB(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:05", "kitchen tv", 30, nil)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:06", "bedroom tv", 30, nil)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:07", "laptop", 30, nil)

	// Substring match on label.
	res, err := app.DB.SearchMACs(ctx, "tv", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Errorf("expected 2 tv rows; got %d", len(res))
	}

	// Substring on MAC.
	res2, _ := app.DB.SearchMACs(ctx, "EE:07", "", 100)
	if len(res2) != 1 || res2[0].Mac != "AA:BB:CC:DD:EE:07" {
		t.Errorf("MAC search wrong: %+v", res2)
	}

	// Empty query lists all.
	all, _ := app.DB.SearchMACs(ctx, "", "", 100)
	if len(all) != 3 {
		t.Errorf("empty q should return all 3; got %d", len(all))
	}

	// limit caps results.
	cap, _ := app.DB.SearchMACs(ctx, "", "", 2)
	if len(cap) != 2 {
		t.Errorf("limit=2 should return 2; got %d", len(cap))
	}
}
