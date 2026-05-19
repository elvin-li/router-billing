package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

func TestAdminExportMACsFilterByStatus(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:1B:01", "ok", 30, nil)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:1B:02", "blocked-one", 30, nil)
	_ = app.DB.SetMACStatus(ctx, "AA:BB:CC:00:1B:02", "blocked")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/macs.csv?status=blocked", nil, jar)
	if !strings.Contains(body, "AA:BB:CC:00:1B:02") {
		t.Error("blocked MAC missing from status=blocked export")
	}
	if strings.Contains(body, "AA:BB:CC:00:1B:01") {
		t.Error("active MAC leaked into status=blocked export")
	}
}

func TestAdminExportMACsFilterByUserID(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800330001", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:1B:03", "mine", 30, &u.ID)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:1B:04", "theirs", 30, nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/macs.csv?user_id="+strconv.FormatInt(u.ID, 10), nil, jar)
	if !strings.Contains(body, "AA:BB:CC:00:1B:03") {
		t.Error("user-owned MAC missing from user_id export")
	}
	if strings.Contains(body, "AA:BB:CC:00:1B:04") {
		t.Error("unowned MAC leaked into user_id-filtered export")
	}
}

// q substring filter (mac or label).
func TestAdminExportMACsFilterByQ(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:1B:05", "marketing-phone", 30, nil)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:1B:06", "engineering", 30, nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/macs.csv?q=marketing", nil, jar)
	if !strings.Contains(body, "marketing-phone") {
		t.Error("label match missing")
	}
	if strings.Contains(body, "engineering") {
		t.Error("non-match label leaked")
	}
}

func TestAdminExportMACsFilenameFlavor(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/export/macs.csv", nil, jar)
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, `"macs.csv"`) {
		t.Errorf("unfiltered should be macs.csv; got %q", cd)
	}
	res, _ = do(t, h, "GET", "/admin/export/macs.csv?status=active", nil, jar)
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "macs-filtered.csv") {
		t.Errorf("filtered should be macs-filtered.csv; got %q", cd)
	}
}

// /admin/macs page export link should pass q/status through.
func TestAdminMacsPageExportLinkHonorsFilters(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs?q=AB&status=active", nil, jar)
	if !strings.Contains(body, "/admin/export/macs.csv?q=AB&status=active") {
		t.Error("export link should pass q + status through")
	}
	if !strings.Contains(body, "导出筛选 MAC") {
		t.Error("filtered export label missing")
	}
}
