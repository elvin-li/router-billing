package server

import (
	"context"
	"strings"
	"testing"
)

func TestAdminExportUsersFilterByQ(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.CreateUser(ctx, "13800320001", "h")
	_, _ = app.DB.CreateUser(ctx, "13900320001", "h")

	h := app.Routes()
	jar := loginAdmin(t, h)
	// Only 138 prefix should appear.
	_, body := do(t, h, "GET", "/admin/export/users.csv?q=138", nil, jar)
	if !strings.Contains(body, "13800320001") {
		t.Error("expected 138-prefix user in CSV")
	}
	if strings.Contains(body, "13900320001") {
		t.Error("non-matching user leaked into filtered CSV")
	}
}

func TestAdminExportUsersFilterBySuspended(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u1, _ := app.DB.CreateUser(ctx, "13800320010", "h")
	_, _ = app.DB.CreateUser(ctx, "13800320011", "h")
	_ = app.DB.SuspendUser(ctx, u1.ID, true)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/users.csv?suspended=1", nil, jar)
	if !strings.Contains(body, "13800320010") {
		t.Error("suspended user missing from suspended=1 export")
	}
	if strings.Contains(body, "13800320011") {
		t.Error("active user leaked into suspended=1 export")
	}
}

// Filename should reflect that filters are applied so the download is
// self-describing.
func TestAdminExportUsersFilenameFlavor(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	// No filter → plain users.csv.
	res, _ := do(t, h, "GET", "/admin/export/users.csv", nil, jar)
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, `"users.csv"`) {
		t.Errorf("no-filter filename should be users.csv; got %q", cd)
	}
	// With filter → users-filtered.csv.
	res, _ = do(t, h, "GET", "/admin/export/users.csv?suspended=1", nil, jar)
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "users-filtered.csv") {
		t.Errorf("filtered export filename should be users-filtered.csv; got %q", cd)
	}
}

// /admin/users page's export link should carry q through.
func TestAdminUsersPageExportLinkHonorsQuery(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/users?q=138", nil, jar)
	if !strings.Contains(body, "/admin/export/users.csv?q=138") {
		t.Error("export link should embed the current q filter")
	}
	if !strings.Contains(body, "导出筛选结果") {
		t.Error("export label should switch to '导出筛选结果' when filter is active")
	}
}
