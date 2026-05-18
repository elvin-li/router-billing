package server

import (
	"context"
	"strings"
	"testing"
)

func TestAdminExportAuditCSVShape(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin", "extend", "AA:BB:CC:00:00:01", "days=30 ip=10.0.0.1")
	app.DB.Audit(ctx, "user:13800100000", "login", "", "ip=10.0.0.2")

	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/export/audit.csv", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Errorf("content-type: %s", ct)
	}
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "audit.csv") {
		t.Errorf("content-disposition: %s", cd)
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected header + 2+ rows; got %d", len(lines))
	}
	// Header row.
	for _, want := range []string{"id", "at", "actor", "action", "target", "detail"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("header missing %q", want)
		}
	}
	if !strings.Contains(body, "extend") {
		t.Error("body should include 'extend' action")
	}
	if !strings.Contains(body, "AA:BB:CC:00:00:01") {
		t.Error("body should include the target MAC")
	}
}

func TestAdminExportAuditHonorsFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin", "extend", "AA:BB:CC:00:00:01", "")
	app.DB.Audit(ctx, "user:13800100001", "login", "", "")
	app.DB.Audit(ctx, "admin", "revoke", "AA:BB:CC:00:00:02", "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/audit.csv?action=login", nil, jar)
	if !strings.Contains(body, "login") {
		t.Error("filtered csv should include login row")
	}
	if strings.Contains(body, "extend") || strings.Contains(body, "revoke") {
		t.Error("action=login filter should exclude extend/revoke")
	}
}

func TestAdminAuditPageLinksCSVExport(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/audit?action=login", nil, jar)
	if !strings.Contains(body, "/admin/export/audit.csv") {
		t.Error("page should link to the CSV export")
	}
}
