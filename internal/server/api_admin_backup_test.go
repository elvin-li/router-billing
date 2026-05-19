package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIBackupReturnsValidSQLite(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "GET", "/api/admin/backup", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	// SQLite files start with the exact magic header "SQLite format 3\x00".
	body := rr.Body.Bytes()
	want := "SQLite format 3\x00"
	if !strings.HasPrefix(string(body), want) {
		t.Errorf("response body should start with SQLite magic; got first 32 bytes=%q",
			string(body[:min(32, len(body))]))
	}
	// Content-Type + filename hints.
	ct := rr.Header().Get("Content-Type")
	if ct != "application/x-sqlite3" {
		t.Errorf("Content-Type wrong: %q", ct)
	}
	cd := rr.Header().Get("Content-Disposition")
	if !strings.Contains(cd, `attachment; filename="billing-`) {
		t.Errorf("Content-Disposition wrong: %q", cd)
	}
}

func TestAPIBackupAuditRowMarksViaAPI(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	apiReq(t, h, "GET", "/api/admin/backup", "rb_w", "")

	entries, _ := app.DB.ListAudit(context.Background(), 5)
	found := false
	for _, e := range entries {
		if e.Action == "backup" {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit detail should mark via=api; got %q", e.Detail)
			}
			if !strings.Contains(e.Detail, "size=") {
				t.Errorf("audit detail should record size=; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("backup audit row missing")
	}
}

func TestAPIBackupReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/backup", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly GET should be 200; got %d", rr.Code)
	}
}

func TestAPIBackupRejectsPOST(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/backup", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("POST should be 405; got %d", rr.Code)
	}
}
