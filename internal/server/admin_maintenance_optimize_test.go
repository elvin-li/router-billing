package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestAdminOptimizeNowRunsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/maintenance/optimize-now",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=optimize_now") {
		t.Errorf("redirect should signal success; got %s", loc)
	}
	if !strings.Contains(loc, "ms=") {
		t.Error("redirect should include ms= duration")
	}

	// Audit row with elapsed time.
	entries, _ := app.DB.ListAudit(context.Background(), 5)
	found := false
	for _, e := range entries {
		if e.Action == "optimize_now" {
			found = true
			if !strings.Contains(e.Detail, "ms=") {
				t.Errorf("audit should record ms=; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("optimize_now audit row missing")
	}
}

func TestAdminOptimizeNowRejectsGET(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/maintenance/optimize-now", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("GET should redirect (not fire); got %d", res.StatusCode)
	}
}

func TestAdminMaintenancePageShowsOptimizeButton(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/maintenance", nil, jar)
	if !strings.Contains(body, "/admin/maintenance/optimize-now") {
		t.Error("page missing optimize-now form")
	}
	if !strings.Contains(body, "PRAGMA optimize") {
		t.Error("page should label the button clearly")
	}
}
