package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

// /admin/maintenance/expire-now should mark every active MAC whose
// expires_at is in the past as expired, AND write an audit row carrying
// the count.
func TestAdminExpireNowFlipsDueMAC(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// Seed an active MAC with an already-elapsed expiry so the sweep has
	// something to do.
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:FA", "victim", 30, nil); err != nil {
		t.Fatal(err)
	}
	_, _ = app.DB.Exec(ctx,
		`UPDATE macs SET expires_at = ? WHERE mac = ?`,
		time.Now().UTC().Add(-time.Hour), "AA:BB:CC:DD:EE:FA")

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/maintenance/expire-now",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=expire_now") || !strings.Contains(loc, "expired=1") {
		t.Errorf("redirect should report expired=1; got %s", loc)
	}

	// MAC should have transitioned to expired.
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:FA")
	if m == nil || m.Status != "expired" {
		t.Errorf("MAC should be expired; got %+v", m)
	}

	// Audit row with count.
	entries, _ := app.DB.ListAudit(ctx, 10)
	found := false
	for _, e := range entries {
		if e.Action == "expire_now" {
			found = true
			if !strings.Contains(e.Detail, "expired=1") {
				t.Errorf("audit detail should include expired=1; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("expire_now audit row missing")
	}
}

func TestAdminAuditTrimRunsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// Seed many rows so the trim has something to do (cap defaults to
	// 10000 — for testing override to a tiny number).
	app.Cfg.Security.AuditLogKeep = 5
	for i := 0; i < 20; i++ {
		app.DB.Audit(ctx, "test", "spam", "tgt", "row")
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/maintenance/audit-trim",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=audit_trim") {
		t.Errorf("missing ok=audit_trim redirect; got %s", res.Header.Get("Location"))
	}

	// Should have ≤ keep+1 rows now (the trim itself adds one audit_trim row).
	n, _ := app.DB.CountAudit(ctx)
	keep := app.Cfg.Security.AuditLogRetention()
	if n > keep+1 {
		t.Errorf("expected audit log trimmed to ~%d rows; have %d", keep, n)
	}
}

// Both new handlers reject GET so the CSRF-protected POST is the only way
// to trigger them. Otherwise a browser preload of a /admin/maintenance/...
// URL could accidentally fire the sweep.
func TestAdminMaintenanceTriggersRejectGET(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	for _, p := range []string{
		"/admin/maintenance/expire-now",
		"/admin/maintenance/audit-trim",
	} {
		res, _ := do(t, h, "GET", p, nil, jar)
		// 303 is the GET handler's "go back to the page" redirect; never
		// a 200 (which would mean we actually performed the action).
		if res.StatusCode != 303 {
			t.Errorf("%s GET should redirect; got %d", p, res.StatusCode)
		}
	}
}

func TestAdminMaintenancePageShowsTriggerButtons(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/maintenance", nil, jar)
	for _, want := range []string{
		"/admin/maintenance/expire-now",
		"/admin/maintenance/audit-trim",
		"立即执行到期扫描",
		"立即裁剪审计日志",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("maintenance page missing %q", want)
		}
	}
}
