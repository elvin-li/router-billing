package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

// GET /admin/logout must NOT end the session (v0.108): SameSite=Lax cookies
// ride along on top-level cross-site GET navigations and on speculative link
// prefetches, so a GET logout was both a CSRF logout vector and a footgun.
func TestAdminLogoutGETKeepsSession(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, _ := do(t, h, "GET", "/admin/logout", nil, jar)
	if res.StatusCode != 303 {
		t.Fatalf("GET /admin/logout: %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/admin/dashboard" {
		t.Errorf("GET logout should bounce to dashboard, got %q", loc)
	}
	// Session must still be alive.
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar)
	if res.StatusCode != 200 {
		t.Errorf("session killed by GET logout: /admin/macs = %d, want 200", res.StatusCode)
	}
}

// POST /admin/logout without a CSRF token is rejected and keeps the session.
func TestAdminLogoutPOSTRequiresCSRF(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, _ := do(t, h, "POST", "/admin/logout", url.Values{}, jar)
	if res.StatusCode != 403 {
		t.Fatalf("POST logout without CSRF: %d, want 403", res.StatusCode)
	}
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar)
	if res.StatusCode != 200 {
		t.Errorf("session killed by rejected logout: /admin/macs = %d, want 200", res.StatusCode)
	}
}

// POST /admin/logout with a valid CSRF token logs out and kills the session.
func TestAdminLogoutPOSTWithCSRF(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, _ := do(t, h, "POST", "/admin/logout",
		url.Values{"_csrf": {jar[csrfCookieName]}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("POST logout with CSRF: %d, want 303", res.StatusCode)
	}
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("session should be dead after logout: /admin/macs = %d, want 303", res.StatusCode)
	}
}

// The sidebar renders logout as a POST form with a CSRF field, not a GET link.
func TestAdminSidebarLogoutIsPOSTForm(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/dashboard", nil, jar)
	if !strings.Contains(body, `action="/admin/logout"`) {
		t.Error("sidebar missing the logout POST form")
	}
	if strings.Contains(body, `href="/admin/logout"`) {
		t.Error("sidebar still renders logout as a GET link")
	}
}

// /admin/login?err=… codes from the 2FA flow are surfaced on the GET render.
// Pre-v0.108 they were silently dropped, so an expired pending-2FA session
// bounced the admin to a blank form with no explanation.
func TestAdminLoginSurfaces2FAErrCodes(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	cases := map[string]string{
		"2fa_expired":       "二步验证会话已过期",
		"2fa_locked":        "验证码错误次数过多",
		"2fa_misconfigured": "二步验证配置异常",
	}
	for code, want := range cases {
		_, body := do(t, h, "GET", "/admin/login?err="+code, nil, nil)
		if !strings.Contains(body, want) {
			t.Errorf("login?err=%s missing %q", code, want)
		}
	}
	// Unknown / absent codes render a clean form (no stray text).
	_, body := do(t, h, "GET", "/admin/login?err=bogus_code", nil, nil)
	if strings.Contains(body, "bogus_code") {
		t.Error("unknown err code must not be echoed into the page")
	}
}

// The 最近在线 pill on /admin/macs/detail reflects RECENCY (10-minute window),
// not merely the existence of a sighting row. Pre-v0.108 a device last seen
// weeks ago still showed a green 在线 pill.
func TestMACDetailSightingPillFreshVsStale(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:44:01", "fresh-dev", 30, nil)
	_, _ = app.DB.Exec(ctx, `INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen)
		VALUES ('AA:BB:CC:00:44:01', '192.168.5.10', 'fresh', ?, ?)`,
		now.Add(-time.Hour), now.Add(-2*time.Minute))

	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:44:02", "stale-dev", 30, nil)
	_, _ = app.DB.Exec(ctx, `INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen)
		VALUES ('AA:BB:CC:00:44:02', '192.168.5.11', 'stale', ?, ?)`,
		now.Add(-72*time.Hour), now.Add(-48*time.Hour))

	h := app.Routes()
	jar := loginAdmin(t, h)

	_, body := do(t, h, "GET", "/admin/macs/detail?mac=AA:BB:CC:00:44:01", nil, jar)
	if !strings.Contains(body, ">在线</span>") {
		t.Error("fresh sighting (2 min ago) should render the 在线 pill")
	}

	_, body = do(t, h, "GET", "/admin/macs/detail?mac=AA:BB:CC:00:44:02", nil, jar)
	if strings.Contains(body, ">在线</span>") {
		t.Error("stale sighting (48h ago) must not render the 在线 pill")
	}
	if !strings.Contains(body, ">离线</span>") {
		t.Error("stale sighting should render the 离线 pill")
	}
}

// Filtered CSV exports advertise it in the filename so a truncated download
// isn't mistaken for the full dataset.
func TestExportFilenamesReflectFilters(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	cases := []struct{ path, want string }{
		{"/admin/export/orders.csv", `filename="orders.csv"`},
		{"/admin/export/orders.csv?status=paid", `filename="orders-filtered.csv"`},
		{"/admin/export/audit.csv", `filename="audit.csv"`},
		{"/admin/export/audit.csv?action=login", `filename="audit-filtered.csv"`},
	}
	for _, c := range cases {
		res, _ := do(t, h, "GET", c.path, nil, jar)
		if res.StatusCode != 200 {
			t.Errorf("%s: status %d", c.path, res.StatusCode)
			continue
		}
		if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, c.want) {
			t.Errorf("%s: Content-Disposition %q, want %q", c.path, cd, c.want)
		}
	}
}

// MAC export search post-filter is case-insensitive, matching the
// case-insensitive SQL LIKE used by the /admin/macs page itself.
func TestExportMACsSearchCaseInsensitive(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:55:01", "Office-Printer", 30, nil)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/macs.csv?q=office", nil, jar)
	if !strings.Contains(body, "AA:BB:CC:00:55:01") {
		t.Error("lowercase query should match mixed-case label in MAC export")
	}
}
