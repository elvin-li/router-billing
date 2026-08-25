package server

import (
	"net/url"
	"strings"
	"testing"
)

func TestSafeNextPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "/user/me"},
		{"/user/orders", "/user/orders"},
		{"/user/me?tab=devices", "/user/me?tab=devices"},
		{"/", "/"},
		// Protocol-relative → external navigation in browsers.
		{"//evil.com", "/user/me"},
		{"//evil.com/user/me", "/user/me"},
		// Some browsers normalize backslash to slash before resolving.
		{"/\\evil.com", "/user/me"},
		{"/user\\me", "/user/me"},
		// Absolute URLs.
		{"https://evil.com", "/user/me"},
		{"http://evil.com/", "/user/me"},
		// Header-injection characters.
		{"/user/me\r\nSet-Cookie: x=1", "/user/me"},
	}
	for _, c := range cases {
		if got := safeNextPath(c.in, "/user/me"); got != c.want {
			t.Errorf("safeNextPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Regression (v0.99): login accepted any next with a leading "/" —
// "//evil.com" is protocol-relative, so the 303 bounced the freshly
// authenticated user to an attacker-chosen external domain.
func TestUserLoginNextOpenRedirectBlocked(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	registerAndLogin(t, h, "13800139101", "redirect-pw")

	for _, evil := range []string{"//evil.com", "/\\evil.com", "https://evil.com"} {
		res, _ := do(t, h, "POST", "/user/login",
			url.Values{"phone": {"13800139101"}, "password": {"redirect-pw"}, "next": {evil}}, nil)
		if res.StatusCode != 303 {
			t.Fatalf("login with next=%q: status %d", evil, res.StatusCode)
		}
		if loc := res.Header.Get("Location"); loc != "/user/me" {
			t.Errorf("next=%q redirected to %q, want /user/me", evil, loc)
		}
	}

	// Legitimate same-site next still works.
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139101"}, "password": {"redirect-pw"}, "next": {"/user/orders"}}, nil)
	if loc := res.Header.Get("Location"); loc != "/user/orders" {
		t.Errorf("good next redirected to %q, want /user/orders", loc)
	}
}

// The login form GET must not echo a hostile next back into the hidden field.
func TestUserLoginFormSanitizesNext(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, body := do(t, h, "GET", "/user/login?next=//evil.com", nil, nil)
	if strings.Contains(body, "//evil.com") {
		t.Error("login form echoed the hostile next value")
	}
}

// Regression (v0.99): the 2FA login handler read next from the query string
// with no validation at all — a crafted login link could bounce the user to
// an external phishing domain right after they proved their identity.
func TestUser2FALoginNextOpenRedirectBlocked(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139102", "redirect2fa-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139102")
	do(t, h, "POST", "/user/2fa/confirm", url.Values{"_csrf": {csrf}, "code": {code}}, jar)
	// Confirm consumed this timestep (one-time use); the login below
	// legitimately reuses it inside the same 30s step.
	resetTOTPReplay()

	// Fresh browser: password → pending cookie.
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139102"}, "password": {"redirect2fa-pw"}}, nil)
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	csrf2 := pending[csrfCookieName]

	code2 := validTOTPForUser(t, app, "13800139102")
	res3, _ := do(t, h, "POST", "/user/login/2fa?next="+url.QueryEscape("https://evil.com"),
		url.Values{"code": {code2}, "_csrf": {csrf2}}, pending)
	if res3.StatusCode != 303 {
		t.Fatalf("2fa verify: %d", res3.StatusCode)
	}
	if loc := res3.Header.Get("Location"); loc != "/user/me" {
		t.Errorf("hostile 2fa next redirected to %q, want /user/me", loc)
	}
}

// Regression (v0.99): /admin/resync accepted GET, and verifyCSRF skips
// non-POST — so a cross-site <img src=/admin/resync> could trigger a
// firewall rebuild with the admin's SameSite=Lax cookie riding along.
func TestAdminResyncRejectsGET(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, _ := do(t, h, "GET", "/admin/resync", nil, jar)
	if res.StatusCode != 405 {
		t.Fatalf("GET /admin/resync status = %d, want 405", res.StatusCode)
	}
	// No resync audit row was written.
	rows, err := app.DB.ListAudit(contextForTest(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if strings.Contains(row.Action, "firewall_resync") {
			t.Errorf("GET still executed resync: %+v", row)
		}
	}

	// POST with CSRF still works.
	res2, _ := do(t, h, "POST", "/admin/resync",
		url.Values{"_csrf": {jar[csrfCookieName]}}, jar)
	if res2.StatusCode != 303 {
		t.Fatalf("POST /admin/resync status = %d, want 303", res2.StatusCode)
	}
	if loc := res2.Header.Get("Location"); loc != "/admin/macs?ok=1" {
		t.Errorf("POST redirect = %q, want /admin/macs?ok=1", loc)
	}
}
