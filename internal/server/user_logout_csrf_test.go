package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// registerUserJar registers a fresh user and returns a cookie jar carrying
// both the rb_user session cookie and the rb_csrf cookie.
func registerUserJar(t *testing.T, h http.Handler, phone string) map[string]string {
	t.Helper()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {phone}, "password": {"secret123"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register: %d", res.StatusCode)
	}
	jar := cookieJar(res)
	if jar["rb_user"] == "" {
		t.Fatal("no rb_user cookie after register")
	}
	// Touch a page to make sure an rb_csrf cookie is present.
	res, _ = do(t, h, "GET", "/user/me", nil, jar)
	for k, v := range cookieJar(res) {
		jar[k] = v
	}
	if jar[csrfCookieName] == "" {
		t.Fatal("no rb_csrf cookie")
	}
	return jar
}

// GET /user/logout must NOT end the session: SameSite=Lax cookies ride along
// on top-level cross-site GET navigations and on speculative link prefetches,
// so a GET logout was both a CSRF-logout vector and a footgun. Mirrors the
// v0.108 admin logout hardening, which had been applied to /admin/logout but
// not to the user path.
func TestUserLogoutGETKeepsSession(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerUserJar(t, h, "13800130001")

	res, _ := do(t, h, "GET", "/user/logout", nil, jar)
	if res.StatusCode != 303 {
		t.Fatalf("GET /user/logout: %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/user/me" {
		t.Errorf("GET logout should bounce to /user/me, got %q", loc)
	}
	// Session must still be alive.
	res, _ = do(t, h, "GET", "/user/me", nil, jar)
	if res.StatusCode != 200 {
		t.Errorf("session killed by GET logout: /user/me = %d, want 200", res.StatusCode)
	}
}

// POST /user/logout without a CSRF token is rejected and keeps the session.
func TestUserLogoutPOSTRequiresCSRF(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerUserJar(t, h, "13800130002")

	res, _ := do(t, h, "POST", "/user/logout", url.Values{}, jar)
	if res.StatusCode != 403 {
		t.Fatalf("POST logout without CSRF: %d, want 403", res.StatusCode)
	}
	res, _ = do(t, h, "GET", "/user/me", nil, jar)
	if res.StatusCode != 200 {
		t.Errorf("session killed by rejected logout: /user/me = %d, want 200", res.StatusCode)
	}
}

// POST /user/logout with a valid CSRF token logs out and kills the session.
func TestUserLogoutPOSTWithCSRF(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerUserJar(t, h, "13800130003")

	res, _ := do(t, h, "POST", "/user/logout",
		url.Values{"_csrf": {jar[csrfCookieName]}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("POST logout with CSRF: %d, want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/portal" {
		t.Errorf("logout should bounce to /portal, got %q", loc)
	}
	// Session should be dead: /user/me now redirects to the login page.
	res, _ = do(t, h, "GET", "/user/me", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("session should be dead after logout: /user/me = %d, want 303", res.StatusCode)
	}
}

// The account page renders logout as a POST form with a CSRF field, not a
// GET link that a prefetch or cross-site navigation could trigger.
func TestUserMeLogoutIsPOSTForm(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerUserJar(t, h, "13800130004")

	_, body := do(t, h, "GET", "/user/me", nil, jar)
	if !strings.Contains(body, `action="/user/logout"`) {
		t.Error("account page missing the logout POST form")
	}
	if strings.Contains(body, `href="/user/logout"`) {
		t.Error("account page still renders logout as a GET link")
	}
}
