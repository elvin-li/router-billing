package server

import (
	"net/url"
	"strings"
	"testing"
)

func TestSafeNextPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/user/me"},
		{"/user/2fa", "/user/2fa"},
		{"/portal?mac=AA:BB:CC:DD:EE:FF", "/portal?mac=AA:BB:CC:DD:EE:FF"},
		{"//evil.com", "/user/me"},
		{"//evil.com/phish", "/user/me"},
		{"/\\evil.com", "/user/me"},
		{"https://evil.com", "/user/me"},
		{"http://evil.com", "/user/me"},
		{"evil.com", "/user/me"},
		{"javascript:alert(1)", "/user/me"},
	}
	for _, c := range cases {
		if got := safeNextPath(c.in, "/user/me"); got != c.want {
			t.Errorf("safeNextPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// End-to-end: login POST with a hostile next must not bounce off-site.
func TestUserLoginRejectsOpenRedirect(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Register a user first (register auto-logs-in but we exercise login).
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800138000"}, "password": {"hunter22"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register: %d", res.StatusCode)
	}

	res, _ = do(t, h, "POST", "/user/login", url.Values{
		"phone":    {"13800138000"},
		"password": {"hunter22"},
		"next":     {"//evil.com/phish"},
	}, nil)
	loc := res.Header.Get("Location")
	if strings.Contains(loc, "evil.com") {
		t.Fatalf("open redirect: Location=%q", loc)
	}
	if loc != "/user/me" {
		t.Errorf("want fallback /user/me, got %q", loc)
	}
}
