package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestBuildHSTSHeaderDefaults(t *testing.T) {
	// Zero config → 1-year max-age, no extras.
	got := buildHSTSHeader(config.Security{})
	if got != "max-age=31536000" {
		t.Errorf("default HSTS: got %q", got)
	}
}

func TestBuildHSTSHeaderCustomMaxAge(t *testing.T) {
	got := buildHSTSHeader(config.Security{HSTSMaxAgeSeconds: 63072000})
	if got != "max-age=63072000" {
		t.Errorf("custom HSTS: got %q", got)
	}
}

func TestBuildHSTSHeaderWithSubdomainsAndPreload(t *testing.T) {
	got := buildHSTSHeader(config.Security{
		HSTSMaxAgeSeconds:     63072000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           true,
	})
	for _, want := range []string{"max-age=63072000", "includeSubDomains", "preload"} {
		if !strings.Contains(got, want) {
			t.Errorf("HSTS should include %q; got %q", want, got)
		}
	}
}

func TestBuildHSTSHeaderNegativeMaxAgeFallsBackToDefault(t *testing.T) {
	got := buildHSTSHeader(config.Security{HSTSMaxAgeSeconds: -1})
	if got != "max-age=31536000" {
		t.Errorf("negative max-age should fallback to default; got %q", got)
	}
}

func TestSecurityHeadersAppliesHSTSWhenTLS(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security = config.Security{
		HSTSMaxAgeSeconds:     63072000,
		HSTSIncludeSubdomains: true,
	}
	h := app.Routes()
	res, _ := do(t, h, "GET", "/portal", nil, map[string]string{})
	// Without TLS / X-Forwarded-Proto, HSTS is NOT set (correct — we don't
	// want to burn the directive on an HTTP-only deploy).
	if hsts := res.Header.Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS shouldn't be set on plain HTTP; got %q", hsts)
	}
}

func TestSecurityHeadersHSTSFiresWithForwardedProtoHTTPS(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security = config.Security{
		HSTSMaxAgeSeconds:     63072000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           true,
	}
	h := app.Routes()

	// Build a request with X-Forwarded-Proto: https (the typical reverse-
	// proxy signal that the upstream is TLS).
	req := httptest.NewRequest("GET", "/portal", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()

	hsts := res.Header.Get("Strict-Transport-Security")
	for _, want := range []string{"max-age=63072000", "includeSubDomains", "preload"} {
		if !strings.Contains(hsts, want) {
			t.Errorf("HSTS should include %q; got %q", want, hsts)
		}
	}
}

// clientIPThroughMiddleware runs one request through realIPMiddleware and
// reports what clientIP resolved.
func clientIPThroughMiddleware(t *testing.T, app *App, remoteAddr, xff string) string {
	t.Helper()
	got := ""
	h := app.realIPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = clientIP(r)
	}))
	req := httptest.NewRequest("GET", "/portal", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestClientIPIgnoresForwardedForByDefault(t *testing.T) {
	// No trusted_proxies configured → X-Forwarded-For is plain client input
	// and must never override RemoteAddr. Pre-v0.106 the header's first
	// entry won, so any direct client could rotate a fake IP per request
	// and sidestep every per-IP rate limit.
	app := setupTestApp(t)
	if got := clientIPThroughMiddleware(t, app, "203.0.113.7:5555", "6.6.6.6"); got != "203.0.113.7" {
		t.Errorf("spoofed XFF should be ignored; got %q", got)
	}
	if got := clientIPThroughMiddleware(t, app, "203.0.113.7:5555", ""); got != "203.0.113.7" {
		t.Errorf("plain request: got %q, want RemoteAddr host", got)
	}
}

func TestClientIPTrustsForwardedForFromTrustedProxyOnly(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security.TrustedProxies = []string{"10.0.0.1", "192.168.0.0/16"}

	// From the trusted proxy: the LAST entry (appended by the proxy) wins —
	// a client-prepended fake stays ignored.
	if got := clientIPThroughMiddleware(t, app, "10.0.0.1:9999", "6.6.6.6, 203.0.113.50"); got != "203.0.113.50" {
		t.Errorf("trusted proxy: got %q, want last XFF entry", got)
	}
	// CIDR entries match too.
	if got := clientIPThroughMiddleware(t, app, "192.168.3.4:80", "203.0.113.51"); got != "203.0.113.51" {
		t.Errorf("trusted CIDR: got %q", got)
	}
	// From anyone else the header stays ignored.
	if got := clientIPThroughMiddleware(t, app, "203.0.113.7:5555", "6.6.6.6"); got != "203.0.113.7" {
		t.Errorf("untrusted peer: got %q, want RemoteAddr host", got)
	}
	// Garbage header values from the trusted proxy fall back to RemoteAddr.
	if got := clientIPThroughMiddleware(t, app, "10.0.0.1:9999", "not-an-ip,,"); got != "10.0.0.1" {
		t.Errorf("garbage XFF: got %q, want proxy host", got)
	}
}

func TestForwardedForCannotRotateRateLimitKeys(t *testing.T) {
	// End-to-end: the register limiter is keyed per IP. A client stamping a
	// fresh X-Forwarded-For per request must still exhaust its budget.
	app := setupTestApp(t)
	app.registerLimiter = newRateLimiter(2, 3600e9)
	h := app.Routes()

	register := func(phone, xff string) *http.Response {
		form := url.Values{"phone": {phone}, "password": {"some-pw-123"}}
		req := httptest.NewRequest("POST", "/user/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", xff)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Result()
	}

	register("13800139070", "10.9.9.1")
	register("13800139071", "10.9.9.2")
	res := register("13800139072", "10.9.9.3")
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "rate_limited") {
		t.Errorf("3rd register with rotated XFF should be rate-limited; got %s", loc)
	}
}

func TestLoginUnknownPhoneBurnsBcryptCost(t *testing.T) {
	// The unknown-phone path must run a dummy bcrypt comparison so its
	// response time is indistinguishable from a wrong-password attempt.
	// bcrypt at DefaultCost takes tens of ms; pre-fix the path returned in
	// well under a millisecond. Assert a conservative lower bound only —
	// no flaky upper-bound comparisons.
	app := setupTestApp(t)
	h := app.Routes()

	start := time.Now()
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800130999"}, "password": {"whatever-pw"}}, nil)
	elapsed := time.Since(start)

	if loc := res.Header.Get("Location"); !strings.Contains(loc, "bad_credentials") {
		t.Fatalf("unknown phone should redirect bad_credentials; got %s", loc)
	}
	if elapsed < 5*time.Millisecond {
		t.Errorf("unknown-phone login returned in %v — dummy bcrypt compare missing?", elapsed)
	}
}

func TestParseTrustedProxiesSkipsGarbage(t *testing.T) {
	nets := parseTrustedProxies([]string{"", "  ", "10.0.0.1", "not-a-net", "192.168.0.0/16", "::1"})
	if len(nets) != 3 {
		t.Fatalf("expected 3 parsed entries; got %d", len(nets))
	}
}

func TestSecurityHeadersCommonHeadersAlwaysSet(t *testing.T) {
	// CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
	// Permissions-Policy should fire on every response, TLS or not.
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "GET", "/portal", nil, nil)
	for _, header := range []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Content-Security-Policy",
	} {
		if v := res.Header.Get(header); v == "" {
			t.Errorf("%s should be set on every response", header)
		}
	}
}
