package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/db"
	"router-billing/internal/firewall"
	"router-billing/internal/service"
)

// webRoot finds the project's web/ directory regardless of where `go test`
// runs from.
func webRoot(t *testing.T) string {
	t.Helper()
	_, this, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(this), "..", "..", "web")
	if _, err := os.Stat(filepath.Join(root, "templates", "portal.html")); err != nil {
		t.Skip("web/ not found relative to this file — skipping integration test")
	}
	return root
}

func setupTestApp(t *testing.T) *App {
	t.Helper()
	root := webRoot(t)
	dir := t.TempDir()
	dbx, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbx.Close() })

	fw := firewall.New("inet", "billing", "mac_paid", "br-paid")
	fw.SetDryRun(true)
	svc := service.New(dbx, fw)

	cfg := &config.Config{
		Listen:    ":0",
		DBPath:    filepath.Join(dir, "test.db"),
		WebRoot:   root,
		PaidIface: "br-paid",
		Admin:     config.Admin{Username: "admin", Password: "admin-pw"},
		Plans: map[string]config.Plan{
			"month": {Label: "1 个月", Days: 30, PriceCents: 100},
		},
	}

	app, err := NewApp(cfg, dbx, svc)
	if err != nil {
		t.Fatal(err)
	}
	app.Version = "test"
	return app
}

// do issues a request through the full middleware chain (security headers +
// csrf + log + routes). Returns the response and body string.
func do(t *testing.T, h http.Handler, method, path string, form url.Values, cookies map[string]string) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func cookieJar(res *http.Response) map[string]string {
	out := map[string]string{}
	for _, c := range res.Cookies() {
		out[c.Name] = c.Value
	}
	return out
}

func TestPortalRenders(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, body := do(t, h, "GET", "/portal", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("portal: %d", res.StatusCode)
	}
	for _, want := range []string{"WiFi 上网认证", "1 个月", "充值码", "</html>"} {
		if !strings.Contains(body, want) {
			t.Errorf("portal missing %q", want)
		}
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options header")
	}
	if !strings.Contains(res.Header.Get("Set-Cookie"), "rb_csrf=") {
		t.Error("expected rb_csrf cookie on portal")
	}
}

func TestAdminLoginFlow(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Unauthed → redirect to login
	res, _ := do(t, h, "GET", "/admin/macs", nil, nil)
	if res.StatusCode != 303 {
		t.Errorf("unauth /admin/macs: %d, want 303", res.StatusCode)
	}

	// Bad creds
	res, _ = do(t, h, "POST", "/admin/login", url.Values{"username": {"admin"}, "password": {"wrong"}}, nil)
	if res.StatusCode != 200 {
		t.Errorf("bad login: %d (expect inline render)", res.StatusCode)
	}

	// Good creds
	res, _ = do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("good login: %d, want 303", res.StatusCode)
	}
	jar := cookieJar(res)
	if jar["rb_admin"] == "" {
		t.Fatal("no rb_admin cookie set")
	}

	// Authed
	res, body := do(t, h, "GET", "/admin/macs", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("authed /admin/macs: %d", res.StatusCode)
	}
	if !strings.Contains(body, "MAC 管理") {
		t.Error("expected '/admin/macs' to render admin shell")
	}
}

func TestCSRFEnforcedOnAdminPost(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	jar := cookieJar(res)

	// Get a CSRF cookie by visiting any page
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar)
	csrfJar := cookieJar(res)
	for k, v := range jar {
		csrfJar[k] = v
	}

	// POST without _csrf → 403
	res, _ = do(t, h, "POST", "/admin/macs/add",
		url.Values{"mac": {"aa:bb:cc:dd:ee:ff"}, "days": {"30"}}, csrfJar)
	if res.StatusCode != 403 {
		t.Errorf("POST without csrf: %d, want 403", res.StatusCode)
	}

	// POST with _csrf → 303
	tok := csrfJar["rb_csrf"]
	res, _ = do(t, h, "POST", "/admin/macs/add",
		url.Values{"mac": {"aa:bb:cc:dd:ee:ff"}, "days": {"30"}, "_csrf": {tok}}, csrfJar)
	if res.StatusCode != 303 {
		t.Errorf("POST with csrf: %d, want 303", res.StatusCode)
	}
	// Verify MAC landed in DB
	m, _ := app.DB.GetMAC(context.Background(), "AA:BB:CC:DD:EE:FF")
	if m == nil {
		t.Fatal("MAC not inserted")
	}
}

func TestUserRegisterLoginLogout(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Register
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800138888"}, "password": {"secret123"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register: %d", res.StatusCode)
	}
	jar := cookieJar(res)
	if jar["rb_user"] == "" {
		t.Fatal("no rb_user cookie")
	}

	// Authed /user/me
	res, body := do(t, h, "GET", "/user/me", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("/user/me: %d", res.StatusCode)
	}
	if !strings.Contains(body, "13800138888") {
		t.Error("phone not shown on /user/me")
	}

	// Logout
	res, _ = do(t, h, "GET", "/user/logout", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("logout: %d", res.StatusCode)
	}

	// Bad phone format
	res, _ = do(t, h, "POST", "/user/register",
		url.Values{"phone": {"12345"}, "password": {"secret123"}}, nil)
	if res.StatusCode != 303 {
		t.Errorf("bad phone: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "err=bad_phone") {
		t.Errorf("bad phone location: %s", loc)
	}
}

func TestVoucherFullFlow(t *testing.T) {
	ctx := context.Background()
	app := setupTestApp(t)
	h := app.Routes()

	// Admin generates a voucher directly via DB
	_, err := app.DB.CreateVoucher(ctx, "TESTCDE23456", 30, "lab", "batch-test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Anonymous redeem (no auth needed)
	res, _ := do(t, h, "POST", "/redeem",
		url.Values{"code": {"TEST-CDE2-3456"}, "mac": {"aa:bb:cc:dd:ee:ff"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("redeem: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=1") {
		t.Errorf("redeem location: %s", loc)
	}

	// MAC was granted with 30 days
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:FF")
	if m == nil {
		t.Fatal("MAC not granted")
	}
	if m.Label != "voucher:batch-test" {
		t.Errorf("label = %q", m.Label)
	}

	// Re-redeem fails
	res, _ = do(t, h, "POST", "/redeem",
		url.Values{"code": {"TEST-CDE2-3456"}, "mac": {"aa:bb:cc:dd:ee:ff"}}, nil)
	loc = res.Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("re-redeem should fail; loc=%s", loc)
	}

	// Invalid code
	res, _ = do(t, h, "POST", "/redeem",
		url.Values{"code": {"NOPE-NOPE-NOPE"}, "mac": {"aa:bb:cc:dd:ee:ff"}}, nil)
	loc = res.Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("invalid code: %s", loc)
	}
}

func TestMetricsTokenGate(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.MetricsToken = "the-secret"
	h := app.Routes()

	res, _ := do(t, h, "GET", "/metrics", nil, nil)
	if res.StatusCode != 401 {
		t.Errorf("no token: %d, want 401", res.StatusCode)
	}

	// With token
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer the-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("good token: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "router_billing_uptime_seconds") {
		t.Error("metrics body missing expected text")
	}
}

func TestSecurityHeaders(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "GET", "/portal", nil, nil)
	mustHave := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "SAMEORIGIN",
		"Referrer-Policy":        "same-origin",
	}
	for k, v := range mustHave {
		if got := res.Header.Get(k); got != v {
			t.Errorf("%s: got %q, want %q", k, got, v)
		}
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src self: %s", csp)
	}
}

