package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
	"router-billing/internal/db"
	"router-billing/internal/firewall"
	"router-billing/internal/service"
	"router-billing/internal/totp"
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

// loginAdmin posts admin creds and returns a cookie jar with rb_admin + rb_csrf.
func loginAdmin(t *testing.T, h http.Handler) map[string]string {
	t.Helper()
	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("login: %d", res.StatusCode)
	}
	jar := cookieJar(res)
	// Touch a page to pick up an rb_csrf cookie.
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar)
	for k, v := range cookieJar(res) {
		jar[k] = v
	}
	return jar
}

func TestMaintenancePageRenders(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/maintenance", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	for _, want := range []string{"下载完整备份", "从备份恢复", "上传 + 暂存", `name="backup"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in body", want)
		}
	}
}

func TestBackupRestoreRejectsNonSQLite(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	tok := jar[csrfCookieName]
	if tok == "" {
		t.Fatal("no csrf token in jar")
	}

	body, ct := multipartBackup(t, "junk.db", []byte("definitely not a sqlite file"))
	req := httptest.NewRequest("POST", "/admin/backup/restore", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-CSRF-Token", tok)
	for k, v := range jar {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Errorf("expected 400 for bad sqlite; got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "magic") && !strings.Contains(rr.Body.String(), "SQLite") {
		t.Errorf("error body should mention SQLite magic; got: %s", rr.Body.String())
	}
}

func TestBackupRestoreAcceptsValidDB(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	tok := jar[csrfCookieName]

	// Use the live test DB file itself as the "upload" — guaranteed to pass
	// both magic-header and macs-table checks.
	_, _ = app.DB.Exec(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)")
	raw, err := os.ReadFile(app.Cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}

	body, ct := multipartBackup(t, "billing-good.db", raw)
	req := httptest.NewRequest("POST", "/admin/backup/restore", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("X-CSRF-Token", tok)
	for k, v := range jar {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("expected 200; got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "等待重启切换") {
		t.Errorf("body missing staged message")
	}
	if _, err := os.Stat(app.Cfg.DBPath + ".pending-restore"); err != nil {
		t.Errorf("expected pending file: %v", err)
	}
}

// multipartBackup builds a multipart/form-data body with a `backup` field.
func multipartBackup(t *testing.T, filename string, data []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("backup", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

func TestPayCreateRateLimit(t *testing.T) {
	app := setupTestApp(t)
	app.payCreateLimiter = newRateLimiter(2, time.Hour)
	h := app.Routes()

	// Two POSTs go through. Body schema fails downstream (no provider) but
	// the limiter counts them first.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/api/pay/create", strings.NewReader(`{"mac":"aa:bb:cc:dd:ee:ff","plan":"month","provider":"wechat"}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == 429 {
			t.Errorf("attempt %d wrongly rate-limited", i)
		}
	}
	// 3rd hit gets 429.
	req := httptest.NewRequest("POST", "/api/pay/create", strings.NewReader(`{"mac":"aa:bb:cc:dd:ee:ff","plan":"month","provider":"wechat"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 429 {
		t.Errorf("3rd attempt should be 429, got %d", rr.Code)
	}
}

func TestServiceWorkerServed(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, body := do(t, h, "GET", "/sw.js", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("/sw.js status=%d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/javascript") {
		t.Errorf("content-type = %q; want application/javascript*", ct)
	}
	if !strings.Contains(body, "self.addEventListener('fetch'") {
		t.Error("body doesn't look like our SW")
	}
}

func TestManifestServed(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, body := do(t, h, "GET", "/static/manifest.json", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status=%d", res.StatusCode)
	}
	if !strings.Contains(body, `"start_url"`) || !strings.Contains(body, "WiFi 上网认证") {
		t.Errorf("manifest body unexpected: %s", body)
	}
}

func TestPortalAnnouncesPWAAssets(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, body := do(t, h, "GET", "/portal", nil, nil)
	for _, want := range []string{
		`rel="manifest"`,
		`/static/manifest.json`,
		`navigator.serviceWorker.register('/sw.js'`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("portal missing %q", want)
		}
	}
}

func TestAdminPlansPageRenders(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/plans", nil, jar)
	for _, want := range []string{"套餐管理", "新增 / 修改套餐", `name="key"`, `name="days"`} {
		if !strings.Contains(body, want) {
			t.Errorf("plans page missing %q", want)
		}
	}
}

func TestAdminAuditPageRendersAndFilters(t *testing.T) {
	ctx := context.Background()
	app := setupTestApp(t)
	// Seed a few audit rows so the filter has something to find.
	app.DB.Audit(ctx, "admin", "login", "", "ok")
	app.DB.Audit(ctx, "admin", "grant", "AA:BB:CC:DD:EE:FF", "30 days")
	app.DB.Audit(ctx, "user:13800138000", "redeem", "AA:BB:CC:DD:EE:FF", "voucher=X")

	h := app.Routes()
	jar := loginAdmin(t, h)

	_, all := do(t, h, "GET", "/admin/audit", nil, jar)
	for _, want := range []string{"审计日志", "grant", "redeem", "login"} {
		if !strings.Contains(all, want) {
			t.Errorf("audit page missing %q", want)
		}
	}

	// Filter by action=grant should not include the redeem/login rows.
	_, filtered := do(t, h, "GET", "/admin/audit?action=grant", nil, jar)
	if !strings.Contains(filtered, "grant") {
		t.Error("filtered page lost the grant row")
	}
	if strings.Contains(filtered, "voucher=X") {
		t.Error("filtered page should not include redeem row (filter by action=grant)")
	}
}

func TestAdminVoucherPrintPageRenders(t *testing.T) {
	ctx := context.Background()
	app := setupTestApp(t)
	for i, code := range []string{"TESTCODE2222", "TESTCODE3333", "TESTCODE4444"} {
		if _, err := app.DB.CreateVoucher(ctx, code, 30, "lab", "print-batch", nil); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	h := app.Routes()
	jar := loginAdmin(t, h)

	_, body := do(t, h, "GET", "/admin/vouchers/print?batch=print-batch", nil, jar)
	// Pretty-codes are formatted 4-4-4
	for _, want := range []string{"TEST-CODE-2222", "TEST-CODE-3333", "TEST-CODE-4444",
		"30 天", "充值卡", "@media print"} {
		if !strings.Contains(body, want) {
			t.Errorf("print page missing %q", want)
		}
	}

	// The QR endpoint should return PNG.
	res, _ := do(t, h, "GET", "/admin/vouchers/print/qr?code=TESTCODE2222", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("qr endpoint: %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("qr content-type = %q", ct)
	}
}

func TestSuspendKicksLoggedInUser(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	ctx := context.Background()

	// Register a user and grab the resulting session.
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800138000"}, "password": {"hunter22"}}, nil)
	jar := cookieJar(res)
	if jar[userCookieName] == "" {
		t.Fatal("no user cookie after register")
	}

	// /user/me works while authed.
	res, _ = do(t, h, "GET", "/user/me", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("authed /user/me: %d", res.StatusCode)
	}

	// Admin suspends the user via DB (skip the HTTP form for brevity, but
	// verify the DB layer + currentUserID flow).
	u, _ := app.DB.GetUserByPhone(ctx, "13800138000")
	killed, _ := app.DB.DeleteSessionsByUserID(ctx, u.ID)
	if killed < 1 {
		t.Errorf("expected DeleteSessionsByUserID to kill ≥1; got %d", killed)
	}

	// Same cookie now bounces back to /user/login.
	res, _ = do(t, h, "GET", "/user/me", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("expected redirect after session killed; got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "/user/login") {
		t.Errorf("redirect should be to /user/login; got %s", res.Header.Get("Location"))
	}
}

func TestSuspendedFlagAlsoBlocksValidSession(t *testing.T) {
	// Defense-in-depth: if a stale session exists, currentUserID still bounces
	// the user because GetUser returns Suspended=true.
	app := setupTestApp(t)
	h := app.Routes()
	ctx := context.Background()

	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800138100"}, "password": {"hunter22"}}, nil)
	jar := cookieJar(res)

	// Flip suspended flag WITHOUT killing the session — simulating the
	// race where the DB write succeeded but DeleteSessionsByUserID failed.
	u, _ := app.DB.GetUserByPhone(ctx, "13800138100")
	if err := app.DB.SuspendUser(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}

	res, _ = do(t, h, "GET", "/user/me", nil, jar)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/user/login") {
		t.Errorf("expected redirect for suspended user even with valid session; got status=%d loc=%s",
			res.StatusCode, res.Header.Get("Location"))
	}
}

func TestSecureCookieSetWhenBehindTLS(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Login through plain HTTP-by-default → Secure=false.
	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	if sc := res.Header.Get("Set-Cookie"); strings.Contains(sc, "Secure") {
		t.Errorf("admin cookie shouldn't be Secure on HTTP; got %s", sc)
	}

	// Now repeat with X-Forwarded-Proto: https → Secure must be present.
	form := url.Values{"username": {"admin"}, "password": {"admin-pw"}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if sc := rr.Header().Get("Set-Cookie"); !strings.Contains(sc, "Secure") {
		t.Errorf("admin cookie should be Secure behind TLS proxy; got %s", sc)
	}
}

func TestAdminLoginRateLimitByUsername(t *testing.T) {
	app := setupTestApp(t)
	app.adminLoginByUser = newRateLimiter(3, time.Hour)
	// Trust the httptest peer (192.0.2.1) as a reverse proxy so the
	// X-Forwarded-For rotation below is honored — otherwise clientIP
	// ignores the header entirely (see security.trusted_proxies).
	nets, err := (config.Security{TrustedProxies: []string{"192.0.2.0/24"}}).TrustedProxyNets()
	if err != nil {
		t.Fatal(err)
	}
	app.trustedProxies = nets
	h := app.Routes()

	// 3 attempts with wrong password but the SAME username are allowed
	// (failures, but not rate-limited). Different X-Forwarded-For each time
	// to defeat the IP-keyed limiter and isolate the per-username one.
	for i := 0; i < 3; i++ {
		form := url.Values{"username": {"admin"}, "password": {"bad"}}
		req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i+1))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if !strings.Contains(rr.Body.String(), "用户名或密码错误") {
			t.Errorf("attempt %d body: %s", i, rr.Body.String())
		}
	}
	// 4th attempt with a fresh IP — rate-limit fires on USERNAME, not IP.
	form := url.Values{"username": {"admin"}, "password": {"bad"}}
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "尝试过于频繁") {
		t.Errorf("4th attempt should be rate-limited by username; body=%s", rr.Body.String())
	}
}

func TestAPIToken401WithoutBearer(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_abc", Label: "monitor"}}
	h := app.Routes()

	for _, path := range []string{"/api/admin/health", "/api/admin/macs", "/api/admin/macs/grant"} {
		res, _ := do(t, h, "GET", path, nil, nil)
		if res.StatusCode != 401 {
			t.Errorf("%s no-auth: %d (want 401)", path, res.StatusCode)
		}
	}
}

func TestAPITokenAcceptsValidGrantsMAC(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_letmein", Label: "ci"}}
	h := app.Routes()

	body := strings.NewReader(`{"mac":"aa:bb:cc:11:22:33","days":30,"label":"ci-test"}`)
	req := httptest.NewRequest("POST", "/api/admin/macs/grant", body)
	req.Header.Set("Authorization", "Bearer rb_letmein")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("grant: %d, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "AA:BB:CC:11:22:33") {
		t.Errorf("response missing MAC: %s", rr.Body.String())
	}

	// And it actually landed.
	m, _ := app.DB.GetMAC(context.Background(), "AA:BB:CC:11:22:33")
	if m == nil {
		t.Fatal("MAC not in DB")
	}
	if m.Label != "ci-test" {
		t.Errorf("label=%q (want ci-test)", m.Label)
	}
}

func TestAPITokenRejectsBadToken(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_letmein", Label: "ci"}}
	h := app.Routes()

	req := httptest.NewRequest("GET", "/api/admin/health", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Errorf("bad token: %d", rr.Code)
	}
}

func TestAPITokenRevokeMAC(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_letmein", Label: "ci"}}
	// Pre-seed a MAC
	ctx := context.Background()
	_, _ = app.MACSvc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "to-delete", 30, nil)
	h := app.Routes()

	body := strings.NewReader(`{"mac":"aa:bb:cc:dd:ee:ff"}`)
	req := httptest.NewRequest("POST", "/api/admin/macs/revoke", body)
	req.Header.Set("Authorization", "Bearer rb_letmein")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("revoke: %d, body=%s", rr.Code, rr.Body.String())
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:FF")
	if m != nil {
		t.Error("MAC should be gone")
	}
}

func TestAdminLogin2FAFullFlow(t *testing.T) {
	app := setupTestApp(t)
	const secret = "JBSWY3DPEHPK3PXP" // RFC 4648 example
	app.Cfg.Admin.TOTPSecret = secret
	h := app.Routes()

	// Step 1: password POST → 303 to /admin/login/2fa, sets pending cookie.
	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/admin/login/2fa") {
		t.Fatalf("pw stage: status=%d loc=%s", res.StatusCode, res.Header.Get("Location"))
	}
	jar := cookieJar(res)
	if jar[adminPendingCookie] == "" {
		t.Fatal("no rb_admin_pending cookie set")
	}
	if jar[adminCookieName] != "" {
		t.Fatal("real admin cookie should NOT be set yet")
	}

	// Step 2: pending session shouldn't grant /admin/macs access.
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("pending session shouldn't grant admin access; got %d", res.StatusCode)
	}

	// Step 3: submit a correct TOTP code → real admin session.
	code, err := totp.Code(secret, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	res, _ = do(t, h, "POST", "/admin/login/2fa", url.Values{"code": {code}}, jar)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/admin/dashboard") {
		t.Fatalf("2fa stage: status=%d loc=%s", res.StatusCode, res.Header.Get("Location"))
	}
	jar2 := cookieJar(res)
	if jar2[adminCookieName] == "" {
		t.Error("real admin cookie should be set after successful 2FA")
	}

	// Step 4: merged cookies open /admin/macs.
	merged := map[string]string{}
	for k, v := range jar {
		merged[k] = v
	}
	for k, v := range jar2 {
		merged[k] = v
	}
	res, _ = do(t, h, "GET", "/admin/macs", nil, merged)
	if res.StatusCode != 200 {
		t.Errorf("authed /admin/macs: %d", res.StatusCode)
	}
}

func TestAdminLogin2FAWrongCodeRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Admin.TOTPSecret = "JBSWY3DPEHPK3PXP"
	h := app.Routes()

	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	jar := cookieJar(res)

	res, body := do(t, h, "POST", "/admin/login/2fa", url.Values{"code": {"000000"}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("wrong code: status=%d", res.StatusCode)
	}
	if !strings.Contains(body, "验证码错误") {
		t.Error("body should show '验证码错误'")
	}
	if cookieJar(res)[adminCookieName] != "" {
		t.Error("real admin cookie must NOT be set after a wrong code")
	}
}

func TestAdminLogin2FALocksAfterFiveAttempts(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Admin.TOTPSecret = "JBSWY3DPEHPK3PXP"
	h := app.Routes()

	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	jar := cookieJar(res)

	// 5 wrong attempts → still inline error (status 200).
	for i := 0; i < 5; i++ {
		res, _ = do(t, h, "POST", "/admin/login/2fa", url.Values{"code": {"000000"}}, jar)
		if res.StatusCode != 200 {
			t.Errorf("attempt %d: status=%d (want 200 inline)", i, res.StatusCode)
		}
	}
	// 6th: pending session killed; redirect to /admin/login.
	res, _ = do(t, h, "POST", "/admin/login/2fa", url.Values{"code": {"000000"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("6th attempt: status=%d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "2fa_locked") {
		t.Errorf("expected 2fa_locked redirect; got %s", res.Header.Get("Location"))
	}
}

func TestAdminLogin2FANoSecretMeansOldFlow(t *testing.T) {
	app := setupTestApp(t) // no TOTPSecret set
	h := app.Routes()
	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "/admin/dashboard") {
		t.Errorf("no-totp path should redirect to /admin/dashboard; got status=%d loc=%s",
			res.StatusCode, res.Header.Get("Location"))
	}
	if cookieJar(res)[adminCookieName] == "" {
		t.Error("real admin cookie should be set immediately")
	}
}

func TestAdminSessionsList(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	// Add an extra user session so the list has 2 rows.
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800138777"}, "password": {"hunter22"}}, nil)
	if res.StatusCode != 303 {
		t.Fatal("register failed")
	}

	_, body := do(t, h, "GET", "/admin/sessions", nil, jar)
	for _, want := range []string{"活跃 Session", "admin", "user", "本机", "13800138777"} {
		if !strings.Contains(body, want) {
			t.Errorf("sessions page missing %q", want)
		}
	}
}

func TestAdminSessionRevoke(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	tok := jar[csrfCookieName]

	// Create a victim user session.
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800138888"}, "password": {"hunter22"}}, nil)
	victimJar := cookieJar(res)
	victimTok := victimJar[userCookieName]
	if victimTok == "" {
		t.Fatal("victim has no session cookie")
	}

	// Admin revokes the victim's session.
	form := url.Values{"_csrf": {tok}, "token": {victimTok}}
	req := httptest.NewRequest("POST", "/admin/sessions/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range jar {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 303 {
		t.Fatalf("revoke: %d (%s)", rr.Code, rr.Body.String())
	}

	// Victim's previously-valid cookie now bounces.
	res, _ = do(t, h, "GET", "/user/me", nil, victimJar)
	if res.StatusCode != 303 {
		t.Errorf("victim session should be dead; got %d", res.StatusCode)
	}
}

func TestAdminRevokeAllAdminKeepsCurrent(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Two admin sessions: jar1 = "victim", jar2 = "us".
	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	jar1 := cookieJar(res)

	res, _ = do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	jar2 := cookieJar(res)
	// Pick up a csrf token for jar2.
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar2)
	for k, v := range cookieJar(res) {
		jar2[k] = v
	}
	tok := jar2[csrfCookieName]

	form := url.Values{"_csrf": {tok}}
	req := httptest.NewRequest("POST", "/admin/sessions/revoke-all-admin",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range jar2 {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 303 {
		t.Fatalf("revoke-all-admin: %d (%s)", rr.Code, rr.Body.String())
	}

	// jar1 (other admin) is now dead → bounced to login.
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar1)
	if res.StatusCode != 303 {
		t.Errorf("other admin session should be killed; got %d", res.StatusCode)
	}
	// jar2 (us) still works.
	res, _ = do(t, h, "GET", "/admin/macs", nil, jar2)
	if res.StatusCode != 200 {
		t.Errorf("our own admin session should still work; got %d", res.StatusCode)
	}
}

func TestSQLiteDBFileIsOwnerOnly(t *testing.T) {
	app := setupTestApp(t)
	info, err := os.Stat(app.Cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("DB file mode = %o; want 0600 (contains bcrypt hashes)", mode)
	}
}

func TestRedeemRateLimit(t *testing.T) {
	app := setupTestApp(t)
	// Shrink the window so the test runs fast.
	app.redeemLimiter = newRateLimiter(3, time.Hour)
	h := app.Routes()

	// First 3 attempts go through (each fails with "code not found" but the
	// limiter still counts them).
	for i := 0; i < 3; i++ {
		res, _ := do(t, h, "POST", "/redeem",
			url.Values{"code": {"AAAAAAAAAA22"}, "mac": {"aa:bb:cc:dd:ee:ff"}}, nil)
		if res.StatusCode != 303 {
			t.Fatalf("attempt %d: %d", i, res.StatusCode)
		}
		loc := res.Header.Get("Location")
		if strings.Contains(loc, "尝试过于频繁") || strings.Contains(loc, "%e5%b0%9d") {
			t.Errorf("attempt %d should not be rate-limited yet: %s", i, loc)
		}
	}
	// 4th hit gets the rate-limit redirect.
	res, _ := do(t, h, "POST", "/redeem",
		url.Values{"code": {"AAAAAAAAAA22"}, "mac": {"aa:bb:cc:dd:ee:ff"}}, nil)
	loc := res.Header.Get("Location")
	// URL-encoded "尝试" prefix
	if !strings.Contains(loc, "%e5%b0%9d%e8%af%95") {
		t.Errorf("4th attempt should be rate-limited; got %s", loc)
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
