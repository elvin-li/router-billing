package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// loginWith2FAUntilSession runs through password → /user/login/2fa, optionally
// setting trust_device. Returns the post-login cookie jar (rb_user + maybe
// rb_user_trusted) so subsequent tests can issue authed requests.
func loginWith2FAUntilSession(t *testing.T, h http.Handler, app *App, phone, password string, trustDevice bool) map[string]string {
	t.Helper()
	// Tests log in repeatedly inside one 30s TOTP step; a real authenticator
	// would show a fresh code each login, so lift the one-time-use ledger.
	resetTOTPReplay()
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {phone}, "password": {password}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("password login: %d", res.StatusCode)
	}
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	csrf := pending[csrfCookieName]
	code := validTOTPForUser(t, app, phone)
	form := url.Values{"code": {code}, "_csrf": {csrf}}
	if trustDevice {
		form.Set("trust_device", "1")
	}
	res3, _ := do(t, h, "POST", "/user/login/2fa", form, pending)
	if res3.StatusCode != 303 {
		t.Fatalf("2fa verify: %d", res3.StatusCode)
	}
	// Merge cookies from the verify response on top of the prior jar so
	// rb_csrf (set by the GET earlier), rb_user (set by verify), and
	// rb_user_trusted (set conditionally by verify) all coexist.
	out := pending
	for k, v := range cookieJar(res3) {
		out[k] = v
	}
	// Fetch /user/2fa to refresh rb_csrf for this jar — login swaps cookies.
	r4, _ := do(t, h, "GET", "/user/2fa", nil, out)
	for k, v := range cookieJar(r4) {
		out[k] = v
	}
	if out[userCookieName] == "" {
		t.Fatal("rb_user should be set after 2fa")
	}
	return out
}

func TestTrustDeviceCheckboxIssuesCookieAndRow(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139030", "trust-pw")

	jar := loginWith2FAUntilSession(t, h, app, "13800139030", "trust-pw", true)
	if jar[userTrustedCookie] == "" {
		t.Fatal("rb_user_trusted cookie should be set when trust_device=1")
	}
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139030")
	devices, _ := app.DB.ListTrustedDevices(context.Background(), u.ID)
	if len(devices) != 1 {
		t.Fatalf("expected 1 trusted device row; got %d", len(devices))
	}
	if devices[0].Token != jar[userTrustedCookie] {
		t.Error("DB token must match cookie value")
	}
}

func TestTrustDeviceBypasses2FAOnNextLogin(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139031", "bypass-pw")

	first := loginWith2FAUntilSession(t, h, app, "13800139031", "bypass-pw", true)
	trust := first[userTrustedCookie]
	if trust == "" {
		t.Fatal("setup: trust cookie not issued")
	}

	// Second login with only the trust cookie (no rb_user) — should skip 2FA.
	req := httptest.NewRequest("POST", "/user/login",
		strings.NewReader(url.Values{"phone": {"13800139031"}, "password": {"bypass-pw"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: userTrustedCookie, Value: trust})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	if res.StatusCode != 303 {
		t.Fatalf("login w/ trust: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if strings.Contains(loc, "/user/login/2fa") {
		t.Errorf("trusted device should skip 2fa; got %s", loc)
	}
	if cookieJar(res)[userCookieName] == "" {
		t.Error("trusted device login should set rb_user directly")
	}
}

func TestUntrustedBrowserStillGets2FAChallenge(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139032", "stillchal-pw")
	_ = loginWith2FAUntilSession(t, h, app, "13800139032", "stillchal-pw", true)

	// Fresh browser → no trust cookie. Must still go through 2fa.
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139032"}, "password": {"stillchal-pw"}}, nil)
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "/user/login/2fa") {
		t.Errorf("untrusted browser should hit 2fa; got %s", loc)
	}
}

func TestRevokeOneTrustedDeviceDoesNotKickOthers(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139033", "two-trust-pw")

	first := loginWith2FAUntilSession(t, h, app, "13800139033", "two-trust-pw", true)
	second := loginWith2FAUntilSession(t, h, app, "13800139033", "two-trust-pw", true)
	if first[userTrustedCookie] == second[userTrustedCookie] {
		t.Fatal("two issuances should produce different tokens")
	}

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139033")
	devices, _ := app.DB.ListTrustedDevices(context.Background(), u.ID)
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices; got %d", len(devices))
	}

	// Find the row for `first` and revoke it via the authed user endpoint.
	var firstID int64
	for _, d := range devices {
		if d.Token == first[userTrustedCookie] {
			firstID = d.ID
		}
	}
	if firstID == 0 {
		t.Fatal("could not find first device row")
	}
	res, _ := do(t, h, "POST", "/user/2fa/trusted-devices/revoke",
		url.Values{"_csrf": {second[csrfCookieName]}, "device_id": {strconv.FormatInt(firstID, 10)}}, second)
	if res.StatusCode != 303 {
		t.Fatalf("revoke: %d", res.StatusCode)
	}

	// First's cookie no longer bypasses 2fa.
	req := httptest.NewRequest("POST", "/user/login",
		strings.NewReader(url.Values{"phone": {"13800139033"}, "password": {"two-trust-pw"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: userTrustedCookie, Value: first[userTrustedCookie]})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/user/login/2fa") {
		t.Errorf("revoked device should hit 2fa; got %s", loc)
	}

	// Second's cookie still works.
	req2 := httptest.NewRequest("POST", "/user/login",
		strings.NewReader(url.Values{"phone": {"13800139033"}, "password": {"two-trust-pw"}}.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: userTrustedCookie, Value: second[userTrustedCookie]})
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	loc2 := rr2.Header().Get("Location")
	if strings.Contains(loc2, "/user/login/2fa") {
		t.Errorf("non-revoked device should bypass; got %s", loc2)
	}
}

func TestRevokeAllTrustedDevicesWipesAndClears(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139034", "wipeall-pw")

	jar := loginWith2FAUntilSession(t, h, app, "13800139034", "wipeall-pw", true)
	_ = loginWith2FAUntilSession(t, h, app, "13800139034", "wipeall-pw", true)

	res, _ := do(t, h, "POST", "/user/2fa/trusted-devices/revoke-all",
		url.Values{"_csrf": {jar[csrfCookieName]}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("revoke-all: %d", res.StatusCode)
	}
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139034")
	devices, _ := app.DB.ListTrustedDevices(context.Background(), u.ID)
	if len(devices) != 0 {
		t.Errorf("expected 0 devices after revoke-all; got %d", len(devices))
	}
}

func TestDisable2FAWipesTrustedDevices(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139035", "disable-trust-pw")

	jar := loginWith2FAUntilSession(t, h, app, "13800139035", "disable-trust-pw", true)
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139035")
	if devs, _ := app.DB.ListTrustedDevices(context.Background(), u.ID); len(devs) != 1 {
		t.Fatalf("setup: should have 1 trusted device; got %d", len(devs))
	}

	// Disable 2FA. (Fresh-code simulation: the login above consumed the
	// current step for one-time-use purposes.)
	resetTOTPReplay()
	code := validTOTPForUser(t, app, "13800139035")
	res, _ := do(t, h, "POST", "/user/2fa/disable",
		url.Values{"_csrf": {jar[csrfCookieName]}, "password": {"disable-trust-pw"}, "code": {code}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "ok=2fa_disabled") {
		t.Fatalf("disable: %s", res.Header.Get("Location"))
	}
	if devs, _ := app.DB.ListTrustedDevices(context.Background(), u.ID); len(devs) != 0 {
		t.Errorf("disabling 2fa should wipe trusted devices; got %d", len(devs))
	}
}

func TestAdminReset2FAWipesTrustedDevices(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139036", "adminres-pw")
	_ = loginWith2FAUntilSession(t, h, app, "13800139036", "adminres-pw", true)
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139036")

	adminJar := loginAdmin(t, h)
	do(t, h, "POST", "/admin/users/reset-2fa",
		url.Values{"_csrf": {adminJar[csrfCookieName]}, "id": {strconv.FormatInt(u.ID, 10)}}, adminJar)

	devs, _ := app.DB.ListTrustedDevices(context.Background(), u.ID)
	if len(devs) != 0 {
		t.Errorf("admin reset-2fa should wipe trusted devices; got %d", len(devs))
	}
}

func TestStaleTrustCookieGetsCleared(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139037", "stale-pw")

	// Pretend the browser has a leftover cookie from some other user / a
	// long-purged session. /user/login should NOT skip 2fa.
	req := httptest.NewRequest("POST", "/user/login",
		strings.NewReader(url.Values{"phone": {"13800139037"}, "password": {"stale-pw"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: userTrustedCookie, Value: "obviously-not-a-real-token"})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	res := rr.Result()
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "/user/login/2fa") {
		t.Errorf("stale cookie should not skip 2fa; got %s", loc)
	}
	// And the response should clear the stale cookie.
	cleared := false
	for _, c := range res.Cookies() {
		if c.Name == userTrustedCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("stale cookie should be cleared on the response")
	}
}

func TestLabelFromUserAgent(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "(unknown browser)"},
		{"Mozilla/5.0", "Mozilla/5.0"},
		{strings.Repeat("X", 100), strings.Repeat("X", 80) + "…"},
	}
	for _, c := range cases {
		if got := labelFromUserAgent(c.in); got != c.want {
			t.Errorf("labelFromUserAgent(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatRelativeTime(t *testing.T) {
	now := time.Now()
	if got := formatRelativeTime(now); got != "刚刚" {
		t.Errorf("just-now: got %q", got)
	}
	if got := formatRelativeTime(now.Add(-10 * time.Minute)); !strings.Contains(got, "分钟前") {
		t.Errorf("10m: got %q", got)
	}
	if got := formatRelativeTime(now.Add(-3 * time.Hour)); !strings.Contains(got, "小时前") {
		t.Errorf("3h: got %q", got)
	}
	if got := formatRelativeTime(now.Add(-5 * 24 * time.Hour)); !strings.Contains(got, "天前") {
		t.Errorf("5d: got %q", got)
	}
}
