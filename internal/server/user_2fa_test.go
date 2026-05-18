package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"router-billing/internal/totp"
)

// registerAndLogin pulls the user through register so the bcrypt hash is real,
// then returns the active user + a cookie jar with rb_user and rb_csrf set so
// subsequent authed POSTs work.
func registerAndLogin(t *testing.T, h http.Handler, phone, password string) map[string]string {
	t.Helper()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {phone}, "password": {password}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register: %d", res.StatusCode)
	}
	jar := cookieJar(res)
	// Touch a page to pick up an rb_csrf cookie.
	res, _ = do(t, h, "GET", "/user/2fa", nil, jar)
	for k, v := range cookieJar(res) {
		jar[k] = v
	}
	return jar
}

// validTOTPForUser asks the DB for the user's current secret and returns the
// 6-digit code that should be valid right now. Picks pending if live is empty
// so the "confirm" flow can test against the pending secret.
func validTOTPForUser(t *testing.T, app *App, phone string) string {
	t.Helper()
	u, err := app.DB.GetUserByPhone(context.Background(), phone)
	if err != nil || u == nil {
		t.Fatalf("get user %s: %v", phone, err)
	}
	secret := u.TOTPSecret
	if secret == "" {
		secret = u.TOTPPending
	}
	if secret == "" {
		t.Fatalf("user %s has no totp secret", phone)
	}
	code, err := totp.Code(secret, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestUser2FAEnrollmentBeginGeneratesPendingSecret(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139001", "secret-pw")
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/user/2fa/begin",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("begin: %d", res.StatusCode)
	}

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139001")
	if u.TOTPPending == "" {
		t.Fatal("pending secret should be set")
	}
	if u.TOTPSecret != "" {
		t.Fatal("live secret must not be set before confirm")
	}
	// Calling begin again must generate a fresh secret (not reuse).
	prior := u.TOTPPending
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	u, _ = app.DB.GetUserByPhone(context.Background(), "13800139001")
	if u.TOTPPending == prior {
		t.Error("begin must rotate the pending secret on each click")
	}
}

func TestUser2FAConfirmPromotesPendingToLive(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139002", "another-pw")
	csrf := jar[csrfCookieName]

	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139002")

	res, _ := do(t, h, "POST", "/user/2fa/confirm",
		url.Values{"_csrf": {csrf}, "code": {code}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("confirm: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=2fa_enabled") {
		t.Errorf("confirm location: %s", loc)
	}

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139002")
	if u.TOTPSecret == "" {
		t.Fatal("live secret should be set after confirm")
	}
	if u.TOTPPending != "" {
		t.Fatal("pending must be cleared after confirm")
	}
}

func TestUser2FAConfirmWrongCodeKeepsPending(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139003", "third-pw")
	csrf := jar[csrfCookieName]

	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)

	res, _ := do(t, h, "POST", "/user/2fa/confirm",
		url.Values{"_csrf": {csrf}, "code": {"000000"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("confirm: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "err=2fa_failed") {
		t.Errorf("expected err=2fa_failed; got %s", res.Header.Get("Location"))
	}

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139003")
	if u.TOTPPending == "" {
		t.Error("pending should remain after a wrong code")
	}
	if u.TOTPSecret != "" {
		t.Error("live secret must not promote on wrong code")
	}
}

func TestUser2FALoginRequiresCodeWhenEnrolled(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139004", "topaz-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139004")
	do(t, h, "POST", "/user/2fa/confirm",
		url.Values{"_csrf": {csrf}, "code": {code}}, jar)

	// Now wipe the active session — simulate a fresh browser logging in.
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139004"}, "password": {"topaz-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("login: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "/user/login/2fa") {
		t.Fatalf("password-only login should redirect to 2fa; got %s", loc)
	}
	// And no rb_user cookie is set yet — only the pending cookie.
	cookies := cookieJar(res)
	if cookies[userCookieName] != "" {
		t.Error("rb_user cookie must not be set before 2fa verify")
	}
	if cookies[userPendingCookie] == "" {
		t.Error("rb_user_pending cookie should be set")
	}

	// Submit the right TOTP — should finally issue rb_user.
	pendingJar := cookies
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pendingJar)
	for k, v := range cookieJar(res2) {
		pendingJar[k] = v
	}
	csrf2 := pendingJar[csrfCookieName]
	code2 := validTOTPForUser(t, app, "13800139004")
	res3, _ := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {code2}, "_csrf": {csrf2}}, pendingJar)
	if res3.StatusCode != 303 {
		t.Fatalf("2fa verify: %d", res3.StatusCode)
	}
	finalCookies := cookieJar(res3)
	if finalCookies[userCookieName] == "" {
		t.Error("rb_user should be set after good 2fa code")
	}
}

func TestUser2FALoginBlocksOnWrongCode(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139005", "azure-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139005")
	do(t, h, "POST", "/user/2fa/confirm",
		url.Values{"_csrf": {csrf}, "code": {code}}, jar)

	// Fresh login → pending cookie.
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139005"}, "password": {"azure-pw"}}, nil)
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	csrf2 := pending[csrfCookieName]

	res3, body := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {"000000"}, "_csrf": {csrf2}}, pending)
	if res3.StatusCode != 200 {
		t.Fatalf("wrong code should re-render 200; got %d", res3.StatusCode)
	}
	if !strings.Contains(body, "验证码错误") {
		t.Errorf("missing wrong-code banner; body=%s", truncate(body, 300))
	}
	if cookieJar(res3)[userCookieName] != "" {
		t.Error("rb_user must not be set on wrong code")
	}
}

func TestUser2FALoginLockoutAfterFiveWrongCodes(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139006", "lock-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139006")
	do(t, h, "POST", "/user/2fa/confirm",
		url.Values{"_csrf": {csrf}, "code": {code}}, jar)

	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139006"}, "password": {"lock-pw"}}, nil)
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	csrf2 := pending[csrfCookieName]

	// Burn 6 wrong attempts (cap is 5 → 6th destroys the pending session).
	var locOnLast string
	for i := 0; i < 6; i++ {
		r, _ := do(t, h, "POST", "/user/login/2fa",
			url.Values{"code": {"000000"}, "_csrf": {csrf2}}, pending)
		locOnLast = r.Header.Get("Location")
	}
	if !strings.Contains(locOnLast, "2fa_locked") && !strings.Contains(locOnLast, "2fa_expired") {
		t.Errorf("6th attempt should bounce to login with locked/expired; got %s", locOnLast)
	}
}

func TestUser2FADisableRequiresPasswordAndCode(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139007", "disable-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139007")
	do(t, h, "POST", "/user/2fa/confirm",
		url.Values{"_csrf": {csrf}, "code": {code}}, jar)

	// Wrong password → blocked.
	res, _ := do(t, h, "POST", "/user/2fa/disable",
		url.Values{"_csrf": {csrf}, "password": {"WRONG"}, "code": {validTOTPForUser(t, app, "13800139007")}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "bad_credentials") {
		t.Errorf("wrong password should err=bad_credentials; got %s", res.Header.Get("Location"))
	}
	if u, _ := app.DB.GetUserByPhone(context.Background(), "13800139007"); u.TOTPSecret == "" {
		t.Fatal("secret cleared with wrong password!")
	}

	// Wrong code → blocked.
	res, _ = do(t, h, "POST", "/user/2fa/disable",
		url.Values{"_csrf": {csrf}, "password": {"disable-pw"}, "code": {"000000"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "2fa_failed") {
		t.Errorf("wrong code should err=2fa_failed; got %s", res.Header.Get("Location"))
	}
	if u, _ := app.DB.GetUserByPhone(context.Background(), "13800139007"); u.TOTPSecret == "" {
		t.Fatal("secret cleared with wrong code!")
	}

	// Both correct → cleared.
	res, _ = do(t, h, "POST", "/user/2fa/disable",
		url.Values{"_csrf": {csrf}, "password": {"disable-pw"}, "code": {validTOTPForUser(t, app, "13800139007")}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "ok=2fa_disabled") {
		t.Errorf("disable should ok=2fa_disabled; got %s", res.Header.Get("Location"))
	}
	if u, _ := app.DB.GetUserByPhone(context.Background(), "13800139007"); u.TOTPSecret != "" || u.TOTPPending != "" {
		t.Errorf("secret/pending should be cleared after disable; got secret=%q pending=%q", u.TOTPSecret, u.TOTPPending)
	}
}

func TestUser2FALoginWithoutCookieRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	res, _ := do(t, h, "GET", "/user/login/2fa", nil, nil)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "2fa_expired") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}
}

func TestUser2FAQRReturnsPNG(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139008", "qrcode-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)

	res, body := do(t, h, "GET", "/user/2fa/qr", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("qr: %d", res.StatusCode)
	}
	if res.Header.Get("Content-Type") != "image/png" {
		t.Errorf("content-type: %s", res.Header.Get("Content-Type"))
	}
	// PNG signature is 89 50 4E 47 0D 0A 1A 0A.
	if len(body) < 8 || body[:4] != "\x89PNG" {
		t.Errorf("body doesn't look like PNG; first 8 bytes: %x", body[:min(8, len(body))])
	}
}

func TestUser2FALoginFlowDoesntSetUserCookieOnPasswordOK(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139009", "fresh-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139009")
	do(t, h, "POST", "/user/2fa/confirm", url.Values{"_csrf": {csrf}, "code": {code}}, jar)

	// A no-cookie POST is the moral equivalent of "fresh browser logging in".
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139009"}, "password": {"fresh-pw"}}, nil)
	if cookieJar(res)[userCookieName] != "" {
		t.Fatal("password-only login set rb_user for a 2fa-enrolled user — bypasses 2fa!")
	}
}

func TestAdminCanResetUserTOTPWhenLocked(t *testing.T) {
	// Scenario: user enrolled 2FA, lost their phone. Admin clicks "重置 2FA"
	// so the user can log in with just password and re-enroll.
	app := setupTestApp(t)
	h := app.Routes()

	// Enroll user 2FA.
	jar := registerAndLogin(t, h, "13800139010", "lost-phone-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139010")
	do(t, h, "POST", "/user/2fa/confirm", url.Values{"_csrf": {csrf}, "code": {code}}, jar)

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139010")
	if u.TOTPSecret == "" {
		t.Fatal("setup: 2fa should be enrolled")
	}
	userID := u.ID

	// Admin logs in and resets the user's 2FA.
	adminJar := loginAdmin(t, h)
	adminCSRF := adminJar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/users/reset-2fa",
		url.Values{"_csrf": {adminCSRF}, "id": {itoa(int(userID))}}, adminJar)
	if res.StatusCode != 303 {
		t.Fatalf("admin reset-2fa: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=reset_2fa") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}

	u2, _ := app.DB.GetUserByPhone(context.Background(), "13800139010")
	if u2.TOTPSecret != "" || u2.TOTPPending != "" {
		t.Errorf("totp should be cleared; got secret=%q pending=%q", u2.TOTPSecret, u2.TOTPPending)
	}

	// User can now log in with just password (no 2FA gate).
	res2, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139010"}, "password": {"lost-phone-pw"}}, nil)
	if res2.StatusCode != 303 {
		t.Fatalf("post-reset login: %d", res2.StatusCode)
	}
	loc := res2.Header.Get("Location")
	if strings.Contains(loc, "/user/login/2fa") {
		t.Errorf("post-reset login should bypass 2fa; got %s", loc)
	}
	if cookieJar(res2)[userCookieName] == "" {
		t.Error("post-reset login should set rb_user directly")
	}
}

func TestAdminReset2FANoOpForUserWithoutTOTP(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	registerAndLogin(t, h, "13800139011", "never-enrolled-pw")
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139011")

	adminJar := loginAdmin(t, h)
	adminCSRF := adminJar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/users/reset-2fa",
		url.Values{"_csrf": {adminCSRF}, "id": {itoa(int(u.ID))}}, adminJar)
	// Should still succeed — ClearUserTOTP is a no-op if nothing is set, but
	// the redirect path is the same.
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestPrettySecret(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"abc", "ABC"},
		{"abcd", "ABCD"},
		{"abcde", "ABCD E"},
		{"abcdefghijklmnop", "ABCD EFGH IJKL MNOP"},
		{"a b c d", "ABCD"},
	}
	for _, c := range cases {
		if got := prettySecret(c.in); got != c.want {
			t.Errorf("prettySecret(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtractDigits(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"abc", ""},
		{"123 456", "123456"},
		{"  123-456  ", "123456"},
		{"a1b2c3d4e5f6", "123456"},
	}
	for _, c := range cases {
		if got := extractDigits(c.in); got != c.want {
			t.Errorf("extractDigits(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
