package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"router-billing/internal/sms"
)

// registerUser puts a user in the DB through the public POST handler so the
// password hash is real (bcrypt-cost as configured). Returns the phone for
// readability.
func registerUserForReset(t *testing.T, h http.Handler, phone, password string) {
	t.Helper()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {phone}, "password": {password}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register %s: %d", phone, res.StatusCode)
	}
}

// jarWithCSRF prefetches the forgot-password page so we have an rb_csrf cookie
// and matching form value to use in subsequent POSTs.
func jarWithCSRF(t *testing.T, h http.Handler) (jar map[string]string, csrf string) {
	t.Helper()
	res, _ := do(t, h, "GET", "/user/forgot-password", nil, nil)
	jar = cookieJar(res)
	csrf = jar[csrfCookieName]
	if csrf == "" {
		t.Fatal("no rb_csrf after GET /user/forgot-password")
	}
	return
}

// withConsoleSMS replaces app.SMS with a console provider that captures every
// message into the returned channel so tests can pull the code out.
func withConsoleSMS(t *testing.T, app *App) *sms.Console {
	t.Helper()
	c := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: c}
	return c
}

// extractCode pulls the 6-digit code out of the most recent console message.
// Fails the test if no message landed.
func extractCode(t *testing.T, c *sms.Console) string {
	t.Helper()
	recs := c.Recent()
	if len(recs) == 0 {
		t.Fatal("no SMS recorded")
	}
	body := recs[len(recs)-1].Message
	// Walk the body left-to-right and grab the first run of exactly 6 digits.
	// The body shape is "...验证码：123456，10 分钟内有效..." so the 6-digit run
	// ends well before the "10 分钟" suffix.
	run := []byte{}
	for _, r := range body {
		if r >= '0' && r <= '9' {
			run = append(run, byte(r))
		} else {
			if len(run) == 6 {
				return string(run)
			}
			run = run[:0]
		}
	}
	if len(run) == 6 {
		return string(run)
	}
	t.Fatalf("no 6-digit code in SMS: %q", body)
	return ""
}

func TestForgotPasswordHappyPath(t *testing.T) {
	app := setupTestApp(t)
	console := withConsoleSMS(t, app)
	h := app.Routes()

	registerUserForReset(t, h, "13800138001", "old-password-123")

	jar, csrf := jarWithCSRF(t, h)

	// Stage 1 — request code
	res, body := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13800138001"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("stage1: %d", res.StatusCode)
	}
	if !strings.Contains(body, "请输入收到的 6 位数字验证码") {
		t.Errorf("stage1 didn't advance to stage 2; body: %s", truncate(body, 400))
	}
	if !strings.Contains(body, "13800138001") {
		t.Error("stage2 doesn't show phone")
	}

	code := extractCode(t, console)
	if len(code) != 6 {
		t.Fatalf("code = %q", code)
	}

	// Stage 2 — verify + new password
	res, _ = do(t, h, "POST", "/user/forgot-password/verify",
		url.Values{"phone": {"13800138001"}, "code": {code}, "new_password": {"new-password-456"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("verify: %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "ok=password_reset") {
		t.Errorf("verify location: %s", loc)
	}

	// Old password is dead; new one works.
	res, _ = do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800138001"}, "password": {"old-password-123"}}, nil)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "bad_credentials") {
		t.Errorf("old password should fail: %s", res.Header.Get("Location"))
	}
	res, _ = do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800138001"}, "password": {"new-password-456"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("new login: %d", res.StatusCode)
	}
	if cookieJar(res)["rb_user"] == "" {
		t.Error("new login didn't produce rb_user cookie")
	}

	// The reset row should be gone (verify deletes it on success).
	user, _ := app.DB.GetUserByPhone(context.Background(), "13800138001")
	row, _ := app.DB.GetActivePasswordReset(context.Background(), user.ID)
	if row != nil {
		t.Errorf("reset row should be deleted after success, got %+v", row)
	}
}

func TestForgotPasswordWrongCodeThenSuccess(t *testing.T) {
	app := setupTestApp(t)
	console := withConsoleSMS(t, app)
	h := app.Routes()

	registerUserForReset(t, h, "13800138002", "original-pw")

	jar, csrf := jarWithCSRF(t, h)

	// Issue
	res, _ := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13800138002"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("issue: %d", res.StatusCode)
	}
	code := extractCode(t, console)

	// One wrong attempt — should re-render stage 2 with bad_code.
	res, body := do(t, h, "POST", "/user/forgot-password/verify",
		url.Values{"phone": {"13800138002"}, "code": {"000000"}, "new_password": {"another-pw-789"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("wrong code: %d", res.StatusCode)
	}
	if !strings.Contains(body, "验证码错误") {
		t.Errorf("missing bad_code banner; body=%s", truncate(body, 300))
	}

	// Right code — succeeds.
	res, _ = do(t, h, "POST", "/user/forgot-password/verify",
		url.Values{"phone": {"13800138002"}, "code": {code}, "new_password": {"another-pw-789"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("good verify: %d", res.StatusCode)
	}
}

func TestForgotPasswordExceedsAttemptCap(t *testing.T) {
	app := setupTestApp(t)
	withConsoleSMS(t, app)
	h := app.Routes()

	registerUserForReset(t, h, "13800138003", "starter-pw")
	jar, csrf := jarWithCSRF(t, h)

	// Issue code
	if res, _ := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13800138003"}, "_csrf": {csrf}}, jar); res.StatusCode != 200 {
		t.Fatalf("issue: %d", res.StatusCode)
	}

	// Burn 5 wrong attempts → row deleted on the 5th.
	for i := 0; i < 5; i++ {
		do(t, h, "POST", "/user/forgot-password/verify",
			url.Values{"phone": {"13800138003"}, "code": {"111111"}, "new_password": {"newpw1234"}, "_csrf": {csrf}}, jar)
	}

	// Row must be gone.
	user, _ := app.DB.GetUserByPhone(context.Background(), "13800138003")
	row, _ := app.DB.GetActivePasswordReset(context.Background(), user.ID)
	if row != nil {
		t.Fatalf("row should be deleted after %d failed attempts", pwResetMaxAttempts)
	}

	// 6th attempt — even with a correct-shape code, hits "expired" because no row.
	res, body := do(t, h, "POST", "/user/forgot-password/verify",
		url.Values{"phone": {"13800138003"}, "code": {"123456"}, "new_password": {"newpw1234"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("post-cap status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "验证码已过期") && !strings.Contains(body, "验证次数过多") {
		t.Errorf("post-cap banner unexpected; body=%s", truncate(body, 300))
	}
}

func TestForgotPasswordUnknownPhoneSilentSuccess(t *testing.T) {
	app := setupTestApp(t)
	console := withConsoleSMS(t, app)
	h := app.Routes()
	jar, csrf := jarWithCSRF(t, h)

	// Phone never registered. Stage 1 should still advance to stage 2 (no enumeration).
	res, body := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13900000000"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "请输入收到的 6 位数字验证码") {
		t.Error("should advance to stage 2 even for unknown phone")
	}
	// But no SMS was actually sent.
	if len(console.Recent()) != 0 {
		t.Errorf("no SMS should be sent for unknown phone; got %d", len(console.Recent()))
	}
}

func TestForgotPasswordRateLimitPerPhone(t *testing.T) {
	app := setupTestApp(t)
	withConsoleSMS(t, app)
	// Tighten the limiter to 1/hour so the test is deterministic.
	app.pwResetIssuePhoneLimit = newRateLimiter(1, time.Hour)
	h := app.Routes()

	registerUserForReset(t, h, "13800138004", "first-pw")
	jar, csrf := jarWithCSRF(t, h)

	// First request — allowed.
	res, _ := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13800138004"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("first: %d", res.StatusCode)
	}

	// Second — rate limited, stays on stage 1 with banner.
	res, body := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13800138004"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("second: %d", res.StatusCode)
	}
	if !strings.Contains(body, "请求过于频繁") {
		t.Errorf("expected rate-limited banner; body=%s", truncate(body, 300))
	}
}

func TestForgotPasswordSMSUnavailableRedirects(t *testing.T) {
	app := setupTestApp(t)
	// app.SMS comes back as a no-op Sender with P=nil → Available()==false.
	if app.SMS.Available() {
		t.Fatal("expected SMS unavailable in setupTestApp")
	}
	h := app.Routes()

	res, _ := do(t, h, "GET", "/user/forgot-password", nil, nil)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "sms_unavailable") {
		t.Errorf("redirect location: %s", loc)
	}
}

func TestForgotPasswordLoginPageOmitsLinkWhenSMSOff(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	_, body := do(t, h, "GET", "/user/login", nil, nil)
	if strings.Contains(body, "/user/forgot-password") {
		t.Error("login page must not link to forgot-password when SMS disabled")
	}

	// Wire up SMS and re-render.
	withConsoleSMS(t, app)
	h = app.Routes()
	_, body = do(t, h, "GET", "/user/login", nil, nil)
	if !strings.Contains(body, "/user/forgot-password") {
		t.Error("login page should link to forgot-password when SMS enabled")
	}
}

func TestForgotPasswordVerifyMissingRowExpired(t *testing.T) {
	app := setupTestApp(t)
	withConsoleSMS(t, app)
	h := app.Routes()

	registerUserForReset(t, h, "13800138005", "secret-pw")
	jar, csrf := jarWithCSRF(t, h)

	// Submit verify without ever issuing a code.
	res, body := do(t, h, "POST", "/user/forgot-password/verify",
		url.Values{"phone": {"13800138005"}, "code": {"123456"}, "new_password": {"newone789"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "验证码已过期") {
		t.Errorf("expected expired banner; body=%s", truncate(body, 300))
	}
}

func TestForgotPasswordVerifyDoesNotEnumerateAccounts(t *testing.T) {
	// Probing /verify with a made-up code must answer identically for an
	// unregistered phone and a registered phone that never requested a
	// reset. Pre-v0.106 the former said 验证码错误 and the latter 已过期 —
	// a free registration oracle that never even triggered an SMS.
	app := setupTestApp(t)
	withConsoleSMS(t, app)
	h := app.Routes()

	registerUserForReset(t, h, "13800138008", "real-user-pw")
	jar, csrf := jarWithCSRF(t, h)

	probe := func(phone string) string {
		res, body := do(t, h, "POST", "/user/forgot-password/verify",
			url.Values{"phone": {phone}, "code": {"123456"}, "new_password": {"whatever789"}, "_csrf": {csrf}}, jar)
		if res.StatusCode != 200 {
			t.Fatalf("probe %s: %d", phone, res.StatusCode)
		}
		return body
	}

	registered := probe("13800138008")   // exists, no reset pending
	unregistered := probe("13800130000") // does not exist

	for _, banner := range []string{"验证码已过期", "验证码错误"} {
		if strings.Contains(registered, banner) != strings.Contains(unregistered, banner) {
			t.Errorf("banner %q differs between registered and unregistered phone — enumeration oracle", banner)
		}
	}
	if !strings.Contains(unregistered, "验证码已过期") {
		t.Errorf("expected uniform expired banner; body=%s", truncate(unregistered, 300))
	}
}

func TestForgotPasswordSuspendedUserSilent(t *testing.T) {
	app := setupTestApp(t)
	console := withConsoleSMS(t, app)
	h := app.Routes()

	registerUserForReset(t, h, "13800138006", "doomed-pw")
	user, _ := app.DB.GetUserByPhone(context.Background(), "13800138006")
	if err := app.DB.SuspendUser(context.Background(), user.ID, true); err != nil {
		t.Fatal(err)
	}

	jar, csrf := jarWithCSRF(t, h)
	res, _ := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13800138006"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if n := len(console.Recent()); n != 0 {
		t.Errorf("suspended user should not get SMS; got %d", n)
	}
}

func TestPasswordResetCodeHashIsBcrypt(t *testing.T) {
	app := setupTestApp(t)
	withConsoleSMS(t, app)
	h := app.Routes()

	registerUserForReset(t, h, "13800138007", "any-old-pw")
	jar, csrf := jarWithCSRF(t, h)
	res, _ := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13800138007"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("issue: %d", res.StatusCode)
	}

	user, _ := app.DB.GetUserByPhone(context.Background(), "13800138007")
	row, err := app.DB.GetActivePasswordReset(context.Background(), user.ID)
	if err != nil || row == nil {
		t.Fatalf("expected reset row; err=%v row=%v", err, row)
	}
	// Cost > 0 + recognized prefix → genuine bcrypt hash.
	if cost, err := bcrypt.Cost([]byte(row.CodeHash)); err != nil || cost < 4 {
		t.Errorf("not a bcrypt hash: cost=%d err=%v hash=%q", cost, err, row.CodeHash)
	}
	if len(row.CodeHash) < 50 {
		t.Errorf("hash too short: %q", row.CodeHash)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
