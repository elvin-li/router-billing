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

// resetTOTPReplay clears the one-time-use ledger. Test helper for flows that
// legitimately verify more than once with the same secret inside a single
// 30-second step — a real authenticator would have rolled to a fresh code,
// but tests run far faster than the TOTP period.
func resetTOTPReplay() {
	totpUsedSteps.Lock()
	totpUsedSteps.m = map[[32]byte]int64{}
	totpUsedSteps.Unlock()
}

func TestTOTPConsumeStepRejectsReplay(t *testing.T) {
	resetTOTPReplay()
	if !totpConsumeStep("SECRETA", 100) {
		t.Fatal("first use of step 100 should be accepted")
	}
	if totpConsumeStep("SECRETA", 100) {
		t.Error("second use of the same step must be rejected")
	}
	if totpConsumeStep("SECRETA", 99) {
		t.Error("an older step must be rejected after a newer one was used")
	}
	if !totpConsumeStep("SECRETA", 101) {
		t.Error("the next step should be accepted")
	}
	// A different secret is an independent ledger.
	if !totpConsumeStep("SECRETB", 100) {
		t.Error("step 100 for a different secret should be accepted")
	}
}

func TestUser2FALoginRejectsReplayedCode(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139060", "replay-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139060")
	do(t, h, "POST", "/user/2fa/confirm", url.Values{"_csrf": {csrf}, "code": {code}}, jar)
	resetTOTPReplay()

	login2FA := func() (*http.Response, map[string]string) {
		res, _ := do(t, h, "POST", "/user/login",
			url.Values{"phone": {"13800139060"}, "password": {"replay-pw"}}, nil)
		pending := cookieJar(res)
		res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
		for k, v := range cookieJar(res2) {
			pending[k] = v
		}
		res3, _ := do(t, h, "POST", "/user/login/2fa",
			url.Values{"code": {code}, "_csrf": {pending[csrfCookieName]}}, pending)
		return res3, cookieJar(res3)
	}

	// First use of the code succeeds.
	res, cookies := login2FA()
	if res.StatusCode != 303 || cookies[userCookieName] == "" {
		t.Fatalf("first use should log in; status=%d", res.StatusCode)
	}
	// Immediate replay of the SAME code on a fresh login must be rejected —
	// RFC 6238 §5.2 (an OTP is valid at most once).
	res2, cookies2 := login2FA()
	if cookies2[userCookieName] != "" {
		t.Fatal("replayed TOTP code opened a second session")
	}
	if res2.StatusCode != 200 {
		t.Errorf("replay should re-render the challenge; status=%d", res2.StatusCode)
	}
}

func TestUser2FADisableRejectsReplayedCode(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139061", "replay2-pw")
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, "13800139061")
	do(t, h, "POST", "/user/2fa/confirm", url.Values{"_csrf": {csrf}, "code": {code}}, jar)
	resetTOTPReplay()

	// Log in on a second browser with the current code (consumes it) …
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139061"}, "password": {"replay2-pw"}}, nil)
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	res3, _ := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {code}, "_csrf": {pending[csrfCookieName]}}, pending)
	if res3.StatusCode != 303 {
		t.Fatalf("setup login: %d", res3.StatusCode)
	}

	// … then try to disable 2FA with the very same code from the first
	// session. Must be treated as a wrong code.
	res4, _ := do(t, h, "POST", "/user/2fa/disable",
		url.Values{"_csrf": {csrf}, "password": {"replay2-pw"}, "code": {code}}, jar)
	if !strings.Contains(res4.Header.Get("Location"), "2fa_failed") {
		t.Errorf("replayed code must not disable 2fa; got %s", res4.Header.Get("Location"))
	}
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139061")
	if u.TOTPSecret == "" {
		t.Fatal("2fa was disabled with a replayed code")
	}
}

func TestAdminLogin2FARejectsReplayedCode(t *testing.T) {
	app := setupTestApp(t)
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // distinct from other tests' secrets
	app.Cfg.Admin.TOTPSecret = secret
	h := app.Routes()
	resetTOTPReplay()

	code, err := totp.Code(secret, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	login2FA := func() (*http.Response, map[string]string) {
		res, _ := do(t, h, "POST", "/admin/login",
			url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
		jar := cookieJar(res)
		res2, _ := do(t, h, "POST", "/admin/login/2fa",
			url.Values{"code": {code}, "_csrf": {jar[csrfCookieName]}}, jar)
		return res2, cookieJar(res2)
	}

	res, cookies := login2FA()
	if res.StatusCode != 303 || cookies[adminCookieName] == "" {
		t.Fatalf("first use should log in; status=%d", res.StatusCode)
	}
	res2, cookies2 := login2FA()
	if cookies2[adminCookieName] != "" {
		t.Fatal("replayed TOTP code opened a second admin session")
	}
	if res2.StatusCode != 200 {
		t.Errorf("replay should re-render the challenge; status=%d", res2.StatusCode)
	}
}
