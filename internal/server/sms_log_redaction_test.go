package server

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"router-billing/internal/db"
)

// These tests pin the v0.119 secret-in-logs fix: sms_log rows are exposed
// to /admin/sms-log and — by design — to READ-ONLY API tokens via
// GET /api/admin/sms/log ("delivery state, not auth material"). Messages
// carrying a live credential must therefore be redacted before they are
// persisted, while the actual delivery (console ring in dev, provider in
// prod) still carries the real body.

// The forgot-password reset code must never land in sms_log: with the old
// behavior any read-only monitoring token could request a reset for a
// victim's phone (public endpoint), read the live 6-digit code from the
// log within its 10-minute TTL, and take over the account.
func TestForgotPasswordCodeNotPersistedInSMSLog(t *testing.T) {
	app := setupTestApp(t)
	console := withConsoleSMS(t, app)
	h := app.Routes()

	registerUserForReset(t, h, "13800177001", "old-password-123")
	jar, csrf := jarWithCSRF(t, h)

	res, _ := do(t, h, "POST", "/user/forgot-password",
		url.Values{"phone": {"13800177001"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 200 {
		t.Fatalf("stage1: %d", res.StatusCode)
	}

	// The DELIVERED message (console ring) must still contain the code —
	// that is the delivery channel, not the log.
	code := extractCode(t, console)

	rows, err := app.DB.SearchSMSLogs(context.Background(), db.SMSLogFilter{Phone: "13800177001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 sms_log row, got %d", len(rows))
	}
	if strings.Contains(rows[0].Message, code) {
		t.Fatalf("sms_log row contains the live reset code: %q", rows[0].Message)
	}
	if !strings.Contains(rows[0].Message, strings.Repeat("*", pwResetCodeLen)) {
		t.Errorf("sms_log row should carry the redacted body, got %q", rows[0].Message)
	}
	// Shape (prefix/suffix) is preserved so operators still recognize the
	// message kind when troubleshooting delivery.
	if !strings.Contains(rows[0].Message, "密码重置验证码") {
		t.Errorf("redacted row lost the message shape: %q", rows[0].Message)
	}

	// The code the user received must still work end-to-end.
	res, _ = do(t, h, "POST", "/user/forgot-password/verify",
		url.Values{"phone": {"13800177001"}, "code": {code},
			"new_password": {"new-password-456"}, "_csrf": {csrf}}, jar)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "ok=password_reset") {
		t.Fatalf("verify with delivered code failed: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

// The admin-issued temporary password (reset-password via_sms) is a live
// credential too — the sms_log row must record that a reset SMS went out
// without storing the password itself.
func TestAdminTempPasswordNotPersistedInSMSLog(t *testing.T) {
	app := setupTestApp(t)
	console := withConsoleSMS(t, app)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	ctx := context.Background()

	u, err := app.DB.CreateUser(ctx, "13800177002", "old-hash")
	if err != nil {
		t.Fatal(err)
	}

	res, _ := do(t, h, "POST", "/admin/users/reset-password",
		url.Values{"_csrf": {csrf}, "id": {"1"}, "via_sms": {"1"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("reset-password: %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "ok=reset_sms") {
		t.Fatalf("expected via-SMS success redirect, got %q", loc)
	}

	// The delivered SMS body IS the temp password.
	recs := console.Recent()
	if len(recs) != 1 {
		t.Fatalf("expected 1 delivered SMS, got %d", len(recs))
	}
	tmpPwd := recs[0].Message
	if len(tmpPwd) < 8 {
		t.Fatalf("delivered temp password looks wrong: %q", tmpPwd)
	}

	rows, err := app.DB.SearchSMSLogs(ctx, db.SMSLogFilter{Phone: u.Phone})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 sms_log row, got %d", len(rows))
	}
	if strings.Contains(rows[0].Message, tmpPwd) {
		t.Fatalf("sms_log row contains the live temp password: %q", rows[0].Message)
	}
	if !rows[0].Success {
		t.Error("sms_log row should record a successful delivery")
	}
}

// Non-sensitive sends must keep persisting the full body — redaction is
// opt-in per call site, not a blanket behavior change.
func TestPlainSendSMSStillPersistsFullBody(t *testing.T) {
	app := setupTestApp(t)
	withConsoleSMS(t, app)

	if err := app.SendSMS(context.Background(), "13800177003", "hello full body"); err != nil {
		t.Fatal(err)
	}
	rows, err := app.DB.SearchSMSLogs(context.Background(), db.SMSLogFilter{Phone: "13800177003"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Message != "hello full body" {
		t.Fatalf("plain SendSMS should persist the full body, got %+v", rows)
	}
}
