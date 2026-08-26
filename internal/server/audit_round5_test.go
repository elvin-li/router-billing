package server

// Round-5 security audit regression tests (admin UI / API / templates):
//
//  1. /api/admin/sms/log must redact message bodies for read-only tokens
//     (they can carry live temp passwords and password-reset codes).
//  2. Public /health must not leak raw DB driver errors when degraded.
//  3. errLabel must never echo an unrecognized ?err= code into the admin
//     flash box (reflected content injection on every admin page).
//  4. Numeric flash params round-tripped via Query0 (reset_uid, count, …)
//     must be laundered to digits before templates interpolate them.
//  5. The public /redeem page must only render allowlisted flash text and
//     shape-validated days/expires_at; redeemErrLabel must not surface
//     internal DB error strings.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/sms"
)

// --- 1. /api/admin/sms/log scope-sensitive payload ---

func TestAPISMSLogReadonlyRedactsMessages(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_ro", Label: "monitor", ReadOnly: true},
		{Token: "rb_full", Label: "ops"},
	}
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}

	// This is exactly what /admin/users/reset-password (via_sms) sends:
	// the raw temp password as the whole message body.
	const tempPassword = "s3cretTempPw9"
	if err := app.SendSMS(context.Background(), "13800300001", tempPassword); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()

	// Read-only token: row visible, body gone, redaction flagged.
	rr := apiReq(t, h, "GET", "/api/admin/sms/log", "rb_ro", "")
	if rr.Code != 200 {
		t.Fatalf("readonly GET: %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), tempPassword) {
		t.Fatalf("read-only token can read a live temp password: %s", rr.Body.String())
	}
	var roResp struct {
		Logs []struct {
			Phone   string `json:"phone"`
			Message string `json:"message"`
			Success bool   `json:"success"`
		} `json:"logs"`
		Count            int  `json:"count"`
		MessagesRedacted bool `json:"messages_redacted"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &roResp); err != nil {
		t.Fatal(err)
	}
	if roResp.Count != 1 || len(roResp.Logs) != 1 {
		t.Fatalf("readonly should still see the row (metadata is the monitoring use-case): %+v", roResp)
	}
	if roResp.Logs[0].Message != "" {
		t.Errorf("message not redacted: %q", roResp.Logs[0].Message)
	}
	if roResp.Logs[0].Phone != "13800300001" || !roResp.Logs[0].Success {
		t.Errorf("metadata should survive redaction: %+v", roResp.Logs[0])
	}
	if !roResp.MessagesRedacted {
		t.Error("messages_redacted marker missing — callers can't tell redaction from empty SMS")
	}

	// Full token: body intact, no redaction marker.
	rr = apiReq(t, h, "GET", "/api/admin/sms/log", "rb_full", "")
	if rr.Code != 200 {
		t.Fatalf("full GET: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), tempPassword) {
		t.Errorf("full-scope token lost message bodies: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "messages_redacted") {
		t.Errorf("full-scope response should not carry the redaction marker: %s", rr.Body.String())
	}
}

// Failure metadata (the actual monitoring use-case) must survive redaction.
func TestAPISMSLogReadonlyKeepsFailureMetadata(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	app.SMS = &sms.Sender{P: &failingProvider{msg: "creds expired"}}
	_ = app.SendSMS(context.Background(), "13800300002", "reset code 123456")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sms/log?only_failed=1", "rb_ro", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var resp struct {
		Logs []struct {
			Message  string `json:"message"`
			Success  bool   `json:"success"`
			ErrorMsg string `json:"error_msg"`
		} `json:"logs"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Logs) != 1 {
		t.Fatalf("expected 1 failed row; got %d", len(resp.Logs))
	}
	if resp.Logs[0].Success || resp.Logs[0].ErrorMsg == "" {
		t.Errorf("failure metadata lost: %+v", resp.Logs[0])
	}
	if resp.Logs[0].Message != "" {
		t.Errorf("message should be redacted even on failed rows: %q", resp.Logs[0].Message)
	}
}

// --- 2. public /health must not leak driver errors ---

func TestPublicHealthDegradedHidesDBError(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Wedge the DB: subsequent queries fail with "sql: database is closed".
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}

	res, body := do(t, h, "GET", "/health", nil, nil)
	if res.StatusCode != 503 {
		t.Fatalf("degraded health should be 503; got %d body=%s", res.StatusCode, body)
	}
	if !strings.Contains(body, "db unreachable") {
		t.Errorf("expected generic error marker; got %s", body)
	}
	// The raw driver text (and anything path-shaped) must stay server-side.
	for _, banned := range []string{"database is closed", "sql:", "sqlite", ".db"} {
		if strings.Contains(body, banned) {
			t.Errorf("public /health leaks driver detail %q: %s", banned, body)
		}
	}
}

// --- 3. errLabel: unknown codes never echo ---

func TestErrLabelNeverEchoesUnknownCode(t *testing.T) {
	injected := "Session expired - call 13800000000 to verify"
	if got := errLabel(injected); got == injected || strings.Contains(got, "13800000000") {
		t.Fatalf("errLabel echoed attacker text: %q", got)
	}
	if got := errLabel("totally_unknown_code"); got != "操作失败，请重试" {
		t.Errorf("unknown code should collapse to the generic label; got %q", got)
	}
	// Codes that used to fall through to the raw string now have labels.
	for _, code := range []string{
		"bad_phone", "sms_disabled", "sms_failed", "trim_failed",
		"optimize_failed", "expire_failed", "webhook_not_configured",
		"cancel_stale_failed", "missing_order", "not_pending",
		"empty_note", "invalid", "digest_no_phone",
	} {
		if got := errLabel(code); got == code || got == "" {
			t.Errorf("code %q should map to a human label; got %q", code, got)
		}
	}
	// Existing mappings unchanged.
	if got := errLabel("invalid_mac"); got != "MAC 格式不正确" {
		t.Errorf("invalid_mac regressed: %q", got)
	}
	if got := errLabel(""); got != "" {
		t.Errorf("empty code must stay empty; got %q", got)
	}
}

// End-to-end: a crafted ?err= link must not surface its text on an admin page.
func TestAdminPageDoesNotReflectErrQuery(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	const evil = "URGENT-call-13800000000-to-unlock"
	res, body := do(t, h, "GET", "/admin/macs?err="+evil, nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if strings.Contains(body, evil) {
		t.Error("attacker-controlled ?err= text reflected into the admin flash")
	}
}

// --- 4. numeric flash params laundered ---

func TestDigitsOnly(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"42", "42"},
		{"13800-call-me", "13800"},
		{"<script>7</script>", "7"},
		{"EVILTEXT", ""},
		{"123456789012345678", "123456789012"}, // capped at 12
	}
	for _, c := range cases {
		if got := digitsOnly(c.in, 12); got != c.want {
			t.Errorf("digitsOnly(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAdminUsersFlashResetUIDSanitized(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	const evil = "99EVIL-wire-money-now"
	res, body := do(t, h, "GET", "/admin/users?ok=reset_2fa&reset_uid="+evil, nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if strings.Contains(body, evil) || strings.Contains(body, "wire-money-now") {
		t.Error("free text injected into the reset-2fa flash via reset_uid")
	}
	if !strings.Contains(body, "#99") {
		t.Error("digits of reset_uid should still render")
	}
}

// --- 5. public /redeem page hardening ---

func TestRedeemPageErrAllowlist(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Unknown text collapses to the generic label.
	const evil = "WiFi-maintenance-send-payment-to-13800000000"
	res, body := do(t, h, "GET", "/redeem?err="+evil, nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if strings.Contains(body, evil) {
		t.Error("attacker-controlled ?err= text reflected on the public redeem page")
	}
	if !strings.Contains(body, redeemGenericErr) {
		t.Error("generic error label should render for unknown codes")
	}

	// A message the server actually redirects with still renders verbatim.
	res, body = do(t, h, "GET", "/redeem?err="+"该充值码已被使用", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "该充值码已被使用") {
		t.Error("legitimate server-issued flash message got swallowed")
	}
}

func TestRedeemPageSuccessParamsSanitized(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	res, body := do(t, h, "GET",
		"/redeem?ok=1&days=30-FREE-FOREVER&expires_at=CALL-13800000000", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if strings.Contains(body, "FREE-FOREVER") || strings.Contains(body, "CALL-13800000000") {
		t.Error("free text injected into the redeem success banner")
	}
	if !strings.Contains(body, "<strong>30 天</strong>") {
		t.Error("numeric days should still render")
	}

	// A legitimate success redirect round-trips untouched.
	res, body = do(t, h, "GET", "/redeem?ok=1&days=30&expires_at=2026-09-25", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "2026-09-25") {
		t.Error("valid expires_at date got swallowed")
	}
}

func TestDateOnly(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"2026-09-25", "2026-09-25"},
		{"", ""},
		{"not-a-date!", ""},
		{"2026/09/25", ""},
		{"2026-09-25T00:00:00Z", ""},
		{"9999-99-99", "9999-99-99"}, // shape-valid is all we promise
	}
	for _, c := range cases {
		if got := dateOnly(c.in); got != c.want {
			t.Errorf("dateOnly(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedeemErrLabelHidesInternalError(t *testing.T) {
	internal := errors.New("disk I/O error at /srv/router-billing/billing.db")
	if got := redeemErrLabel(internal); got != redeemGenericErr {
		t.Errorf("internal DB error leaked to the public page: %q", got)
	}
	if isKnownRedeemErr(internal) {
		t.Error("random errors must not classify as known redeem errors")
	}
}
