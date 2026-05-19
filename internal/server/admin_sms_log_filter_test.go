package server

import (
	"context"
	"strings"
	"testing"
)

// /admin/sms-log?phone=X should restrict the DB-backed table to rows for
// that phone only.
func TestAdminSMSLogFilterByPhone(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogSMS(ctx, "console", "13800340001", "for-A", true, "")
	_ = app.DB.LogSMS(ctx, "console", "13800340002", "for-B", true, "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log?phone=13800340001", nil, jar)
	if !strings.Contains(body, "for-A") {
		t.Error("filtered page should still show matching message")
	}
	if strings.Contains(body, "for-B") {
		t.Error("filter let non-matching phone through")
	}
}

func TestAdminSMSLogFilterOnlyFailed(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogSMS(ctx, "console", "13800340010", "ok-msg", true, "")
	_ = app.DB.LogSMS(ctx, "console", "13800340010", "fail-msg", false, "boom")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log?only_failed=1", nil, jar)
	if !strings.Contains(body, "fail-msg") {
		t.Error("only_failed should show FAIL row")
	}
	if strings.Contains(body, "ok-msg") {
		t.Error("only_failed should NOT show OK row")
	}
}

func TestAdminSMSLogPageRendersFilterControls(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log", nil, jar)
	if !strings.Contains(body, `name="phone"`) {
		t.Error("phone filter input missing")
	}
	if !strings.Contains(body, `name="only_failed"`) {
		t.Error("only_failed checkbox missing")
	}
	if !strings.Contains(body, "按手机号过滤") {
		t.Error("phone filter placeholder missing")
	}
}
