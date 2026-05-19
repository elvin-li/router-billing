package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestAdminSMSLogTrimRunsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security.AuditLogKeep = 3
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		_ = app.DB.LogSMS(ctx, "console", "13800210010", "spam", true, "")
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/maintenance/sms-log-trim",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=sms_log_trim") {
		t.Errorf("redirect should signal success; got %s", res.Header.Get("Location"))
	}
	logs, _ := app.DB.RecentSMSLogs(ctx, 100)
	if len(logs) > app.Cfg.Security.AuditLogRetention()+1 {
		t.Errorf("trim failed: %d rows remain", len(logs))
	}
	// Audit row.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "sms_log_trim" {
			found = true
		}
	}
	if !found {
		t.Error("sms_log_trim audit row missing")
	}
}

func TestAdminWebhookLogTrimRunsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security.AuditLogKeep = 3
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		_ = app.DB.LogWebhookDelivery(ctx, "spam", "", 0, 200, true, 1, "")
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/maintenance/webhook-log-trim",
		url.Values{"_csrf": {csrf}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "ok=webhook_log_trim") {
		t.Errorf("redirect should signal success; got %s", res.Header.Get("Location"))
	}
	logs, _ := app.DB.RecentWebhookDeliveries(ctx, 100, false)
	if len(logs) > app.Cfg.Security.AuditLogRetention()+1 {
		t.Errorf("trim failed: %d rows remain", len(logs))
	}
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "webhook_log_trim" {
			found = true
		}
	}
	if !found {
		t.Error("webhook_log_trim audit row missing")
	}
}

// GET should redirect (not fire) so a browser preload can't trim.
func TestAdminTrimButtonsRejectGET(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	for _, p := range []string{
		"/admin/maintenance/sms-log-trim",
		"/admin/maintenance/webhook-log-trim",
	} {
		res, _ := do(t, h, "GET", p, nil, jar)
		if res.StatusCode != 303 {
			t.Errorf("%s GET should redirect; got %d", p, res.StatusCode)
		}
	}
}

func TestAdminSMSLogPageShowsTrimButton(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log", nil, jar)
	if !strings.Contains(body, "/admin/maintenance/sms-log-trim") {
		t.Error("sms-log page missing trim button")
	}
}

func TestAdminWebhookLogPageShowsTrimButton(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/webhook-log", nil, jar)
	if !strings.Contains(body, "/admin/maintenance/webhook-log-trim") {
		t.Error("webhook-log page missing trim button")
	}
}
