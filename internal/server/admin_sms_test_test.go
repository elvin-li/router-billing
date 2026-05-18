package server

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"router-billing/internal/sms"
)

func TestAdminSMSTestSendsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/sms-log/test",
		url.Values{
			"_csrf":   {csrf},
			"phone":   {"13800141500"},
			"message": {"hello from admin"},
		}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=sent") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}

	recs := console.Recent()
	if len(recs) != 1 || recs[0].Phone != "13800141500" || recs[0].Message != "hello from admin" {
		t.Errorf("console didn't record the test send: %+v", recs)
	}

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "sms_test" && e.Target == "13800141500" {
			found = true
			if !strings.Contains(e.Detail, "provider=console") {
				t.Errorf("audit detail should mention provider; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("sms_test should land in audit log")
	}
}

func TestAdminSMSTestRejectsBadPhone(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/sms-log/test",
		url.Values{"_csrf": {csrf}, "phone": {"abc"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "bad_phone") {
		t.Errorf("expected bad_phone err; got %s", res.Header.Get("Location"))
	}
}

func TestAdminSMSTestRejectedWhenProviderDisabled(t *testing.T) {
	app := setupTestApp(t)
	// app.SMS is the no-op Sender by default in setupTestApp.
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/sms-log/test",
		url.Values{"_csrf": {csrf}, "phone": {"13800141501"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "sms_disabled") {
		t.Errorf("expected sms_disabled err; got %s", res.Header.Get("Location"))
	}
}

func TestAdminSMSLogPageShowsTestFormWhenProviderEnabled(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log", nil, jar)
	if !strings.Contains(body, "发送测试短信") {
		t.Error("page should show test-send form when provider is enabled")
	}
	if !strings.Contains(body, `action="/admin/sms-log/test"`) {
		t.Error("page should have a form posting to /admin/sms-log/test")
	}
}

func TestAdminSMSLogPageHidesTestFormWhenDisabled(t *testing.T) {
	app := setupTestApp(t)
	// app.SMS is the no-op Sender — Available()==false.
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log", nil, jar)
	if strings.Contains(body, "发送测试短信") {
		t.Error("test-send form should be hidden when provider is disabled")
	}
}

func TestAdminSMSTestDefaultMessageWhenEmpty(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	do(t, h, "POST", "/admin/sms-log/test",
		url.Values{"_csrf": {csrf}, "phone": {"13800141502"}, "message": {""}}, jar)
	recs := console.Recent()
	if len(recs) != 1 {
		t.Fatalf("expected 1 sms; got %d", len(recs))
	}
	if !strings.HasPrefix(recs[0].Message, "router-billing test") {
		t.Errorf("default message should start with 'router-billing test'; got %q", recs[0].Message)
	}
}
