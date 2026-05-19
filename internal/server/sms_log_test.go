package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"router-billing/internal/sms"
)

// SendSMS must:
//  1. Call the underlying provider
//  2. Always record a row in sms_log (success OR failure)
//  3. Return the provider's error verbatim
func TestSendSMSRecordsSuccess(t *testing.T) {
	app := setupTestApp(t)
	// Console provider always succeeds.
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}

	err := app.SendSMS(context.Background(), "13800190001", "hello world")
	if err != nil {
		t.Fatal(err)
	}

	logs, _ := app.DB.RecentSMSLogs(context.Background(), 10)
	if len(logs) == 0 {
		t.Fatal("sms_log row not written")
	}
	e := logs[0]
	if e.Provider != "console" || e.Phone != "13800190001" || !e.Success {
		t.Errorf("unexpected row: %+v", e)
	}
	if e.Message != "hello world" {
		t.Errorf("message not preserved: %q", e.Message)
	}
}

// failingProvider always returns the same error so we can test the failure-
// recording path without flakiness.
type failingProvider struct{ msg string }

func (f *failingProvider) Send(_ context.Context, _, _ string) error { return errors.New(f.msg) }
func (f *failingProvider) Name() string                              { return "fail" }

func TestSendSMSRecordsFailure(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: &failingProvider{msg: "upstream timeout"}}

	err := app.SendSMS(context.Background(), "13800190002", "ping")
	if err == nil || err.Error() != "upstream timeout" {
		t.Errorf("expected upstream-timeout error; got %v", err)
	}

	logs, _ := app.DB.RecentSMSLogs(context.Background(), 5)
	if len(logs) == 0 {
		t.Fatal("failure should still be logged")
	}
	e := logs[0]
	if e.Success {
		t.Errorf("row should be marked failed; got %+v", e)
	}
	if !strings.Contains(e.ErrorMsg, "upstream timeout") {
		t.Errorf("error_msg should capture the provider error; got %q", e.ErrorMsg)
	}
	if e.Provider != "fail" {
		t.Errorf("provider name not captured: %q", e.Provider)
	}
}

func TestRecentSMSLogsOrdersByIDDesc(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}

	for i, msg := range []string{"first", "second", "third"} {
		_ = app.SendSMS(context.Background(), "13800190010", msg)
		_ = i
	}
	logs, _ := app.DB.RecentSMSLogs(context.Background(), 10)
	if len(logs) < 3 {
		t.Fatalf("expected at least 3 logs; got %d", len(logs))
	}
	// Newest first.
	if logs[0].Message != "third" || logs[1].Message != "second" || logs[2].Message != "first" {
		t.Errorf("order should be newest-first; got %+v", []string{logs[0].Message, logs[1].Message, logs[2].Message})
	}
}

// purgeLoop's sms_log trim should respect AuditLogKeep.
func TestPurgeSMSLogRespectsKeepCap(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	for i := 0; i < 20; i++ {
		_ = app.SendSMS(context.Background(), "13800190099", "spam")
	}
	if err := app.DB.PurgeSMSLog(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	logs, _ := app.DB.RecentSMSLogs(context.Background(), 100)
	if len(logs) != 5 {
		t.Errorf("purge to 5 should leave 5; got %d", len(logs))
	}
}

func TestAdminSMSLogPageShowsDBSection(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	_ = app.SendSMS(context.Background(), "13800190015", "from-db-test")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log", nil, jar)
	if !strings.Contains(body, "持久化发送记录") {
		t.Error("page should have DB log section header")
	}
	if !strings.Contains(body, "from-db-test") {
		t.Error("page should render the just-logged message")
	}
}
