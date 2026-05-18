package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"router-billing/internal/sms"
)

func TestAdminLoginAlertSendsWhenConfigured(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	app.Cfg.SMS.AdminLoginAlertPhone = "13800144000"

	h := app.Routes()
	// Force a login by username "admin" / password "admin-pw" — same shape
	// the integration tests use via loginAdmin.
	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("login: %d", res.StatusCode)
	}

	// The alert SMS fires in a detached goroutine — give it a moment.
	deadline := time.After(2 * time.Second)
	for {
		if len(console.Recent()) >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("admin-login alert SMS never sent")
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}

	recs := console.Recent()
	if recs[0].Phone != "13800144000" {
		t.Errorf("alert phone: %s", recs[0].Phone)
	}
	if !strings.Contains(recs[0].Message, "admin") {
		t.Errorf("alert body should mention username; got %s", recs[0].Message)
	}

	// Audit entry written too (best-effort: poll briefly).
	deadline2 := time.After(2 * time.Second)
	for {
		entries, _ := app.DB.ListAudit(context.Background(), 50)
		found := false
		for _, e := range entries {
			if e.Action == "admin_login_alert_sent" {
				found = true
			}
		}
		if found {
			return
		}
		select {
		case <-deadline2:
			t.Fatal("admin_login_alert_sent audit entry never written")
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestAdminLoginAlertSkippedWhenPhoneUnset(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	// AdminLoginAlertPhone left empty.

	h := app.Routes()
	do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)

	// Wait the same window the configured-path test would use — confirm
	// NO SMS lands.
	time.Sleep(150 * time.Millisecond)
	if n := len(console.Recent()); n != 0 {
		t.Errorf("alert phone is empty; no SMS should be sent. got %d", n)
	}
}

func TestAdminLoginAlertSkippedWhenSMSDisabled(t *testing.T) {
	app := setupTestApp(t)
	// app.SMS is the no-op Sender — Available()==false.
	app.Cfg.SMS.AdminLoginAlertPhone = "13800144001"

	h := app.Routes()
	// This should not panic. Without SMS the maybeAlertAdminLogin path is
	// a no-op (verified by the goroutine never running anything).
	res, _ := do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("login: %d", res.StatusCode)
	}
	// No way to assert "no SMS sent" since there's nothing to record into,
	// but the test would fail with a panic if maybeAlertAdminLogin
	// tried to send through a nil provider.
}

func TestAdminLoginAlertInvalidPhoneSkipped(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	app.Cfg.SMS.AdminLoginAlertPhone = "not-a-phone"

	h := app.Routes()
	do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)

	time.Sleep(150 * time.Millisecond)
	if n := len(console.Recent()); n != 0 {
		t.Errorf("invalid phone in config should skip the alert; got %d sms", n)
	}
}

func TestAdminLoginAuditEntryWritten(t *testing.T) {
	// Independent of the alert: issueAdminSession should ALWAYS write a
	// successful-login audit entry (this was missing pre-v0.17).
	app := setupTestApp(t)
	h := app.Routes()
	do(t, h, "POST", "/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}}, nil)

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "login" && e.Actor == "admin:admin" {
			found = true
			if !strings.Contains(e.Detail, "ip=") {
				t.Errorf("audit detail should include ip; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("expected admin login audit entry")
	}
}
