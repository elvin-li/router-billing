package server

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"router-billing/internal/sms"
)

func TestUserNotifyExpiryDefaultsOn(t *testing.T) {
	app := setupTestApp(t)
	u, err := app.DB.CreateUser(context.Background(), "13800148000", "h")
	if err != nil {
		t.Fatal(err)
	}
	if !u.NotifyExpiry {
		t.Error("new user should have NotifyExpiry = true by default")
	}
	// Re-fetch from DB to confirm schema default landed.
	u2, _ := app.DB.GetUserByPhone(context.Background(), "13800148000")
	if !u2.NotifyExpiry {
		t.Error("DB row default should be on")
	}
}

func TestUserToggleNotifyExpiryOff(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800148001"}, "password": {"opt-out-pw"}}, nil)
	jar := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/me", nil, jar)
	for k, v := range cookieJar(res2) {
		jar[k] = v
	}
	csrf := jar[csrfCookieName]

	// Posting with the checkbox UNchecked (no notify_expiry field) opts out.
	res3, body3 := do(t, h, "POST", "/user/notifications",
		url.Values{"_csrf": {csrf}}, jar)
	if res3.StatusCode != 303 {
		t.Fatalf("status: %d body=%s", res3.StatusCode, body3)
	}
	u, err := app.DB.GetUserByPhone(context.Background(), "13800148001")
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("user lookup returned nil — was it deleted?")
	}
	if u.NotifyExpiry {
		t.Error("after unchecked POST, NotifyExpiry should be false")
	}

	// Audit entry.
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "notify_expiry_off" {
			found = true
		}
	}
	if !found {
		t.Error("notify_expiry_off audit entry missing")
	}
}

func TestUserToggleNotifyExpiryBackOn(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800148002"}, "password": {"back-on-pw"}}, nil)
	jar := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/me", nil, jar)
	for k, v := range cookieJar(res2) {
		jar[k] = v
	}
	csrf := jar[csrfCookieName]

	// Opt off, then back on.
	do(t, h, "POST", "/user/notifications", url.Values{"_csrf": {csrf}}, jar)
	do(t, h, "POST", "/user/notifications",
		url.Values{"_csrf": {csrf}, "notify_expiry": {"on"}}, jar)

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800148002")
	if !u.NotifyExpiry {
		t.Error("after re-check, NotifyExpiry should be true again")
	}
}

func TestExpiryReminderSkipsOptedOutUser(t *testing.T) {
	// Regression guard: a user with NotifyExpiry=false should NOT get the
	// reminder SMS even with an eligible MAC.
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}

	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800148003", "h")
	if err := app.DB.SetUserNotifyExpiry(ctx, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:E2:01", "test", 2, &u.ID); err != nil {
		t.Fatal(err)
	}

	sent, _, _ := app.sendExpiryReminders(ctx)
	if sent != 0 {
		t.Errorf("opted-out user should not get reminder; sent=%d", sent)
	}
	if n := len(console.Recent()); n != 0 {
		t.Errorf("no SMS should be sent to opted-out user; got %d", n)
	}
}

func TestUserMePageShowsToggle(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800148004"}, "password": {"show-toggle-pw"}}, nil)
	jar := cookieJar(res)
	_, body := do(t, h, "GET", "/user/me", nil, jar)
	if !strings.Contains(body, "通知偏好") {
		t.Error("page should show 通知偏好 section")
	}
	if !strings.Contains(body, "套餐到期前 3 天 SMS 提醒") {
		t.Error("page should show toggle label")
	}
	if !strings.Contains(body, "checked") {
		t.Error("checkbox should be checked by default")
	}
}
