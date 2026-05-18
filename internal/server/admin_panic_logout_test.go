package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminPanicLogoutKillsAllOthers(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// Seed a couple of users + user sessions.
	u1, _ := app.DB.CreateUser(ctx, "13800147000", "h")
	u2, _ := app.DB.CreateUser(ctx, "13800147001", "h")
	_ = app.DB.CreateSession(ctx, "u1-tok", "user", u1.Phone, &u1.ID, time.Hour)
	_ = app.DB.CreateSession(ctx, "u2-tok", "user", u2.Phone, &u2.ID, time.Hour)

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	// Seed another admin session that should die.
	_ = app.DB.CreateSession(ctx, "other-admin-tok", "admin", "other", nil, time.Hour)

	res, _ := do(t, h, "POST", "/admin/sessions/panic",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=panic") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}

	// Both user sessions gone.
	if n, _ := app.DB.CountUserSessions(ctx, u1.ID); n != 0 {
		t.Errorf("user1 sessions should be 0; got %d", n)
	}
	if n, _ := app.DB.CountUserSessions(ctx, u2.ID); n != 0 {
		t.Errorf("user2 sessions should be 0; got %d", n)
	}
	// The other admin session is gone.
	if s, _ := app.DB.GetSession(ctx, "other-admin-tok"); s != nil {
		t.Error("other admin session should be killed")
	}
	// Calling admin's session still works.
	res2, _ := do(t, h, "GET", "/admin/sessions", nil, jar)
	if res2.StatusCode != 200 {
		t.Errorf("calling admin should still be logged in; got %d", res2.StatusCode)
	}

	// Audit entry with the counts.
	entries, _ := app.DB.ListAudit(ctx, 50)
	found := false
	for _, e := range entries {
		if e.Action == "panic_logout" {
			found = true
			if !strings.Contains(e.Detail, "admin_killed=1") {
				t.Errorf("detail should include admin_killed=1; got %q", e.Detail)
			}
			if !strings.Contains(e.Detail, "user_killed=2") {
				t.Errorf("detail should include user_killed=2; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("panic_logout audit entry missing")
	}
}

func TestAdminPanicLogoutPageButtonRenders(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sessions", nil, jar)
	if !strings.Contains(body, "🆘 应急") {
		t.Error("page should show panic section heading")
	}
	if !strings.Contains(body, `action="/admin/sessions/panic"`) {
		t.Error("page should have panic form")
	}
}

func TestDeleteAllUserSessions(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800147099", "h")
	_ = app.DB.CreateSession(ctx, "tok-a", "user", u.Phone, &u.ID, time.Hour)
	_ = app.DB.CreateSession(ctx, "tok-b", "user", u.Phone, &u.ID, time.Hour)
	// An admin session should NOT be killed.
	_ = app.DB.CreateSession(ctx, "tok-admin", "admin", "admin", nil, time.Hour)

	n, err := app.DB.DeleteAllUserSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 killed; got %d", n)
	}
	// Admin still alive.
	if s, _ := app.DB.GetSession(ctx, "tok-admin"); s == nil {
		t.Error("admin session should survive")
	}
}
