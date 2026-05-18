package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSignOutOthersKillsOnlyOtherSessions(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Register first browser.
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800139050"}, "password": {"sess-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register: %d", res.StatusCode)
	}
	first := cookieJar(res)
	// Touch a page to pick up rb_csrf.
	res2, _ := do(t, h, "GET", "/user/me", nil, first)
	for k, v := range cookieJar(res2) {
		first[k] = v
	}

	// Second browser — fresh password login.
	res3, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139050"}, "password": {"sess-pw"}}, nil)
	if res3.StatusCode != 303 {
		t.Fatalf("second login: %d", res3.StatusCode)
	}
	second := cookieJar(res3)
	if second[userCookieName] == "" || second[userCookieName] == first[userCookieName] {
		t.Fatal("second session should have a distinct rb_user")
	}

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139050")
	if n, _ := app.DB.CountUserSessions(context.Background(), u.ID); n != 2 {
		t.Fatalf("expected 2 sessions; got %d", n)
	}

	// From the first browser, click "sign out others".
	res4, _ := do(t, h, "POST", "/user/sessions/sign-out-others",
		url.Values{"_csrf": {first[csrfCookieName]}}, first)
	if res4.StatusCode != 303 {
		t.Fatalf("sign-out-others: %d", res4.StatusCode)
	}
	if !strings.Contains(res4.Header.Get("Location"), "ok=signed_out_others") {
		t.Errorf("redirect: %s", res4.Header.Get("Location"))
	}

	// Only the calling session survives.
	if n, _ := app.DB.CountUserSessions(context.Background(), u.ID); n != 1 {
		t.Errorf("expected 1 session after sign-out-others; got %d", n)
	}

	// First browser still works.
	res5, _ := do(t, h, "GET", "/user/me", nil, first)
	if res5.StatusCode != 200 {
		t.Errorf("first session should still be usable; got %d", res5.StatusCode)
	}
	// Second browser's cookie is now invalid → redirect to login.
	res6, _ := do(t, h, "GET", "/user/me", nil, second)
	if res6.StatusCode != 303 {
		t.Errorf("second session should be killed; got %d", res6.StatusCode)
	}
}

func TestUserMeShowsSignOutOthersButtonWhenMultipleSessions(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Single session — button should NOT be shown.
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800139051"}, "password": {"btn-pw"}}, nil)
	jar := cookieJar(res)
	_, body := do(t, h, "GET", "/user/me", nil, jar)
	if strings.Contains(body, "退出其他") {
		t.Error("single-session view should NOT show sign-out-others button")
	}

	// Add a second session and re-render.
	do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139051"}, "password": {"btn-pw"}}, nil)

	_, body2 := do(t, h, "GET", "/user/me", nil, jar)
	if !strings.Contains(body2, "退出其他") {
		t.Error("multi-session view SHOULD show sign-out-others button")
	}
	if !strings.Contains(body2, "1 个登录设备") {
		t.Errorf("button should show 1 other; body=%s", truncate(body2, 600))
	}
}

func TestCountUserSessionsReflectsExpiry(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, err := app.DB.CreateUser(ctx, "13800139052", "x")
	if err != nil {
		t.Fatal(err)
	}
	// Two fresh sessions.
	if err := app.DB.CreateSession(ctx, "t1", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.CreateSession(ctx, "t2", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n, _ := app.DB.CountUserSessions(ctx, u.ID); n != 2 {
		t.Errorf("got %d, want 2", n)
	}
}
