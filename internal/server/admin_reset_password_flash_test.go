package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestAdminResetPasswordNotInURL pins the v0.97 flash-store change: the
// temporary password from /admin/users/reset-password must never appear in
// the redirect URL (browser history / intermediary logs would keep a live
// credential). It travels via a one-shot server-side flash token instead,
// shows on exactly one page render, and is gone on reload.
func TestAdminResetPasswordNotInURL(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	ctx := context.Background()

	u, err := app.DB.CreateUser(ctx, "13800138111", "old-hash")
	if err != nil {
		t.Fatal(err)
	}

	res, _ := do(t, h, "POST", "/admin/users/reset-password",
		url.Values{"_csrf": {csrf}, "id": {"1"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("reset-password: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if strings.Contains(loc, "reset_pwd=") {
		t.Fatalf("redirect leaks the password in the URL: %q", loc)
	}
	if !strings.Contains(loc, "flash=") {
		t.Fatalf("redirect should carry a one-shot flash token: %q", loc)
	}

	// First render of the redirect target shows the temp password block.
	res2, body := do(t, h, "GET", loc, nil, jar)
	if res2.StatusCode != 200 {
		t.Fatalf("users page: %d", res2.StatusCode)
	}
	if !strings.Contains(body, "的临时密码：") {
		t.Error("first render should display the temp-password flash")
	}
	// Extract the displayed password and verify it matches the new hash.
	start := strings.Index(body, "font-size:15px;\">")
	if start < 0 {
		t.Fatal("temp password <code> block not found")
	}
	start += len("font-size:15px;\">")
	end := strings.Index(body[start:], "</code>")
	if end < 0 {
		t.Fatal("temp password </code> not found")
	}
	pwd := body[start : start+end]
	if len(pwd) < 8 {
		t.Fatalf("extracted temp password looks wrong: %q", pwd)
	}
	fresh, _ := app.DB.GetUser(ctx, u.ID)
	if bcrypt.CompareHashAndPassword([]byte(fresh.PasswordHash), []byte(pwd)) != nil {
		t.Error("displayed temp password does not match the stored hash")
	}

	// Reload: the flash token is consumed, nothing is displayed.
	_, body2 := do(t, h, "GET", loc, nil, jar)
	if strings.Contains(body2, "的临时密码：") {
		t.Error("second render must not re-display the temp-password flash block")
	}
	if strings.Contains(body2, pwd) {
		t.Error("second render must not contain the temp password anywhere")
	}
}

// TestFlashStoreExpiry pins the TTL + one-shot semantics at the unit level.
func TestFlashStoreExpiry(t *testing.T) {
	app := setupTestApp(t)

	tok := app.stashFlash("secret-1")
	if got := app.popFlash(tok); got != "secret-1" {
		t.Errorf("popFlash = %q, want secret-1", got)
	}
	if got := app.popFlash(tok); got != "" {
		t.Errorf("second pop must be empty, got %q", got)
	}
	if got := app.popFlash("no-such-token"); got != "" {
		t.Errorf("unknown token must be empty, got %q", got)
	}

	// Expired entries return nothing.
	tok2 := app.stashFlash("secret-2")
	app.flashMu.Lock()
	e := app.flashes[tok2]
	e.expires = time.Now().Add(-time.Second)
	app.flashes[tok2] = e
	app.flashMu.Unlock()
	if got := app.popFlash(tok2); got != "" {
		t.Errorf("expired token must be empty, got %q", got)
	}
}
