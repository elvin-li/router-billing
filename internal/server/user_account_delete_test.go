package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestUserAccountDeleteRemovesUserOnCorrectPassword(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800145000"}, "password": {"goodbye-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register: %d", res.StatusCode)
	}
	jar := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/me", nil, jar)
	for k, v := range cookieJar(res2) {
		jar[k] = v
	}
	csrf := jar[csrfCookieName]

	res3, _ := do(t, h, "POST", "/user/account/delete",
		url.Values{"_csrf": {csrf}, "password": {"goodbye-pw"}}, jar)
	if res3.StatusCode != 303 {
		t.Fatalf("delete: %d", res3.StatusCode)
	}
	if !strings.Contains(res3.Header.Get("Location"), "/portal") {
		t.Errorf("expected redirect to /portal; got %s", res3.Header.Get("Location"))
	}

	// User row is gone.
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800145000")
	if u != nil {
		t.Errorf("user should be gone; got %+v", u)
	}

	// Session cookie is invalidated server-side AND wiped client-side.
	cleared := false
	for _, c := range res3.Cookies() {
		if c.Name == userCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("rb_user cookie should be wiped on the response")
	}

	// Audit entry written.
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "account_self_deleted" && e.Actor == "user:13800145000" {
			found = true
		}
	}
	if !found {
		t.Error("expected account_self_deleted audit entry")
	}
}

func TestUserAccountDeleteRejectsWrongPassword(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800145001"}, "password": {"correct-pw"}}, nil)
	jar := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/me", nil, jar)
	for k, v := range cookieJar(res2) {
		jar[k] = v
	}
	csrf := jar[csrfCookieName]

	resD, _ := do(t, h, "POST", "/user/account/delete",
		url.Values{"_csrf": {csrf}, "password": {"WRONG"}}, jar)
	if !strings.Contains(resD.Header.Get("Location"), "bad_credentials") {
		t.Errorf("expected bad_credentials; got %s", resD.Header.Get("Location"))
	}
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800145001")
	if u == nil {
		t.Fatal("user should NOT have been deleted on wrong password")
	}

	// Failure audited too.
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "account_delete_failed" {
			found = true
		}
	}
	if !found {
		t.Error("expected account_delete_failed audit entry")
	}
}

func TestUserAccountDeleteMACsLoseOwnerNotDeleted(t *testing.T) {
	// FK ON DELETE SET NULL behavior: deleting the user should leave the
	// MAC row but null out user_id.
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800145002"}, "password": {"keep-mac"}}, nil)
	jar := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/me", nil, jar)
	for k, v := range cookieJar(res2) {
		jar[k] = v
	}
	csrf := jar[csrfCookieName]

	// Give the user a MAC.
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800145002")
	if _, err := app.DB.UpsertMAC(context.Background(), "AA:BB:CC:DD:00:01", "keepme", 30, &u.ID); err != nil {
		t.Fatal(err)
	}

	do(t, h, "POST", "/user/account/delete",
		url.Values{"_csrf": {csrf}, "password": {"keep-mac"}}, jar)

	m, _ := app.DB.GetMAC(context.Background(), "AA:BB:CC:DD:00:01")
	if m == nil {
		t.Fatal("MAC should survive user deletion")
	}
	if m.UserID != nil {
		t.Errorf("MAC.UserID should be NULL after user delete; got %v", *m.UserID)
	}
}

func TestUserAccountExportFilenameIsQuotedConstantShape(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800145003"}, "password": {"export-pw"}}, nil)
	jar := cookieJar(res)
	res2, body := do(t, h, "GET", "/user/account/export", nil, jar)
	_ = body
	cd := res2.Header.Get("Content-Disposition")
	want := `attachment; filename="router-billing-data-13800145003.json"`
	if cd != want {
		t.Errorf("Content-Disposition = %q, want %q", cd, want)
	}
	if strings.Count(cd, `"`) != 2 {
		t.Errorf("filename must be a single quoted-string; got %q", cd)
	}
}
