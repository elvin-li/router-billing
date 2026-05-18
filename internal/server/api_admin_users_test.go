package server

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIUserListReturnsRegisteredUsers(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_users_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()

	// Seed two users.
	if _, err := app.DB.CreateUser(ctx, "13800139060", "hash1"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.CreateUser(ctx, "13800139061", "hash2"); err != nil {
		t.Fatal(err)
	}

	rr := apiReq(t, h, "GET", "/api/admin/users", "rb_users_ro", "")
	if rr.Code != 200 {
		t.Fatalf("got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Users []apiUserSummary `json:"users"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Users) != 2 {
		t.Fatalf("expected 2 users; got %d (body=%s)", len(resp.Users), rr.Body.String())
	}
	phones := map[string]bool{}
	for _, u := range resp.Users {
		phones[u.Phone] = true
	}
	if !phones["13800139060"] || !phones["13800139061"] {
		t.Errorf("missing phones in response: %v", phones)
	}
}

func TestAPIUserListExcludesAuthMaterial(t *testing.T) {
	// A leaked monitoring token must not exfiltrate password hashes or
	// TOTP secrets — only the public-ish summary fields.
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_users_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800139062", "super-secret-bcrypt-hash")
	if err := app.DB.SetUserTOTPPending(ctx, u.ID, "JBSWY3DPEHPK3PXP-secret"); err != nil {
		t.Fatal(err)
	}

	rr := apiReq(t, h, "GET", "/api/admin/users", "rb_users_ro", "")
	if rr.Code != 200 {
		t.Fatalf("got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, leak := range []string{"super-secret-bcrypt-hash", "JBSWY3DPEHPK3PXP", "password_hash", "totp_secret", "totp_pending"} {
		if strings.Contains(body, leak) {
			t.Errorf("response leaks %q: %s", leak, body)
		}
	}
}

func TestAPIUserListFiltersByQuery(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_users_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()
	_, _ = app.DB.CreateUser(ctx, "13800139063", "h")
	_, _ = app.DB.CreateUser(ctx, "13900139063", "h")
	_, _ = app.DB.CreateUser(ctx, "13700139999", "h")

	rr := apiReq(t, h, "GET", "/api/admin/users?q=63", "rb_users_ro", "")
	var resp struct {
		Users []apiUserSummary `json:"users"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Users) != 2 {
		t.Errorf("q=63 should match 2 users; got %d", len(resp.Users))
	}
}

func TestAPIUserListIncludesTOTPFlagAndMACCount(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_users_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800139064", "h")
	// "Enroll" TOTP by setting the pending then confirming.
	_ = app.DB.SetUserTOTPPending(ctx, u.ID, "JBSWY3DPEHPK3PXP")
	_ = app.DB.ConfirmUserTOTP(ctx, u.ID)
	// Grant a MAC for this user.
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:00:01", "phone", 30, &u.ID); err != nil {
		t.Fatal(err)
	}

	rr := apiReq(t, h, "GET", "/api/admin/users", "rb_users_ro", "")
	var resp struct {
		Users []apiUserSummary `json:"users"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Users) != 1 {
		t.Fatalf("expected 1 user; got %d", len(resp.Users))
	}
	if !resp.Users[0].TOTPEnabled {
		t.Error("totp_enabled should be true")
	}
	if resp.Users[0].MACs != 1 {
		t.Errorf("macs = %d, want 1", resp.Users[0].MACs)
	}
}

func TestAPIUserListRejectsNoToken(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_users_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/users", "", "")
	if rr.Code != 401 {
		t.Errorf("no token: %d", rr.Code)
	}
}

func TestAdminExportUsersCSVShapeAndHeader(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800139065", "hash")
	_ = app.DB.SuspendUser(ctx, u.ID, true)
	_, _ = app.DB.CreateUser(ctx, "13800139066", "hash")

	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/export/users.csv", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if res.Header.Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Errorf("content-type: %s", res.Header.Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected header + 2 rows; got %d (body=%q)", len(lines), body)
	}
	header := lines[0]
	for _, want := range []string{"id", "phone", "suspended", "totp_enabled", "macs", "created_at"} {
		if !strings.Contains(header, want) {
			t.Errorf("header missing %q: %s", want, header)
		}
	}
	if !strings.Contains(body, "13800139065") {
		t.Error("CSV missing first phone")
	}
	if !strings.Contains(body, "13800139066") {
		t.Error("CSV missing second phone")
	}
}

func TestAdminExportUsersCSVOmitsAuthMaterial(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800139067", "leaky-hash-must-not-appear")
	_ = app.DB.SetUserTOTPPending(ctx, u.ID, "PENDING-LEAK-TOKEN")
	_ = app.DB.ConfirmUserTOTP(ctx, u.ID)

	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/users.csv", nil, jar)
	for _, leak := range []string{"leaky-hash-must-not-appear", "PENDING-LEAK-TOKEN"} {
		if strings.Contains(body, leak) {
			t.Errorf("CSV leaks %q: %s", leak, body)
		}
	}
}

func TestAdminExportUsersCSVRequiresAdminAuth(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "GET", "/admin/export/users.csv", nil, nil)
	if res.StatusCode != 303 {
		t.Errorf("no auth: %d (want 303 to /admin/login)", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "/admin/login") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}
}

// silence "url unused" when nothing in this file uses url.Values directly —
// keep the import so future tests can add form-based requests.
var _ = url.Values{}
