package server

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestUserAccountExportReturnsJSON(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Register + give the user a MAC + audit entry.
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800146000"}, "password": {"export-pw"}}, nil)
	jar := cookieJar(res)
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800146000")
	if _, err := app.DB.UpsertMAC(context.Background(), "AA:BB:CC:DD:EE:F1", "phone", 30, &u.ID); err != nil {
		t.Fatal(err)
	}

	res2, body := do(t, h, "GET", "/user/account/export", nil, jar)
	if res2.StatusCode != 200 {
		t.Fatalf("export: %d", res2.StatusCode)
	}
	if ct := res2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type: %s", ct)
	}
	if cd := res2.Header.Get("Content-Disposition"); !strings.Contains(cd, "router-billing-data-13800146000.json") {
		t.Errorf("content-disposition: %s", cd)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	// Account section present + phone exposed.
	acct, _ := got["account"].(map[string]any)
	if acct == nil || acct["phone"] != "13800146000" {
		t.Errorf("account phone missing/wrong: %+v", acct)
	}
	// MACs section non-empty.
	macs, _ := got["macs"].([]any)
	if len(macs) == 0 {
		t.Error("export should include the seeded MAC")
	}
	// activity section is at least an array (may be empty if nothing audited).
	if _, ok := got["activity"].([]any); !ok {
		t.Error("export should include activity array")
	}
}

func TestUserAccountExportOmitsSecrets(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800146001"}, "password": {"secret-pw"}}, nil)
	jar := cookieJar(res)

	// Set a TOTP secret directly on the user (skip enrollment).
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800146001")
	if err := app.DB.SetUserTOTPPending(context.Background(), u.ID, "JBSWY3DPEHPK3PXP-OBVIOUS-LEAK"); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.ConfirmUserTOTP(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}

	_, body := do(t, h, "GET", "/user/account/export", nil, jar)
	for _, leak := range []string{"JBSWY3DPEHPK3PXP-OBVIOUS-LEAK", "password_hash", "totp_secret", "totp_pending"} {
		if strings.Contains(body, leak) {
			t.Errorf("export leaks %q", leak)
		}
	}
}

func TestUserAccountExportWritesAudit(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800146002"}, "password": {"audit-pw"}}, nil)
	jar := cookieJar(res)
	do(t, h, "GET", "/user/account/export", nil, jar)

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "account_export" && e.Actor == "user:13800146002" {
			found = true
		}
	}
	if !found {
		t.Error("expected account_export audit entry")
	}
}

func TestUserAccountExportRequiresAuth(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	res, _ := do(t, h, "GET", "/user/account/export", nil, nil)
	if res.StatusCode != 303 {
		t.Errorf("unauth: %d (want 303)", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "/user/login") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}
}
