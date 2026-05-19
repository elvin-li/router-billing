package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIUserGrantByPhoneHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800140001", "h")
	for _, m := range []string{"AA:BB:CC:00:02:01", "AA:BB:CC:00:02:02"} {
		if _, err := app.DB.UpsertMAC(ctx, m, "phone", 30, &u.ID); err != nil {
			t.Fatal(err)
		}
	}

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant-by-phone", "rb_w",
		`{"phone":"13800140001","days":7,"label":"support-extend"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		UserID       int64  `json:"user_id"`
		Phone        string `json:"phone"`
		MACsExtended int    `json:"macs_extended"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.UserID != u.ID || resp.Phone != "13800140001" || resp.MACsExtended != 2 {
		t.Errorf("unexpected response: %+v", resp)
	}

	// Audit must carry the phone so reviewers can search by it.
	entries, _ := app.DB.ListAudit(ctx, 10)
	found := false
	for _, e := range entries {
		if e.Action == "user_grant" {
			found = true
			if !strings.Contains(e.Detail, "phone=13800140001") {
				t.Errorf("audit should embed phone; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("user_grant summary row missing")
	}
}

func TestAPIUserGrantByPhoneInvalidPhone400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant-by-phone", "rb_w",
		`{"phone":"not-a-number","days":7}`)
	if rr.Code != 400 {
		t.Errorf("invalid phone should be 400; got %d", rr.Code)
	}
}

func TestAPIUserGrantByPhoneNotFound404(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	// Valid format but no such user.
	rr := apiReq(t, h, "POST", "/api/admin/users/grant-by-phone", "rb_w",
		`{"phone":"13800999999","days":7}`)
	if rr.Code != 404 {
		t.Errorf("missing user should be 404; got %d", rr.Code)
	}
}

func TestAPIUserGrantByPhoneReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant-by-phone", "rb_ro",
		`{"phone":"13800140001","days":7}`)
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

func TestAPIUserGrantByPhoneZeroDaysBadRequest(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant-by-phone", "rb_w",
		`{"phone":"13800140001","days":0}`)
	if rr.Code != 400 {
		t.Errorf("zero days should be 400; got %d", rr.Code)
	}
}

// Same anti-leak red-line: response body must never carry password_hash etc.
func TestAPIUserGrantByPhoneResponseLeakCheck(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800140002", "super-secret-hash")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:02:03", "phone", 30, &u.ID)
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant-by-phone", "rb_w",
		`{"phone":"13800140002","days":7}`)
	body := rr.Body.String()
	for _, banned := range []string{"password_hash", "super-secret-hash", "totp_secret", "session_token"} {
		if strings.Contains(body, banned) {
			t.Errorf("response leaks %q: %s", banned, body)
		}
	}
}
