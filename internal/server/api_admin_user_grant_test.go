package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIUserGrantExtendsAllMACs(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800120001", "h")
	// Three MACs owned by the user.
	for _, m := range []string{"AA:BB:CC:00:01:01", "AA:BB:CC:00:01:02", "AA:BB:CC:00:01:03"} {
		if _, err := app.DB.UpsertMAC(ctx, m, "phone", 30, &u.ID); err != nil {
			t.Fatal(err)
		}
	}

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"days":7,"label":"support-extend"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		UserID       int64 `json:"user_id"`
		MACsExtended int   `json:"macs_extended"`
		MACs         []struct {
			MAC string `json:"mac"`
		} `json:"macs"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.UserID != u.ID || resp.MACsExtended != 3 || len(resp.MACs) != 3 {
		t.Errorf("expected 3 MACs extended; got %+v", resp)
	}

	// Audit: one summary `user_grant` row + 3 per-MAC `grant` rows.
	entries, _ := app.DB.ListAudit(ctx, 20)
	var summaryFound, grantCount int
	for _, e := range entries {
		switch e.Action {
		case "user_grant":
			if e.Target == strconv.FormatInt(u.ID, 10) {
				summaryFound++
				if !strings.Contains(e.Detail, "macs=3") {
					t.Errorf("summary audit should record macs=3; got %q", e.Detail)
				}
				if !strings.Contains(e.Detail, "via=api") {
					t.Errorf("summary audit should mark via=api; got %q", e.Detail)
				}
			}
		case "grant":
			if strings.HasPrefix(e.Target, "AA:BB:CC:00:01:") {
				grantCount++
				if !strings.Contains(e.Detail, "user_id="+strconv.FormatInt(u.ID, 10)) {
					t.Errorf("per-mac grant should record user_id; got %q", e.Detail)
				}
			}
		}
	}
	if summaryFound != 1 {
		t.Errorf("expected 1 user_grant summary row; got %d", summaryFound)
	}
	if grantCount != 3 {
		t.Errorf("expected 3 per-MAC grant rows; got %d", grantCount)
	}
}

func TestAPIUserGrantZeroMACsIsOK(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	// User exists but has no MACs. Should NOT 404 — the user is real,
	// the grant just had nothing to do.
	u, _ := app.DB.CreateUser(ctx, "13800120002", "h")

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"days":7}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		MACsExtended int `json:"macs_extended"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.MACsExtended != 0 {
		t.Errorf("expected 0 macs extended; got %d", resp.MACsExtended)
	}
}

func TestAPIUserGrantNonexistentUser404(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/users/grant", "rb_w",
		`{"user_id":99999,"days":7}`)
	if rr.Code != 404 {
		t.Errorf("expected 404 for missing user; got %d", rr.Code)
	}
}

func TestAPIUserGrantBadRequest(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	// Zero user_id → 400.
	rr := apiReq(t, h, "POST", "/api/admin/users/grant", "rb_w", `{"days":7}`)
	if rr.Code != 400 {
		t.Errorf("zero user_id should give 400; got %d", rr.Code)
	}
	// Zero days → 400.
	rr = apiReq(t, h, "POST", "/api/admin/users/grant", "rb_w", `{"user_id":1,"days":0}`)
	if rr.Code != 400 {
		t.Errorf("zero days should give 400; got %d", rr.Code)
	}
}

func TestAPIUserGrantReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/users/grant", "rb_ro",
		`{"user_id":1,"days":7}`)
	if rr.Code != 403 {
		t.Errorf("readonly should get 403; got %d", rr.Code)
	}
}

// Anti-leak: response must never carry the user's password_hash or any
// session_token even though the handler reads the User row.
func TestAPIUserGrantResponseHasNoSensitiveFields(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800120003", "supersecrethash")
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:01:04", "phone", 30, &u.ID); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"days":7}`)
	body := rr.Body.String()
	for _, banned := range []string{"password_hash", "supersecrethash", "totp_secret", "session_token"} {
		if strings.Contains(body, banned) {
			t.Errorf("response leaks sensitive field %q: %s", banned, body)
		}
	}
}
