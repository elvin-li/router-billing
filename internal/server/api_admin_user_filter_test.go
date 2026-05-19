package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIUserListFilterBySuspended(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	u1, _ := app.DB.CreateUser(ctx, "13800240001", "h")
	u2, _ := app.DB.CreateUser(ctx, "13800240002", "h")
	_, _ = app.DB.CreateUser(ctx, "13800240003", "h")
	// Suspend u1 + u2.
	_ = app.DB.SuspendUser(ctx, u1.ID, true)
	_ = app.DB.SuspendUser(ctx, u2.ID, true)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/users?suspended=1", "rb_w", "")
	var resp struct {
		Users []struct {
			Phone     string `json:"phone"`
			Suspended bool   `json:"suspended"`
		} `json:"users"`
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count != 2 || len(resp.Users) != 2 {
		t.Errorf("expected 2 suspended; got %d", resp.Count)
	}
	for _, u := range resp.Users {
		if !u.Suspended {
			t.Errorf("filter let non-suspended through: %+v", u)
		}
	}

	// suspended=0 → only the 1 non-suspended (filtered out the 2 above).
	rr = apiReq(t, h, "GET", "/api/admin/users?suspended=0", "rb_w", "")
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, u := range resp.Users {
		if u.Suspended {
			t.Errorf("suspended=0 should exclude suspended: %+v", u)
		}
	}
}

func TestAPIUserListFilterByTOTP(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800240010", "h")
	_, _ = app.DB.CreateUser(ctx, "13800240011", "h")
	// Enable TOTP on u only.
	_, _ = app.DB.Exec(ctx, `UPDATE users SET totp_secret = ? WHERE id = ?`, "JBSWY3DPEHPK3PXP", u.ID)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/users?totp=1", "rb_w", "")
	var resp struct {
		Users []struct {
			Phone       string `json:"phone"`
			TOTPEnabled bool   `json:"totp_enabled"`
		} `json:"users"`
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, x := range resp.Users {
		if !x.TOTPEnabled {
			t.Errorf("totp=1 should exclude users without TOTP: %+v", x)
		}
	}
	// At least one row (the user we enabled).
	if resp.Count == 0 {
		t.Error("expected at least 1 TOTP-enabled user")
	}
	// totp=0 must exclude the one TOTP user.
	rr = apiReq(t, h, "GET", "/api/admin/users?totp=0", "rb_w", "")
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, x := range resp.Users {
		if x.TOTPEnabled {
			t.Errorf("totp=0 should exclude TOTP-enabled: %+v", x)
		}
	}
}

// Filters compose: suspended=0 AND totp=0 returns the "non-2FA active
// users" set used for nudge campaigns.
func TestAPIUserListFilterCompose(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u1, _ := app.DB.CreateUser(ctx, "13800240020", "h") // active + no TOTP
	u2, _ := app.DB.CreateUser(ctx, "13800240021", "h") // active + TOTP
	u3, _ := app.DB.CreateUser(ctx, "13800240022", "h") // suspended + no TOTP
	_, _ = app.DB.Exec(ctx, `UPDATE users SET totp_secret = ? WHERE id = ?`, "JBSWY3DPEHPK3PXP", u2.ID)
	_ = app.DB.SuspendUser(ctx, u3.ID, true)
	_ = u1

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/users?suspended=0&totp=0", "rb_w", "")
	var resp struct {
		Users []struct {
			Phone string `json:"phone"`
		} `json:"users"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, u := range resp.Users {
		// Must NOT include the suspended one or the TOTP one.
		if strings.HasSuffix(u.Phone, "21") || strings.HasSuffix(u.Phone, "22") {
			t.Errorf("compose filter let wrong user through: %+v", u)
		}
	}
}

func TestAPIUserListBackwardCompat(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.CreateUser(ctx, "13800240099", "h")
	h := app.Routes()
	// v0.57 added "count" + filter knobs but the legacy no-param call
	// still returns "users" array — v0.40-and-earlier clients keep
	// working.
	rr := apiReq(t, h, "GET", "/api/admin/users", "rb_w", "")
	var resp struct {
		Users []struct {
			Phone string `json:"phone"`
		} `json:"users"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Users) == 0 {
		t.Error("no filters should return all users")
	}
}
