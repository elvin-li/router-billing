package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPIUserSuspendFlips(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800310001", "h")

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/suspend", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"suspend":true}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status    string `json:"status"`
		Suspended bool   `json:"suspended"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "ok" || !resp.Suspended {
		t.Errorf("unexpected response: %+v", resp)
	}
	got, _ := app.DB.GetUser(ctx, u.ID)
	if !got.Suspended {
		t.Error("DB should reflect suspended=true")
	}

	// Unsuspend
	apiReq(t, h, "POST", "/api/admin/users/suspend", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"suspend":false}`)
	got, _ = app.DB.GetUser(ctx, u.ID)
	if got.Suspended {
		t.Error("DB should reflect suspended=false after unsuspend")
	}

	// Audit rows: both user_suspend AND user_unsuspend should appear.
	entries, _ := app.DB.ListAudit(ctx, 10)
	var sus, unsus bool
	for _, e := range entries {
		if e.Target == strconv.FormatInt(u.ID, 10) {
			if e.Action == "user_suspend" {
				sus = true
			}
			if e.Action == "user_unsuspend" {
				unsus = true
			}
		}
	}
	if !sus || !unsus {
		t.Errorf("both audit rows should land; got user_suspend=%v user_unsuspend=%v", sus, unsus)
	}
}

// Suspending should also evict the user's existing sessions so a logged-in
// abusive account loses access immediately.
func TestAPIUserSuspendEvictsSessions(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800310002", "h")
	// Seed an active session.
	_ = app.DB.CreateSession(ctx, "tok-1", "user", u.Phone, &u.ID, time.Hour)
	sess, _ := app.DB.GetSession(ctx, "tok-1")
	if sess == nil {
		t.Fatal("seed session missing")
	}

	h := app.Routes()
	apiReq(t, h, "POST", "/api/admin/users/suspend", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"suspend":true}`)

	// Session should be gone.
	sess, _ = app.DB.GetSession(ctx, "tok-1")
	if sess != nil {
		t.Error("suspend should evict the user's existing sessions")
	}
}

func TestAPIUserSuspendNotFound(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/suspend", "rb_w",
		`{"user_id":99999,"suspend":true}`)
	if rr.Code != 404 {
		t.Errorf("missing user should be 404; got %d", rr.Code)
	}
}

func TestAPIUserSuspendReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/suspend", "rb_ro",
		`{"user_id":1,"suspend":true}`)
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

func TestAPIUserSuspendAuditViaAPI(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800310003", "h")
	h := app.Routes()
	apiReq(t, h, "POST", "/api/admin/users/suspend", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"suspend":true}`)
	entries, _ := app.DB.ListAudit(ctx, 5)
	for _, e := range entries {
		if e.Action == "user_suspend" && !strings.Contains(e.Detail, "via=api") {
			t.Errorf("audit should mark via=api; got %q", e.Detail)
		}
	}
}
