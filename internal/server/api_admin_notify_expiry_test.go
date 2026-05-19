package server

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIUserNotifyExpiryFlips(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800300001", "h")

	h := app.Routes()

	// Default NotifyExpiry is true. Flip off via API.
	rr := apiReq(t, h, "POST", "/api/admin/users/notify-expiry", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"on":false}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status       string `json:"status"`
		NotifyExpiry bool   `json:"notify_expiry"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "ok" || resp.NotifyExpiry != false {
		t.Errorf("unexpected response: %+v", resp)
	}
	got, _ := app.DB.GetUser(ctx, u.ID)
	if got.NotifyExpiry {
		t.Error("DB should reflect notify_expiry=false")
	}

	// Flip back on.
	apiReq(t, h, "POST", "/api/admin/users/notify-expiry", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"on":true}`)
	got, _ = app.DB.GetUser(ctx, u.ID)
	if !got.NotifyExpiry {
		t.Error("DB should reflect notify_expiry=true after re-enable")
	}

	// Audit row carries on= + via=api.
	entries, _ := app.DB.ListAudit(ctx, 10)
	found := false
	for _, e := range entries {
		if e.Action == "user_notify_pref" && e.Target == strconv.FormatInt(u.ID, 10) {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit should mark via=api; got %q", e.Detail)
			}
			if !strings.Contains(e.Detail, "on=") {
				t.Errorf("audit should record on= value; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("user_notify_pref audit row missing")
	}
}

func TestAPIUserNotifyExpiryNotFound(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/notify-expiry", "rb_w",
		`{"user_id":99999,"on":true}`)
	if rr.Code != 404 {
		t.Errorf("missing user should be 404; got %d", rr.Code)
	}
}

func TestAPIUserNotifyExpiryBadRequest(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/notify-expiry", "rb_w",
		`{"on":true}`)
	if rr.Code != 400 {
		t.Errorf("missing user_id should be 400; got %d", rr.Code)
	}
}

func TestAPIUserNotifyExpiryReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/notify-expiry", "rb_ro",
		`{"user_id":1,"on":true}`)
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}
