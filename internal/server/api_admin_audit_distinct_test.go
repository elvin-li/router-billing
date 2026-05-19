package server

import (
	"context"
	"encoding/json"
	"testing"

	"router-billing/internal/config"
)

func TestAPIAuditDistinctActor(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	app.DB.Audit(ctx, "admin:zero", "login", "", "")
	app.DB.Audit(ctx, "admin:alpha", "login", "", "")
	app.DB.Audit(ctx, "user:13800370001", "login", "", "")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/distinct?field=actor", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Values []string `json:"values"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, want := range []string{"admin:zero", "admin:alpha", "user:13800370001"} {
		found := false
		for _, v := range resp.Values {
			if v == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing actor %q in response", want)
		}
	}
	// Sorted.
	for i := 1; i < len(resp.Values); i++ {
		if resp.Values[i-1] > resp.Values[i] {
			t.Errorf("not sorted: %s > %s", resp.Values[i-1], resp.Values[i])
		}
	}
}

func TestAPIAuditDistinctAction(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	app.DB.Audit(ctx, "system", "grant", "X", "")
	app.DB.Audit(ctx, "system", "revoke", "Y", "")
	app.DB.Audit(ctx, "system", "grant", "Z", "") // duplicate

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/distinct?field=action", "rb_w", "")
	var resp struct {
		Values []string `json:"values"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	// grant + revoke present, no duplicates.
	want := map[string]int{}
	for _, v := range resp.Values {
		want[v]++
	}
	if want["grant"] != 1 || want["revoke"] != 1 {
		t.Errorf("expected unique grant + revoke; got %+v", want)
	}
}

func TestAPIAuditDistinctBadField(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/distinct?field=detail", "rb_w", "")
	if rr.Code != 400 {
		t.Errorf("unknown field should be 400; got %d", rr.Code)
	}
}

func TestAPIAuditDistinctMissingField(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/distinct", "rb_w", "")
	if rr.Code != 400 {
		t.Errorf("missing field should be 400; got %d", rr.Code)
	}
}

func TestAPIAuditDistinctReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/distinct?field=actor", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly should be 200; got %d", rr.Code)
	}
}
