package server

import (
	"context"
	"encoding/json"
	"testing"

	"router-billing/internal/config"
)

func TestAPIAuditTotalsCountsActions(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	app.DB.Audit(ctx, "admin", "grant", "M1", "")
	app.DB.Audit(ctx, "admin", "grant", "M2", "")
	app.DB.Audit(ctx, "admin", "revoke", "M3", "")
	app.DB.Audit(ctx, "user:138", "login", "", "")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/totals", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Totals []struct {
			Action string `json:"action"`
			Count  int    `json:"count"`
		} `json:"totals"`
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	got := map[string]int{}
	for _, t := range resp.Totals {
		got[t.Action] = t.Count
	}
	if got["grant"] != 2 {
		t.Errorf("grant should be 2; got %d", got["grant"])
	}
	if got["revoke"] != 1 {
		t.Errorf("revoke should be 1; got %d", got["revoke"])
	}
	if got["login"] != 1 {
		t.Errorf("login should be 1; got %d", got["login"])
	}
	if resp.Total < 4 {
		t.Errorf("total should be at least 4; got %d", resp.Total)
	}
}

// Totals respect since/until.
func TestAPIAuditTotalsHonorsDateRange(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	// Seed today.
	app.DB.Audit(ctx, "admin", "grant", "M-today", "")
	// Future-dated since → nothing today should count.
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/totals?since=2099-01-01", "rb_w", "")
	var resp struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Total != 0 {
		t.Errorf("future since should yield 0; got %d", resp.Total)
	}
}

// Results sorted DESC by count then by action.
func TestAPIAuditTotalsSortedByFrequency(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		app.DB.Audit(ctx, "admin", "popular", "X", "")
	}
	for i := 0; i < 2; i++ {
		app.DB.Audit(ctx, "admin", "rare", "Y", "")
	}

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/totals", "rb_w", "")
	var resp struct {
		Totals []struct {
			Action string `json:"action"`
			Count  int    `json:"count"`
		} `json:"totals"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	// Find positions.
	var popularIdx, rareIdx int = -1, -1
	for i, t := range resp.Totals {
		switch t.Action {
		case "popular":
			popularIdx = i
		case "rare":
			rareIdx = i
		}
	}
	if popularIdx < 0 || rareIdx < 0 {
		t.Fatalf("expected both actions present; got %+v", resp.Totals)
	}
	if popularIdx > rareIdx {
		t.Errorf("popular (5x) should sort before rare (2x); got popular=%d rare=%d", popularIdx, rareIdx)
	}
}

func TestAPIAuditTotalsReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit/totals", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly should be 200; got %d", rr.Code)
	}
}

func TestAPIAuditTotalsRejectsPOST(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/audit/totals", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("POST should be 405; got %d", rr.Code)
	}
}
