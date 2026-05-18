package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIAuditListReturnsAllEntries(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_audit_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()

	app.DB.Audit(ctx, "admin", "grant", "AA:BB:CC:00:00:01", "days=30")
	app.DB.Audit(ctx, "user:13800139000", "login", "", "ip=10.0.0.1")
	app.DB.Audit(ctx, "admin", "revoke", "AA:BB:CC:00:00:02", "")

	rr := apiReq(t, h, "GET", "/api/admin/audit", "rb_audit_ro", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Entries []apiAuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) < 3 {
		t.Fatalf("expected ≥3 entries; got %d", len(resp.Entries))
	}
}

func TestAPIAuditListFilters(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_audit_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()

	app.DB.Audit(ctx, "admin", "grant", "AA:BB:CC:00:00:01", "")
	app.DB.Audit(ctx, "user:13800139000", "login", "", "")
	app.DB.Audit(ctx, "user:13800139000", "login_failed", "", "")
	app.DB.Audit(ctx, "admin", "revoke", "AA:BB:CC:00:00:01", "")

	// Filter by actor=user:
	rr := apiReq(t, h, "GET", "/api/admin/audit?actor=user", "rb_audit_ro", "")
	var resp struct {
		Entries []apiAuditEntry `json:"entries"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, e := range resp.Entries {
		if !strings.Contains(e.Actor, "user") {
			t.Errorf("actor filter failed; got %s", e.Actor)
		}
	}
	if len(resp.Entries) != 2 {
		t.Errorf("actor=user should return 2; got %d", len(resp.Entries))
	}

	// Filter by action=login.
	rr2 := apiReq(t, h, "GET", "/api/admin/audit?action=login", "rb_audit_ro", "")
	var resp2 struct {
		Entries []apiAuditEntry `json:"entries"`
	}
	_ = json.Unmarshal(rr2.Body.Bytes(), &resp2)
	if len(resp2.Entries) != 1 {
		t.Errorf("action=login should return 1; got %d", len(resp2.Entries))
	}

	// Filter by target.
	rr3 := apiReq(t, h, "GET", "/api/admin/audit?target=AA:BB:CC:00:00:01", "rb_audit_ro", "")
	var resp3 struct {
		Entries []apiAuditEntry `json:"entries"`
	}
	_ = json.Unmarshal(rr3.Body.Bytes(), &resp3)
	if len(resp3.Entries) != 2 {
		t.Errorf("target=MAC should return 2; got %d", len(resp3.Entries))
	}
}

func TestAPIAuditLimitParam(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_audit_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		app.DB.Audit(ctx, "admin", "test", "", "")
	}
	rr := apiReq(t, h, "GET", "/api/admin/audit?limit=4", "rb_audit_ro", "")
	var resp struct {
		Entries []apiAuditEntry `json:"entries"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Entries) != 4 {
		t.Errorf("limit=4 should return 4; got %d", len(resp.Entries))
	}
}

func TestAPIAuditRejectsNoToken(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_audit_ro", Label: "x"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit", "", "")
	if rr.Code != 401 {
		t.Errorf("no token: %d", rr.Code)
	}
}
