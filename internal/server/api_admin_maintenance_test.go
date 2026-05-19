package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPIExpireNowFlipsDueMAC(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:EE:FB", "victim", 30, nil)
	_, _ = app.DB.Exec(ctx,
		`UPDATE macs SET expires_at = ? WHERE mac = ?`,
		time.Now().UTC().Add(-time.Hour), "AA:BB:CC:DD:EE:FB")

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/maintenance/expire-now", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Expired int `json:"expired"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Expired != 1 {
		t.Errorf("expected expired=1; got %d", resp.Expired)
	}

	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:FB")
	if m == nil || m.Status != "expired" {
		t.Errorf("MAC should be expired; got %+v", m)
	}

	// Audit via=api so reviewers can tell from UI sweeps.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "expire_now" {
			found = true
			if !strings.Contains(e.Detail, "via=api") || !strings.Contains(e.Detail, "expired=1") {
				t.Errorf("audit detail wrong: %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("expire_now audit row missing")
	}
}

func TestAPIAuditTrimAppliesCap(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.Cfg.Security.AuditLogKeep = 5
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		app.DB.Audit(ctx, "test", "spam", "tgt", "row")
	}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/maintenance/audit-trim", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var resp struct {
		Kept int `json:"kept"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Kept != app.Cfg.Security.AuditLogRetention() {
		t.Errorf("kept should echo configured retention; got %d want %d", resp.Kept, app.Cfg.Security.AuditLogRetention())
	}
	n, _ := app.DB.CountAudit(ctx)
	if n > resp.Kept+1 {
		t.Errorf("trim left too many rows: %d (>%d)", n, resp.Kept+1)
	}
}

func TestAPIExpireNowReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/maintenance/expire-now", "rb_ro", "")
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

func TestAPIAuditTrimReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/maintenance/audit-trim", "rb_ro", "")
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

// Both endpoints reject GET to match the UI handlers' protection against
// browser preload accidentally firing the sweep.
func TestAPIMaintenanceEndpointsRejectGET(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	for _, p := range []string{
		"/api/admin/maintenance/expire-now",
		"/api/admin/maintenance/audit-trim",
	} {
		rr := apiReq(t, h, "GET", p, "rb_w", "")
		if rr.Code != 405 {
			t.Errorf("%s GET should be 405; got %d", p, rr.Code)
		}
	}
}
