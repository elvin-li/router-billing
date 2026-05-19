package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIOptimizeNowRunsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/maintenance/optimize-now", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Ms int64 `json:"ms"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Ms < 0 {
		t.Errorf("ms should be non-negative; got %d", resp.Ms)
	}

	// Audit row with elapsed time + via=api.
	entries, _ := app.DB.ListAudit(context.Background(), 5)
	found := false
	for _, e := range entries {
		if e.Action == "optimize_now" {
			found = true
			if !strings.Contains(e.Detail, "ms=") {
				t.Errorf("audit should record ms=; got %q", e.Detail)
			}
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit should mark via=api; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("optimize_now audit row missing")
	}
}

func TestAPIOptimizeNowReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/maintenance/optimize-now", "rb_ro", "")
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

func TestAPIOptimizeNowRejectsGET(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/maintenance/optimize-now", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("GET should be 405; got %d", rr.Code)
	}
}
