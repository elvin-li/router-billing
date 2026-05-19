package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIMACImportHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	body := `{
	  "default_days": 90,
	  "macs": [
	    {"mac": "AA:BB:CC:00:00:01", "days": 30, "label": "phone"},
	    {"mac": "aa-bb-cc-00-00-02", "label": "tv"},
	    {"mac": "AA:BB:CC:00:00:03"}
	  ]
	}`
	rr := apiReq(t, h, "POST", "/api/admin/macs/import", "rb_w", body)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Added  int `json:"added"`
		Failed int `json:"failed"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Added != 3 || resp.Failed != 0 {
		t.Errorf("added=%d failed=%d; want 3/0", resp.Added, resp.Failed)
	}

	ctx := context.Background()
	for _, mac := range []string{"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02", "AA:BB:CC:00:00:03"} {
		m, _ := app.DB.GetMAC(ctx, mac)
		if m == nil {
			t.Errorf("MAC %s not created", mac)
		}
	}
}

func TestAPIMACImportSkipsInvalidMACs(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/macs/import", "rb_w",
		`{"macs":[{"mac":"NOT-A-MAC"},{"mac":"AA:BB:CC:00:00:01","days":30}]}`)
	var resp struct {
		Added  int `json:"added"`
		Failed int `json:"failed"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Added != 1 || resp.Failed != 1 {
		t.Errorf("expected added=1 failed=1; got %d/%d", resp.Added, resp.Failed)
	}
}

func TestAPIMACImportDefaultDays(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	// Row with no days field — should fall back to default_days.
	apiReq(t, h, "POST", "/api/admin/macs/import", "rb_w",
		`{"default_days":7,"macs":[{"mac":"AA:BB:CC:00:00:99"}]}`)

	// Audit trail records the days resolved.
	entries, _ := app.DB.ListAudit(context.Background(), 10)
	found := false
	for _, e := range entries {
		if e.Action == "grant" && e.Target == "AA:BB:CC:00:00:99" {
			found = true
			if !strings.Contains(e.Detail, "days=7") {
				t.Errorf("default_days not applied; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("grant audit row missing")
	}
}

func TestAPIMACImportReadOnlyTokenRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/import", "rb_ro",
		`{"macs":[{"mac":"AA:BB:CC:00:00:01"}]}`)
	if rr.Code != 403 {
		t.Errorf("readonly should get 403; got %d", rr.Code)
	}
}

func TestAPIMACImportEmptyMACsList(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/import", "rb_w", `{"macs":[]}`)
	if rr.Code != 400 {
		t.Errorf("empty macs: %d", rr.Code)
	}
}

func TestAPIMACImportTooManyRowsRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	// Build a JSON with 1001 rows.
	var b strings.Builder
	b.WriteString(`{"macs":[`)
	for i := 0; i < 1001; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"mac":"AA:BB:CC:00:00:01"}`)
	}
	b.WriteString(`]}`)

	rr := apiReq(t, h, "POST", "/api/admin/macs/import", "rb_w", b.String())
	if rr.Code != 400 {
		t.Errorf("expected 400 for too many rows; got %d", rr.Code)
	}
}
