package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIMACLabelSets(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:27:01", "old-label", 30, nil)

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/label", "rb_w",
		`{"mac":"AA:BB:CC:00:27:01","label":"new-label"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:27:01")
	if m.Label != "new-label" {
		t.Errorf("label not persisted: %q", m.Label)
	}
	// Expiry should be unchanged (label endpoint must not touch it).
	if m.ExpiresAt.IsZero() {
		t.Error("expires_at lost")
	}
	// Audit row.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "mac_label" && e.Target == "AA:BB:CC:00:27:01" {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit should mark via=api; got %q", e.Detail)
			}
			if !strings.Contains(e.Detail, "label=new-label") {
				t.Errorf("audit should record label value; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("mac_label audit row missing")
	}
}

func TestAPIMACLabelLengthCapped(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:27:02", "x", 30, nil)
	h := app.Routes()
	long := strings.Repeat("A", 100)
	apiReq(t, h, "POST", "/api/admin/macs/label", "rb_w",
		`{"mac":"AA:BB:CC:00:27:02","label":"`+long+`"}`)
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:27:02")
	if len(m.Label) > 64 {
		t.Errorf("label should be capped at 64; got %d", len(m.Label))
	}
}

func TestAPIMACLabelNotFound(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/label", "rb_w",
		`{"mac":"AA:BB:CC:DD:EE:00","label":"x"}`)
	if rr.Code != 404 {
		t.Errorf("missing mac should be 404; got %d", rr.Code)
	}
}

func TestAPIMACLabelReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/label", "rb_ro",
		`{"mac":"AA:BB:CC:00:27:01","label":"x"}`)
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

func TestAPIMACLabelBadMAC400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/label", "rb_w",
		`{"mac":"NOT-A-MAC","label":"x"}`)
	if rr.Code != 400 {
		t.Errorf("bad mac should be 400; got %d", rr.Code)
	}
}
