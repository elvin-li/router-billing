package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIMACNotesSets(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:26:01", "phone", 30, nil)

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/notes", "rb_w",
		`{"mac":"AA:BB:CC:00:26:01","notes":"set via API"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:26:01")
	if m.Notes != "set via API" {
		t.Errorf("notes not persisted: %q", m.Notes)
	}
	// Audit row.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "mac_notes" && e.Target == "AA:BB:CC:00:26:01" {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit should mark via=api; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("mac_notes audit row missing")
	}
}

// API path SHOULD overwrite to empty when explicitly sent (unlike the
// import path which preserves on missing field). Pin this distinction.
func TestAPIMACNotesEmptyClears(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:26:02", "phone", 30, nil)
	_ = app.DB.SetMACNotes(ctx, "AA:BB:CC:00:26:02", "stale")

	h := app.Routes()
	apiReq(t, h, "POST", "/api/admin/macs/notes", "rb_w",
		`{"mac":"AA:BB:CC:00:26:02","notes":""}`)

	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:26:02")
	if m.Notes != "" {
		t.Errorf("API empty notes should clear; got %q", m.Notes)
	}
}

func TestAPIMACNotesNormalizesInput(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:26:03", "phone", 30, nil)
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/notes", "rb_w",
		`{"mac":"aa-bb-cc-00-26-03","notes":"lowercased mac"}`)
	if rr.Code != 200 {
		t.Errorf("normalized mac should work; got %d", rr.Code)
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:26:03")
	if m.Notes != "lowercased mac" {
		t.Errorf("normalize round-trip failed; got %q", m.Notes)
	}
}

func TestAPIMACNotesNotFound(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/notes", "rb_w",
		`{"mac":"AA:BB:CC:DD:EE:00","notes":"x"}`)
	if rr.Code != 404 {
		t.Errorf("missing mac should be 404; got %d", rr.Code)
	}
}

func TestAPIMACNotesBadMAC400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/notes", "rb_w",
		`{"mac":"NOT-A-MAC","notes":"x"}`)
	if rr.Code != 400 {
		t.Errorf("bad mac should be 400; got %d", rr.Code)
	}
}

func TestAPIMACNotesReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/notes", "rb_ro",
		`{"mac":"AA:BB:CC:00:26:01","notes":"x"}`)
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}
