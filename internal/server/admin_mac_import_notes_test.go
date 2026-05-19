package server

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"router-billing/internal/config"
)

// UI import: 4th column = notes is honored.
func TestAdminMACImportAcceptsNotesColumn(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	bulk := strings.Join([]string{
		"AA:BB:CC:00:25:01,30,phone,customer's IPTV box",
		"AA:BB:CC:00:25:02,30,tablet",
	}, "\n")
	do(t, h, "POST", "/admin/macs/import",
		url.Values{"_csrf": {csrf}, "bulk": {bulk}, "default_days": {"30"}}, jar)

	ctx := context.Background()
	m1, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:25:01")
	if m1 == nil || !strings.Contains(m1.Notes, "IPTV box") {
		t.Errorf("4th-column notes not persisted: %+v", m1)
	}
	m2, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:25:02")
	if m2 == nil || m2.Notes != "" {
		t.Errorf("row without 4th column should have empty notes; got %+v", m2)
	}
}

// API import: notes field on the JSON row is honored.
func TestAPIMACImportAcceptsNotesField(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/macs/import", "rb_w", `{
		"default_days": 30,
		"macs": [
			{"mac":"AA:BB:CC:00:25:10","label":"corp","notes":"API import note"},
			{"mac":"AA:BB:CC:00:25:11","label":"corp"}
		]
	}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}

	ctx := context.Background()
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:25:10")
	if m == nil || m.Notes != "API import note" {
		t.Errorf("api notes not persisted: %+v", m)
	}
	m2, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:25:11")
	if m2 == nil || m2.Notes != "" {
		t.Errorf("row without notes field should have empty notes; got %+v", m2)
	}
}

// Re-importing the same MAC WITHOUT notes should leave existing notes
// alone (anti-footgun: empty-string overwriting would lose support
// context on a CSV re-upload).
func TestAPIMACImportEmptyNotesDoesNotClearExisting(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:25:20", "phone", 30, nil)
	_ = app.DB.SetMACNotes(ctx, "AA:BB:CC:00:25:20", "pre-existing")

	h := app.Routes()
	// Re-import without notes field.
	apiReq(t, h, "POST", "/api/admin/macs/import", "rb_w", `{
		"macs": [{"mac":"AA:BB:CC:00:25:20","days":30,"label":"phone"}]
	}`)

	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:25:20")
	if m.Notes != "pre-existing" {
		t.Errorf("empty notes field should not clear existing; got %q", m.Notes)
	}
}
