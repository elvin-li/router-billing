package server

import (
	"context"
	"strings"
	"testing"
)

// /admin/macs list should show the notes field inline when present so
// admins see the support context at a glance.
func TestAdminMACsListShowsNotesInline(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:28:01", "phone", 30, nil)
	_ = app.DB.SetMACNotes(ctx, "AA:BB:CC:00:28:01", "IPTV box, expected high traffic")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs", nil, jar)
	if !strings.Contains(body, "IPTV box, expected high traffic") {
		t.Error("notes should render inline on the MACs list")
	}
	// The notes marker emoji 📝 should appear so admins can spot annotated MACs.
	if !strings.Contains(body, "📝") {
		t.Error("notes marker emoji should appear before the inline notes")
	}
}

// MACs without notes don't get the 📝 marker (no noise).
func TestAdminMACsListHidesEmptyNotes(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:28:02", "no-notes", 30, nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs", nil, jar)
	// Sanity: the MAC should appear on the page.
	if !strings.Contains(body, "AA:BB:CC:00:28:02") {
		t.Fatal("MAC missing from list")
	}
	// We can't fully check absence of 📝 since other test fixtures might
	// have added notes. We instead check that the no-notes row's surrounding
	// HTML doesn't include the marker.
	idx := strings.Index(body, "AA:BB:CC:00:28:02")
	if idx < 0 {
		t.Fatal("MAC not in body")
	}
	end := idx + 500
	if end > len(body) {
		end = len(body)
	}
	chunk := body[idx:end]
	if strings.Contains(chunk, "📝") {
		t.Errorf("no-notes MAC row should not show 📝; nearby chunk=%s", chunk)
	}
}
