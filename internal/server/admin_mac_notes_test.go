package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestAdminMACNotesSaves(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:24:01", "phone", 30, nil)

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/macs/notes",
		url.Values{
			"_csrf": {csrf},
			"mac":   {"AA:BB:CC:00:24:01"},
			"notes": {"customer's IPTV box — expected high traffic"},
		}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=notes") {
		t.Errorf("redirect should signal notes saved; got %s", res.Header.Get("Location"))
	}

	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:24:01")
	if m == nil || !strings.Contains(m.Notes, "IPTV") {
		t.Errorf("notes not persisted; got %+v", m)
	}
	// Audit row.
	entries, _ := app.DB.ListAudit(ctx, 5)
	found := false
	for _, e := range entries {
		if e.Action == "mac_notes" && e.Target == "AA:BB:CC:00:24:01" {
			found = true
		}
	}
	if !found {
		t.Error("mac_notes audit row missing")
	}
}

func TestAdminMACNotesLengthCapped(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:24:02", "phone", 30, nil)

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	long := strings.Repeat("A", 2000)
	do(t, h, "POST", "/admin/macs/notes",
		url.Values{
			"_csrf": {csrf},
			"mac":   {"AA:BB:CC:00:24:02"},
			"notes": {long},
		}, jar)

	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:24:02")
	if len(m.Notes) > 1000 {
		t.Errorf("notes should be capped at 1000 chars; got %d", len(m.Notes))
	}
}

// /admin/macs/detail should render the notes textarea + saved content.
func TestAdminMACDetailPageRendersNotesForm(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:24:03", "phone", 30, nil)
	_ = app.DB.SetMACNotes(ctx, "AA:BB:CC:00:24:03", "saved-note-content")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs/detail?mac=AA:BB:CC:00:24:03", nil, jar)
	if !strings.Contains(body, `name="notes"`) {
		t.Error("notes textarea missing")
	}
	if !strings.Contains(body, "saved-note-content") {
		t.Error("saved notes content should pre-fill the textarea")
	}
}

func TestAdminMACNotesBadMAC(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/macs/notes",
		url.Values{"_csrf": {csrf}, "mac": {"NOT-A-MAC"}, "notes": {"x"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=bad_mac") {
		t.Errorf("malformed mac should redirect with err=bad_mac; got %s", res.Header.Get("Location"))
	}
}
