package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestAdminAuditNoteWritesEntry(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/audit/note",
		url.Values{"_csrf": {csrf}, "note": {"customer called confirming lost phone"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=note") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "manual_note" {
			found = true
			if !strings.Contains(e.Detail, "customer called confirming lost phone") {
				t.Errorf("detail missing note text; got %q", e.Detail)
			}
			if !strings.Contains(e.Actor, "admin") {
				t.Errorf("actor should attribute to admin; got %q", e.Actor)
			}
		}
	}
	if !found {
		t.Error("manual_note entry missing")
	}
}

func TestAdminAuditNoteRejectsEmpty(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/audit/note",
		url.Values{"_csrf": {csrf}, "note": {"   "}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "empty_note") {
		t.Errorf("empty note: %s", res.Header.Get("Location"))
	}
}

func TestAdminAuditNoteTruncatesLongInput(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	longNote := strings.Repeat("X", 2000)
	do(t, h, "POST", "/admin/audit/note",
		url.Values{"_csrf": {csrf}, "note": {longNote}}, jar)

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	for _, e := range entries {
		if e.Action == "manual_note" {
			// Detail = note (capped 1000) + " ip=..."  → at most ~1100.
			if strings.Count(e.Detail, "X") > 1000 {
				t.Errorf("note text should be capped at 1000 chars; got %d Xs",
					strings.Count(e.Detail, "X"))
			}
		}
	}
}

func TestAdminAuditPageShowsNoteForm(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/audit", nil, jar)
	if !strings.Contains(body, "手动添加备注") {
		t.Error("page should have manual-note section")
	}
	if !strings.Contains(body, `action="/admin/audit/note"`) {
		t.Error("page should have note form")
	}
}
