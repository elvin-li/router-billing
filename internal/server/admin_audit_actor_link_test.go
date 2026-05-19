package server

import (
	"context"
	"strings"
	"testing"
)

func TestAdminAuditPageLinksActorToFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin:bob", "grant", "AA:BB:CC:00:2C:01", "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/audit", nil, jar)

	// Actor cell should be linked to /admin/audit?actor=admin:bob.
	// html/template URL-escapes `:` in href context as `%3a`.
	if !strings.Contains(body, `href="/admin/audit?actor=admin:bob`) &&
		!strings.Contains(body, `href="/admin/audit?actor=admin%3abob`) &&
		!strings.Contains(body, `href="/admin/audit?actor=admin%3Abob`) {
		t.Errorf("actor should link to one-click filter; body missing the actor link")
	}
}

// When the page is already filtered by date, the actor link should
// PRESERVE the since/until — clicking "show me only this actor" shouldn't
// reset the rest of the filter.
func TestAdminAuditActorLinkPreservesDateFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin:alice", "grant", "X", "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/audit?since=2026-01-01&until=2026-12-31", nil, jar)

	if !strings.Contains(body, "since=2026-01-01") {
		t.Error("actor link should preserve since= param")
	}
	if !strings.Contains(body, "until=2026-12-31") {
		t.Error("actor link should preserve until= param")
	}
}
