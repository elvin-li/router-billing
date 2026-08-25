package server

import (
	"context"
	"testing"
)

// TestAdminResyncRejectsGET pins the POST-only guard on /admin/resync.
// The CSRF middleware only verifies POST bodies, so a state-changing GET
// would be reachable cross-site: SameSite=Lax cookies still ride along on
// top-level GET navigation, letting any page an admin visits trigger a
// firewall resync (and its audit row) via a plain link or img tag.
func TestAdminResyncRejectsGET(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, _ := do(t, h, "GET", "/admin/resync", nil, jar)
	if res.StatusCode != 303 {
		t.Fatalf("GET /admin/resync: got %d, want 303 redirect away", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/admin/macs" {
		t.Errorf("GET /admin/resync redirect = %q, want /admin/macs", loc)
	}

	// No resync must have run — neither success nor failure audit rows.
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	for _, e := range entries {
		if e.Action == "firewall_resync" || e.Action == "firewall_resync_failed" {
			t.Errorf("GET /admin/resync must not trigger a resync; found audit action %q", e.Action)
		}
	}
}
