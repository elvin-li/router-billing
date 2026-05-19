package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

func nowUTC() time.Time { return time.Now().UTC() }

// Known MACs (in the macs table) should link to the v0.48 detail page
// from /admin/devices. Unknown MACs (online but never authorized) stay
// as plain text — clicking the unknown MAC would go to a 404 redirect,
// which would be confusing.
func TestAdminDevicesPageLinksKnownMACToDetail(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// "known" MAC — exists in macs table AND has a recent sighting so
	// the devices page actually renders it (the view filters to MACs
	// online via ARP OR sighted in the last 10 min).
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:21:01", "kitchen", 30, nil)
	now := nowUTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen)
		VALUES ('AA:BB:CC:00:21:01', '192.168.5.50', 'kitchen-tv', ?, ?)`, now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/devices", nil, jar)

	// Accept both the unescaped colons and html/template's URL-context
	// %3a encoding (same as v0.48/v0.71 tests).
	want1 := "/admin/macs/detail?mac=AA:BB:CC:00:21:01"
	want2 := "/admin/macs/detail?mac=AA%3aBB%3aCC%3a00%3a21%3a01"
	want3 := "/admin/macs/detail?mac=AA%3ABB%3ACC%3A00%3A21%3A01"
	if !strings.Contains(body, want1) && !strings.Contains(body, want2) && !strings.Contains(body, want3) {
		t.Error("devices page should link the known MAC to its detail page")
	}
}
