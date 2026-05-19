package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAdminMACDetailShowsSightingWhenPresent(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:1F:01", "phone", 30, nil)
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen)
		VALUES ('AA:BB:CC:00:1F:01', '192.168.5.42', 'roommate-phone', ?, ?)`,
		now.Add(-24*time.Hour), now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs/detail?mac=AA:BB:CC:00:1F:01", nil, jar)
	for _, want := range []string{
		"最近在线",
		"192.168.5.42",
		"roommate-phone",
		"首次发现",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

// MAC with no sighting record: page shows the "未曾出现" hint instead.
func TestAdminMACDetailNoSightingHint(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:1F:02", "phone", 30, nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs/detail?mac=AA:BB:CC:00:1F:02", nil, jar)
	if !strings.Contains(body, "无网络探测记录") {
		t.Error("MAC without sighting should show the 无网络探测记录 hint")
	}
}

// DB-level: GetSightingForMAC returns nil for missing rows.
func TestGetSightingForMACMissing(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	got, err := app.DB.GetSightingForMAC(ctx, "AA:BB:CC:DD:EE:99")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("missing MAC should return nil; got %+v", got)
	}
}
