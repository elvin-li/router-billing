package sightings

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"router-billing/internal/db"
)

// The scan path shells out to `ip neigh show dev <iface>`; stub it so the
// full ARP → leases-hostname-join → DB-upsert pipeline runs for real.
func stubIP(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "ip")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestScanUpsertsSightingsWithHostnames(t *testing.T) {
	stubIP(t, `cat <<'EOF'
192.168.5.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.5.44 lladdr 11:22:33:44:55:66 STALE
192.168.5.45 FAILED
EOF`)
	leases := filepath.Join(t.TempDir(), "dhcp.leases")
	// dnsmasq format: <expire-epoch> <mac> <ip> <hostname> <client-id>
	// The second device advertises no hostname ("*").
	if err := os.WriteFile(leases, []byte(
		"1700000000 aa:bb:cc:dd:ee:ff 192.168.5.42 iPhone-Alice 01:aa:bb:cc:dd:ee:ff\n"+
			"1700000000 11:22:33:44:55:66 192.168.5.44 * *\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	d := openTestDB(t)
	tr := &Tracker{DB: d, Iface: "br-paid", LeasesPath: leases}
	ctx := context.Background()
	tr.scan(ctx)

	s, err := d.GetSightingForMAC(ctx, "AA:BB:CC:DD:EE:FF")
	if err != nil || s == nil {
		t.Fatalf("sighting missing: %v %+v", err, s)
	}
	if s.LastIP != "192.168.5.42" || s.Hostname != "iPhone-Alice" {
		t.Errorf("sighting = %+v", s)
	}

	s2, err := d.GetSightingForMAC(ctx, "11:22:33:44:55:66")
	if err != nil || s2 == nil {
		t.Fatalf("second sighting missing: %v", err)
	}
	if s2.Hostname != "" {
		t.Errorf("'*' hostname should be stored empty; got %q", s2.Hostname)
	}

	// The FAILED entry never reached the DB.
	recent, err := d.ListRecentSightings(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 {
		t.Errorf("recent sightings = %d, want 2: %+v", len(recent), recent)
	}
}

// A rescan must refresh last_ip and keep a previously-learned hostname when
// the leases file no longer carries one (device went quiet but is known).
func TestScanRescanKeepsKnownHostname(t *testing.T) {
	stubIP(t, `echo "192.168.5.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE"`)
	leases := filepath.Join(t.TempDir(), "dhcp.leases")
	if err := os.WriteFile(leases, []byte("1700000000 aa:bb:cc:dd:ee:ff 192.168.5.42 iPhone-Alice *\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	d := openTestDB(t)
	tr := &Tracker{DB: d, Iface: "br-paid", LeasesPath: leases}
	ctx := context.Background()
	tr.scan(ctx)

	// Lease expired / hostname gone; device moved to a new IP.
	stubIP(t, `echo "192.168.5.77 lladdr aa:bb:cc:dd:ee:ff REACHABLE"`)
	if err := os.WriteFile(leases, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	tr.scan(ctx)

	s, err := d.GetSightingForMAC(ctx, "AA:BB:CC:DD:EE:FF")
	if err != nil || s == nil {
		t.Fatal(err)
	}
	if s.LastIP != "192.168.5.77" {
		t.Errorf("last_ip should refresh: %+v", s)
	}
	if s.Hostname != "iPhone-Alice" {
		t.Errorf("known hostname should survive an empty rescan: %+v", s)
	}
}

func TestScanSurvivesArpFailure(t *testing.T) {
	stubIP(t, `exit 1`)
	d := openTestDB(t)
	tr := &Tracker{DB: d, Iface: "br-paid"}
	// Must log and return without touching the DB or panicking.
	tr.scan(context.Background())
	recent, err := d.ListRecentSightings(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 0 {
		t.Errorf("no sightings expected after arp failure: %+v", recent)
	}
}
