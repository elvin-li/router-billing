package dnsmasq

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadLeases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp.leases")
	content := `1716198000 aa:bb:cc:dd:ee:ff 192.168.5.42 iPhone-Joe 01:aa:bb:cc:dd:ee:ff
1716198100 11:22:33:44:55:66 192.168.5.43 chargepile-01 *
1716198200 99:88:77:66:55:44 192.168.5.44 * *
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	leases, err := LoadLeases(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 3 {
		t.Fatalf("got %d leases, want 3", len(leases))
	}
	if leases[0].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MAC %q not uppercased", leases[0].MAC)
	}
	if leases[0].Hostname != "iPhone-Joe" {
		t.Errorf("hostname %q", leases[0].Hostname)
	}
	if leases[2].Hostname != "" {
		t.Errorf("hostname '*' should become empty, got %q", leases[2].Hostname)
	}
}

func TestLoadLeasesMissing(t *testing.T) {
	leases, err := LoadLeases("/non/existent/path")
	if err != nil {
		t.Errorf("missing file should not error: %v", err)
	}
	if leases != nil {
		t.Errorf("missing file should return nil, got %d entries", len(leases))
	}
}

func TestHostnameByMAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp.leases")
	content := `1716198000 AA:BB:CC:DD:EE:FF 192.168.5.42 phone-A *
1716198100 11:22:33:44:55:66 192.168.5.43 * *
`
	_ = os.WriteFile(path, []byte(content), 0o644)
	m := HostnameByMAC(path)
	if m["AA:BB:CC:DD:EE:FF"] != "phone-A" {
		t.Errorf("got %q", m["AA:BB:CC:DD:EE:FF"])
	}
	if _, ok := m["11:22:33:44:55:66"]; ok {
		t.Error("empty hostname should not be mapped")
	}
}
