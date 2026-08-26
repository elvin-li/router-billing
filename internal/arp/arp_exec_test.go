package arp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// stubIP puts a fake `ip` executable at the front of PATH so Lookup /
// ListOnInterface exercise their real exec + parse paths.
func stubIP(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "ip")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestLookupFindsAndUppercasesMAC(t *testing.T) {
	stubIP(t, `echo "192.168.5.42 dev br-paid lladdr aa:bb:cc:dd:ee:ff REACHABLE"`)
	mac, err := Lookup(context.Background(), "192.168.5.42")
	if err != nil {
		t.Fatal(err)
	}
	if mac != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("mac = %q, want uppercase AA:BB:CC:DD:EE:FF", mac)
	}
}

func TestLookupNotFoundIsEmptyNotError(t *testing.T) {
	stubIP(t, `exit 0`) // `ip neigh show to <ip>` prints nothing when unknown
	mac, err := Lookup(context.Background(), "192.168.5.99")
	if err != nil {
		t.Fatal(err)
	}
	if mac != "" {
		t.Errorf("unknown IP should return empty mac, got %q", mac)
	}
}

func TestLookupSkipsEntriesWithoutLladdr(t *testing.T) {
	stubIP(t, `echo "192.168.5.42 dev br-paid FAILED"`)
	mac, err := Lookup(context.Background(), "192.168.5.42")
	if err != nil {
		t.Fatal(err)
	}
	if mac != "" {
		t.Errorf("FAILED entry has no lladdr; got %q", mac)
	}
}

func TestLookupPropagatesExecError(t *testing.T) {
	stubIP(t, `exit 1`)
	if _, err := Lookup(context.Background(), "192.168.5.42"); err == nil {
		t.Error("ip failure should surface as error")
	}
}

func TestListOnInterfaceEndToEnd(t *testing.T) {
	stubIP(t, `cat <<'EOF'
192.168.5.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.5.43 FAILED
fe80::1 lladdr aa:bb:cc:dd:ee:ff router STALE
192.168.5.44 lladdr 11:22:33:44:55:66 STALE
EOF`)
	entries, err := ListOnInterface(context.Background(), "br-paid")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2 (dedup by MAC, FAILED skipped)", entries)
	}
	if entries[0].MAC != "AA:BB:CC:DD:EE:FF" || entries[0].IP != "192.168.5.42" {
		t.Errorf("first entry: %+v", entries[0])
	}
	if entries[1].MAC != "11:22:33:44:55:66" || entries[1].State != "STALE" {
		t.Errorf("second entry: %+v", entries[1])
	}
}

func TestListOnInterfacePropagatesExecError(t *testing.T) {
	stubIP(t, `echo 'Cannot find device "nope0"' >&2; exit 1`)
	if _, err := ListOnInterface(context.Background(), "nope0"); err == nil {
		t.Error("ip failure should surface as error")
	}
}
