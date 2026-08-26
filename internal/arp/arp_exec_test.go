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

// Lookup must reject anything that isn't an IP literal BEFORE spawning
// `ip` — this is the exec boundary; option-looking or multi-token strings
// must never reach the argument vector. The stub would exit 0 and produce
// a parseable entry, so a non-error can only mean the input was executed.
func TestLookupRejectsNonIPWithoutExec(t *testing.T) {
	stubIP(t, `echo "192.168.5.42 dev br-paid lladdr aa:bb:cc:dd:ee:ff REACHABLE"`)
	for _, bad := range []string{
		"", "   ", "not-an-ip", "192.168.5.42 extra", "-V",
		"192.168.5.0/24", "example.com", "192.168.5.42;reboot",
	} {
		if _, err := Lookup(context.Background(), bad); err == nil {
			t.Errorf("Lookup(%q) should be rejected before exec", bad)
		}
	}
}

// An IPv6 zone suffix (the shape RemoteAddr produces for link-local peers,
// "fe80::1%br-paid") must be stripped: iproute2 rejects the %zone syntax,
// so pre-fix these lookups always failed. The stub records its argv so the
// test can assert the canonical, zone-less form was passed.
func TestLookupStripsIPv6ZoneAndCanonicalizes(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	stubIP(t, `echo "$@" > `+argsFile+`
echo "fe80::1 lladdr aa:bb:cc:dd:ee:ff REACHABLE"`)
	mac, err := Lookup(context.Background(), "FE80::1%br-paid")
	if err != nil {
		t.Fatal(err)
	}
	if mac != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("mac = %q", mac)
	}
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := "neigh show to fe80::1\n"; string(got) != want {
		t.Errorf("ip argv = %q, want %q (zone stripped, canonical lowercase)", got, want)
	}
}

// A garbage lladdr token in the output must not be returned as a MAC.
func TestLookupIgnoresMalformedLladdr(t *testing.T) {
	stubIP(t, `echo "192.168.5.42 lladdr not-a-mac REACHABLE"`)
	mac, err := Lookup(context.Background(), "192.168.5.42")
	if err != nil {
		t.Fatal(err)
	}
	if mac != "" {
		t.Errorf("malformed lladdr should yield empty mac, got %q", mac)
	}
}

// ListOnInterface must reject interface names that could be mistaken for
// options or that no Linux interface can have.
func TestListOnInterfaceRejectsBadIfaceWithoutExec(t *testing.T) {
	stubIP(t, `echo "192.168.5.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE"`)
	for _, bad := range []string{
		"", "-junk", "br paid", "a-name-way-too-long", "br/paid", "br\tpaid",
	} {
		if _, err := ListOnInterface(context.Background(), bad); err == nil {
			t.Errorf("ListOnInterface(%q) should be rejected before exec", bad)
		}
	}
}
