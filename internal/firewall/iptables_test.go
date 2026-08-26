package firewall

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// All real-ipset interaction goes through exec, which we don't want to invoke
// in CI. Instead exercise:
//   - parseIPSetList / parseIPSetCounters against canned `ipset list` output
//   - the dry-run path (covers method plumbing without exec)
//   - the factory + interface satisfaction

const sampleIPSetList = `Name: mac_paid
Type: hash:mac
Revision: 4
Header: family inet hashsize 1024 maxelem 65536 counters
Size in memory: 280
References: 0
Number of entries: 3
Members:
AA:BB:CC:DD:EE:FF packets 0 bytes 0
11:22:33:44:55:66 packets 12 bytes 1024
de:ad:be:ef:00:00 packets 9 bytes 4096
garbage line ignored
`

func TestParseIPSetList(t *testing.T) {
	got := parseIPSetList(sampleIPSetList)
	sort.Strings(got)
	want := []string{"11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF", "DE:AD:BE:EF:00:00"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got  %+v\n want %+v", got, want)
	}
}

func TestParseIPSetListEmptyAndNoMembers(t *testing.T) {
	if got := parseIPSetList(""); got != nil {
		t.Errorf("empty: %+v", got)
	}
	// Header but no Members: section yet — initial create state.
	hdr := "Name: x\nType: hash:mac\n"
	if got := parseIPSetList(hdr); got != nil {
		t.Errorf("header-only: %+v", got)
	}
}

func TestParseIPSetCounters(t *testing.T) {
	got := parseIPSetCounters(sampleIPSetList)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if c := got["11:22:33:44:55:66"]; c.Packets != 12 || c.Bytes != 1024 {
		t.Errorf("11:22... counter wrong: %+v", c)
	}
	if c := got["AA:BB:CC:DD:EE:FF"]; c.Packets != 0 || c.Bytes != 0 {
		t.Errorf("AA:BB... counter wrong: %+v", c)
	}
	if c := got["DE:AD:BE:EF:00:00"]; c.Packets != 9 || c.Bytes != 4096 {
		t.Errorf("DE:AD... counter wrong: %+v", c)
	}
}

func TestParseUint(t *testing.T) {
	for in, want := range map[string]uint64{
		"0":      0,
		"42":     42,
		"123456": 123456,
	} {
		got, err := parseUint(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
		}
		if got != want {
			t.Errorf("%q → %d, want %d", in, got, want)
		}
	}
	if _, err := parseUint("12a"); err == nil {
		t.Error("12a should fail")
	}
	if _, err := parseUint(""); err == nil {
		t.Error("empty should fail")
	}
}

func TestIPSetManagerDryRunSync(t *testing.T) {
	m := NewIPSet("mac_paid", "br-paid")
	m.SetDryRun(true)
	ctx := context.Background()

	if err := m.EnsureSet(ctx); err != nil {
		t.Errorf("EnsureSet: %v", err)
	}
	if err := m.Add(ctx, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("Add: %v", err)
	}
	if err := m.Remove(ctx, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("Remove: %v", err)
	}
	if err := m.Sync(ctx, []string{"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "bad"}); err != nil {
		t.Errorf("Sync: %v", err)
	}
}

// Sync must stage into a scratch set and swap: `ipset restore` replays
// lines as individual kernel ops, so the old flush-then-add payload left a
// window (and, on mid-restore failure, a permanent state) where the live
// set was empty and every paying MAC was locked out.
func TestIpsetSwapRestorePayload(t *testing.T) {
	script := ipsetSwapRestore("mac_paid", []string{"AA:BB:CC:DD:EE:FF", "nope", "11:22:33:44:55:66"})
	lines := strings.Split(strings.TrimSpace(script), "\n")
	want := []string{
		"create mac_paid hash:mac counters -exist",
		"create mac_paid_swp hash:mac counters -exist",
		"flush mac_paid_swp",
		"add mac_paid_swp AA:BB:CC:DD:EE:FF",
		"add mac_paid_swp 11:22:33:44:55:66",
		"swap mac_paid_swp mac_paid",
		"destroy mac_paid_swp",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("restore script:\n%s\nwant:\n%s", script, strings.Join(want, "\n"))
	}
	// The live set must never be flushed or written directly.
	for _, l := range lines {
		if l == "flush mac_paid" || strings.HasPrefix(l, "add mac_paid ") {
			t.Errorf("live set mutated outside swap: %q", l)
		}
	}
}

func TestIpsetSwapRestoreEmpty(t *testing.T) {
	script := ipsetSwapRestore("mac_paid", nil)
	if strings.Contains(script, "add ") {
		t.Errorf("empty sync should add nothing: %s", script)
	}
	if !strings.Contains(script, "swap mac_paid_swp mac_paid") {
		t.Errorf("empty sync must still swap in the empty set: %s", script)
	}
}

func TestIPSetManagerRejectsInvalidMAC(t *testing.T) {
	m := NewIPSet("mac_paid", "br-paid")
	m.SetDryRun(true)
	if err := m.Add(context.Background(), "not-a-mac"); err == nil {
		t.Error("Add should reject malformed MAC")
	}
	if err := m.Remove(context.Background(), "x"); err == nil {
		t.Error("Remove should reject malformed MAC")
	}
}

func TestNewBackendFactory(t *testing.T) {
	for _, name := range []string{"", "nftables", "nft", "iptables", "ipt", "ipset", "NFTables", "  iptables  "} {
		fw, err := NewBackend(name, "inet", "billing", "mac_paid", "br-paid", true)
		if err != nil {
			t.Errorf("backend=%q: %v", name, err)
			continue
		}
		// Smoke: every backend exposes the API.
		if err := fw.EnsureSet(context.Background()); err != nil {
			t.Errorf("backend=%q EnsureSet: %v", name, err)
		}
	}
	if _, err := NewBackend("openvpn", "", "", "", "", true); err == nil {
		t.Error("unknown backend should error")
	}
}
