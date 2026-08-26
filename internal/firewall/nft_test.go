package firewall

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestValidMAC(t *testing.T) {
	good := []string{
		"AA:BB:CC:DD:EE:FF",
		"00:11:22:33:44:55",
		"ff:ee:dd:cc:bb:aa",
	}
	for _, m := range good {
		if !validMAC(m) {
			t.Errorf("validMAC(%q) = false, want true", m)
		}
	}
	bad := []string{
		"AA:BB:CC:DD:EE",
		"AA-BB-CC-DD-EE-FF",
		"AABBCCDDEEFF",
		"AA:BB:CC:DD:EE:GG",
		"",
		"not-a-mac-address",
	}
	for _, m := range bad {
		if validMAC(m) {
			t.Errorf("validMAC(%q) = true, want false", m)
		}
	}
}

func TestDryRunSync(t *testing.T) {
	m := New("inet", "billing", "mac_paid", "br-paid")
	m.SetDryRun(true)
	ctx := context.Background()
	// These would otherwise shell out; with dry-run they're just logged.
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
	if err := m.SyncWalledGardenIPs(ctx, "wg_paid", []string{"1.2.3.4"}); err != nil {
		t.Errorf("SyncWalledGardenIPs: %v", err)
	}
	if _, err := m.List(ctx); err != nil {
		t.Errorf("List: %v", err)
	}
}

// Regression for the first-MAC drop: List used to parse the plain-text
// `nft -a list set` output, split the region between the table's opening
// brace and the final brace on commas, and truncate each token at its
// first space — the first element always shared its comma-token with
// "set mac_paid { ... elements = {" and was silently discarded. List now
// goes through the JSON output; this is verbatim `nft -j list set` output
// captured from nft 1.0.9 (the OpenWrt 23.05 version).
func TestParseCountersRealNftJSONKeepsFirstMAC(t *testing.T) {
	const real = `{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "mac_paid", "table": "billing", "type": "ether_addr", "handle": 3, "elem": [{"elem": {"val": "de:ad:be:ef:00:01", "counter": {"packets": 0, "bytes": 0}}}, {"elem": {"val": "de:ad:be:ef:00:02", "counter": {"packets": 0, "bytes": 0}}}], "stmt": [{"counter": null}]}}]}`
	got, err := parseCounters(real)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d MACs, want 2: %+v", len(got), got)
	}
	if _, ok := got["DE:AD:BE:EF:00:01"]; !ok {
		t.Error("first MAC missing — the pre-v0.107 List bug")
	}
	if _, ok := got["DE:AD:BE:EF:00:02"]; !ok {
		t.Error("second MAC missing")
	}
}

func TestNftSyncPayloadIsSingleTransaction(t *testing.T) {
	payload, kept := nftSyncPayload("inet", "billing", "mac_paid",
		[]string{"AA:BB:CC:DD:EE:FF", "totally-bogus", "11:22:33:44:55:66"})
	if kept != 2 {
		t.Errorf("kept = %d, want 2", kept)
	}
	want := "flush set inet billing mac_paid\n" +
		"add element inet billing mac_paid { AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66 }\n"
	if payload != want {
		t.Errorf("payload:\n%s\nwant:\n%s", payload, want)
	}

	// Empty membership → flush only, no dangling add.
	payload, kept = nftSyncPayload("inet", "billing", "mac_paid", nil)
	if kept != 0 || payload != "flush set inet billing mac_paid\n" {
		t.Errorf("empty: kept=%d payload=%q", kept, payload)
	}
}

func TestNftWGSyncPayloadValidatesIPs(t *testing.T) {
	payload, kept := nftWGSyncPayload("inet", "billing", "wg_paid", []string{
		"203.0.113.9",
		" 198.51.100.7 ",                  // whitespace tolerated
		"2001:db8::1",                     // IPv6 → dropped (set is ipv4_addr)
		"not-an-ip",                       // garbage → dropped
		"1.2.3.4 } ; delete table inet t", // injection attempt → dropped
	})
	if kept != 2 {
		t.Fatalf("kept = %d, want 2\npayload:\n%s", kept, payload)
	}
	if !strings.Contains(payload, "203.0.113.9 timeout 25h") ||
		!strings.Contains(payload, "198.51.100.7 timeout 25h") {
		t.Errorf("valid IPs missing timeout: %s", payload)
	}
	if strings.Contains(payload, "delete table") || strings.Contains(payload, "2001:db8") {
		t.Errorf("unvalidated input leaked into nft script: %s", payload)
	}
	if !strings.HasPrefix(payload, "flush set inet billing wg_paid\n") {
		t.Errorf("payload must rebuild (flush) to refresh timeouts: %s", payload)
	}

	// All-invalid → flush only.
	payload, kept = nftWGSyncPayload("inet", "billing", "wg_paid", []string{"::1", "junk"})
	if kept != 0 || payload != "flush set inet billing wg_paid\n" {
		t.Errorf("all-invalid: kept=%d payload=%q", kept, payload)
	}
}

func TestParseCountersReturnsUppercaseSortableMACs(t *testing.T) {
	got, err := parseCounters(`{"nftables":[{"set":{"elem":["aa:bb:cc:dd:ee:ff"]}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]MACCounter{"AA:BB:CC:DD:EE:FF": {}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
