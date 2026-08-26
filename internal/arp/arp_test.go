package arp

import (
	"reflect"
	"testing"
)

func TestParseNeighOutputTypical(t *testing.T) {
	in := `192.168.5.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.5.43 lladdr 11:22:33:44:55:66 STALE
192.168.5.50 FAILED
`
	got := parseNeighOutput(in)
	want := []Entry{
		{IP: "192.168.5.42", MAC: "AA:BB:CC:DD:EE:FF", State: "REACHABLE"},
		{IP: "192.168.5.43", MAC: "11:22:33:44:55:66", State: "STALE"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got  %+v\n want %+v", got, want)
	}
}

func TestParseNeighOutputDedupesByMAC(t *testing.T) {
	// Device has both v4 and v6 neighbor entries — first wins.
	in := `192.168.5.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE
fe80::1 lladdr aa:bb:cc:dd:ee:ff router STALE
`
	got := parseNeighOutput(in)
	if len(got) != 1 {
		t.Fatalf("expected 1 dedup entry; got %+v", got)
	}
	if got[0].IP != "192.168.5.42" {
		t.Errorf("first should win: got %s", got[0].IP)
	}
}

func TestParseNeighOutputSkipsFailedAndIncomplete(t *testing.T) {
	in := `192.168.5.10 FAILED
192.168.5.11 INCOMPLETE
192.168.5.12 lladdr aa:bb:cc:dd:ee:ff REACHABLE
`
	got := parseNeighOutput(in)
	if len(got) != 1 || got[0].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected just the reachable one; got %+v", got)
	}
}

func TestParseNeighOutputIgnoresGarbage(t *testing.T) {
	in := `garbage line
random words here
192.168.5.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE

not-an-ip lladdr aa:bb:cc:dd:ee:ff REACHABLE
`
	got := parseNeighOutput(in)
	if len(got) != 1 {
		t.Errorf("expected 1; got %d (%+v)", len(got), got)
	}
}

func TestParseNeighOutputUppercasesMAC(t *testing.T) {
	in := `192.168.5.42 lladdr aA:bB:Cc:Dd:ee:FF REACHABLE
`
	got := parseNeighOutput(in)
	if len(got) != 1 || got[0].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MAC should be uppercase; got %+v", got)
	}
}

func TestParseNeighOutputIPv6Entry(t *testing.T) {
	// IPv6 neigh with lladdr should be accepted.
	in := `fe80::abcd:1234 lladdr 11:22:33:44:55:66 router REACHABLE
`
	got := parseNeighOutput(in)
	if len(got) != 1 || got[0].MAC != "11:22:33:44:55:66" {
		t.Errorf("ipv6 entry not parsed: %+v", got)
	}
}

func TestParseNeighOutputEmpty(t *testing.T) {
	if got := parseNeighOutput(""); got != nil {
		t.Errorf("empty should yield nil; got %+v", got)
	}
}

func TestCanonicalIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"192.168.5.42", "192.168.5.42", true},
		{"  192.168.5.42 ", "192.168.5.42", true},
		{"fe80::1%br-paid", "fe80::1", true},
		{"FE80::ABCD", "fe80::abcd", true},
		{"::ffff:192.168.5.42", "192.168.5.42", true}, // mapped → canonical dotted quad
		{"", "", false},
		{"not-an-ip", "", false},
		{"192.168.5.42;reboot", "", false},
		{"-V", "", false},
		{"192.168.5.0/24", "", false},
		{"192.168.5.42 lladdr", "", false},
	}
	for _, c := range cases {
		got, ok := canonicalIP(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("canonicalIP(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestValidIface(t *testing.T) {
	for _, good := range []string{"br-paid", "wl0", "eth0.5", "wl-paidsec"} {
		if !validIface(good) {
			t.Errorf("validIface(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"", "-flag", "br paid", "br/paid", "0123456789abcdef", "br\npaid"} {
		if validIface(bad) {
			t.Errorf("validIface(%q) = true, want false", bad)
		}
	}
}
