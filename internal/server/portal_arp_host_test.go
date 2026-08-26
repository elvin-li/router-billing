package server

import "testing"

// arpLookupHost decides which RemoteAddrs are worth an `ip neigh` exec.
// Loopback (including IPv4-mapped ::ffff:127.0.0.1), unspecified, and
// unparseable peers must short-circuit to ""; IPv6 zone suffixes must be
// stripped so link-local portal clients actually resolve.
func TestARPLookupHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"192.168.5.42:51515", "192.168.5.42"},
		{"[fe80::abcd]:51515", "fe80::abcd"},
		{"[fe80::abcd%br-paid]:51515", "fe80::abcd"}, // zone stripped
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"192.168.5.42", "192.168.5.42"}, // port-less tolerated
		{"127.0.0.1:8080", ""},
		{"[::1]:8080", ""},
		{"[::ffff:127.0.0.1]:8080", ""}, // mapped loopback — missed by the old "127." prefix check
		{"[::]:8080", ""},
		{"0.0.0.0:8080", ""},
		{"", ""},
		{"@", ""},
		{"not-an-ip:1234", ""},
	}
	for _, c := range cases {
		if got := arpLookupHost(c.in); got != c.want {
			t.Errorf("arpLookupHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
