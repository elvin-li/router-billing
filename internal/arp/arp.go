package arp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Entry is one ARP/neigh entry.
type Entry struct {
	IP    string
	MAC   string
	State string // REACHABLE / STALE / DELAY / etc.
}

// canonicalIP validates and canonicalizes s for use as an argv element of
// `ip neigh show to`. An IPv6 zone suffix ("fe80::1%br-paid" — the shape
// http.Request.RemoteAddr produces for link-local peers) is stripped:
// iproute2 rejects the %zone syntax outright, so pre-v0.119 every
// link-local IPv6 portal client failed MAC detection with log noise.
//
// Anything that doesn't parse as an IP is rejected before a process is
// spawned — this package is the exec boundary, and callers must never be
// able to smuggle option-looking or multi-token strings into the ip(8)
// argument vector.
func canonicalIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// validIface reports whether s is safe to pass as the `dev` argument.
// Linux interface names are 1-15 bytes, no whitespace / '/'; also refuse a
// leading '-' so the value can never be mistaken for an option.
func validIface(s string) bool {
	if s == "" || len(s) > 15 || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c == '/' || c > 0x7e {
			return false
		}
	}
	return true
}

// Lookup returns the MAC for a single IP (v4 or v6). "" if not found.
// The input must parse as an IP literal (an IPv6 zone suffix is tolerated
// and stripped); anything else is rejected without spawning `ip`.
func Lookup(ctx context.Context, ip string) (string, error) {
	arg, ok := canonicalIP(ip)
	if !ok {
		return "", fmt.Errorf("invalid ip: %q", ip)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "ip", "neigh", "show", "to", arg)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ip neigh: %w", err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "lladdr" {
				// Validate the token actually is a hardware address before
				// handing it to callers that feed DB lookups / firewall ops.
				if hw, err := net.ParseMAC(fields[i+1]); err == nil && len(hw) == 6 {
					return strings.ToUpper(hw.String()), nil
				}
			}
		}
	}
	return "", nil
}

// ListOnInterface returns all neigh entries seen on the given interface (e.g. "br-paid").
// Skips entries without an lladdr (FAILED / INCOMPLETE).
func ListOnInterface(ctx context.Context, iface string) ([]Entry, error) {
	if !validIface(iface) {
		return nil, fmt.Errorf("invalid interface name: %q", iface)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "ip", "neigh", "show", "dev", iface)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ip neigh show dev %s: %w", iface, err)
	}
	return parseNeighOutput(out.String()), nil
}

// parseNeighOutput is the pure-function half of ListOnInterface so it can be
// covered by tests without spawning `ip`. Returns entries in source order,
// deduped by MAC (devices with both IPv4 and IPv6 neigh entries produce just
// one Entry — the first seen).
func parseNeighOutput(out string) []Entry {
	if out == "" {
		return nil
	}
	lines := strings.Split(out, "\n")
	var entries []Entry
	seen := map[string]bool{}
	for _, line := range lines {
		// Examples:
		//   192.168.5.42 lladdr aa:bb:cc:dd:ee:ff REACHABLE
		//   192.168.5.43 FAILED
		//   fe80::1 lladdr aa:bb:cc:dd:ee:ff router STALE
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ipStr := fields[0]
		if net.ParseIP(ipStr) == nil {
			continue
		}
		var mac, state string
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "lladdr":
				if i+1 < len(fields) {
					mac = strings.ToUpper(fields[i+1])
				}
			case "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP", "FAILED", "INCOMPLETE":
				state = fields[i]
			}
		}
		if mac == "" || state == "FAILED" || state == "INCOMPLETE" {
			continue
		}
		if seen[mac] {
			continue
		}
		seen[mac] = true
		entries = append(entries, Entry{IP: ipStr, MAC: mac, State: state})
	}
	return entries
}
