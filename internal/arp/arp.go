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

// Lookup returns the MAC for a single IPv4. "" if not found.
func Lookup(ctx context.Context, ip string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "ip", "neigh", "show", "to", ip)
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ip neigh: %w", err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "lladdr" {
				return strings.ToUpper(fields[i+1]), nil
			}
		}
	}
	return "", nil
}

// ListOnInterface returns all neigh entries seen on the given interface (e.g. "br-paid").
// Skips entries without an lladdr (FAILED / INCOMPLETE).
func ListOnInterface(ctx context.Context, iface string) ([]Entry, error) {
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
