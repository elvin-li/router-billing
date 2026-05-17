package firewall

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// IPSetManager is the iptables/ipset implementation of API. Used on OpenWrt
// 21.02 and earlier (which don't ship fw4/nftables by default), or on
// distributions where nftables isn't first-class yet.
//
// MAC list lives in an ipset (`hash:mac` with `counters` flag). Forwarding
// rules under /etc/firewall.user reference the set via
//
//	iptables -m set --match-set mac_paid src ...
//
// We never edit /etc/firewall.user from Go — the install script writes the
// rules once; this manager only mutates the *contents* of the ipset
// (add/del/list), exactly like the nftables Manager does for `nft add element`.
type IPSetManager struct {
	Set      string // e.g. "mac_paid" — ipset name (no family prefix on iptables)
	Iface    string // for logging only ("br-paid")
	IPSetBin string // path to /usr/sbin/ipset (or whatever LookPath finds)
	dryRun   bool
	mu       sync.Mutex
}

// NewIPSet returns a manager for the named ipset. It does NOT create the set
// — EnsureSet does that, idempotently, on Run startup.
func NewIPSet(set, iface string) *IPSetManager {
	bin, err := exec.LookPath("ipset")
	if err != nil {
		bin = "/usr/sbin/ipset"
	}
	return &IPSetManager{Set: set, Iface: iface, IPSetBin: bin}
}

// SetDryRun: log commands instead of running them — for dev on machines
// without ipset. Matches the nftables Manager API.
func (m *IPSetManager) SetDryRun(v bool) { m.dryRun = v }

// EnsureSet creates the ipset if missing. `counters` flag enables per-element
// byte/packet counters readable via `ipset list --terse=no`.
func (m *IPSetManager) EnsureSet(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// `create -exist` is idempotent. counters=yes survives across restarts.
	if err := m.run(ctx, "create", m.Set, "hash:mac", "counters", "-exist"); err != nil {
		return fmt.Errorf("ipset create: %w", err)
	}
	return nil
}

// Add inserts a MAC. Idempotent — `add -exist` swallows the duplicate error.
func (m *IPSetManager) Add(ctx context.Context, mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validMAC(mac) {
		return fmt.Errorf("invalid mac: %q", mac)
	}
	return m.run(ctx, "add", m.Set, mac, "-exist")
}

// Remove deletes a MAC. Idempotent — `del -exist` swallows missing-element.
func (m *IPSetManager) Remove(ctx context.Context, mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validMAC(mac) {
		return fmt.Errorf("invalid mac: %q", mac)
	}
	return m.run(ctx, "del", m.Set, mac, "-exist")
}

// Sync replaces all elements atomically using `ipset restore` (single
// kernel transaction; reads stay valid throughout).
func (m *IPSetManager) Sync(ctx context.Context, macs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Build a restore script that flushes + adds in one shot.
	var b strings.Builder
	fmt.Fprintf(&b, "flush %s\n", m.Set)
	for _, mac := range macs {
		if !validMAC(mac) {
			log.Printf("firewall(ipset): skip invalid mac %q during sync", mac)
			continue
		}
		fmt.Fprintf(&b, "add %s %s\n", m.Set, mac)
	}
	if m.dryRun {
		log.Printf("firewall(ipset dry-run): restore <<EOF\n%sEOF", b.String())
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.IPSetBin, "restore", "-exist") //nolint:gosec // IPSetBin from LookPath; payload is internally built
	cmd.Stdin = strings.NewReader(b.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ipset restore: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// List returns currently-present MACs (uppercase).
func (m *IPSetManager) List(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := m.runOut(ctx, "list", m.Set)
	if err != nil {
		return nil, err
	}
	return parseIPSetList(out), nil
}

// Counters returns per-MAC bytes/packets. When the set was created without
// the counters flag, all values are zero.
func (m *IPSetManager) Counters(ctx context.Context) (map[string]MACCounter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := m.runOut(ctx, "list", m.Set)
	if err != nil {
		return nil, err
	}
	return parseIPSetCounters(out), nil
}

// run executes ipset with args, swallowing common idempotent-add/del errors.
func (m *IPSetManager) run(ctx context.Context, args ...string) error {
	if m.dryRun {
		log.Printf("firewall(ipset dry-run): %s %s", m.IPSetBin, strings.Join(args, " "))
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.IPSetBin, args...) //nolint:gosec // IPSetBin from LookPath at construction; args internally generated
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// `-exist` should swallow these but older ipset (pre-6.34) returns
		// non-zero with the message anyway. Be tolerant.
		s := strings.ToLower(stderr.String() + err.Error())
		if strings.Contains(s, "already added") || strings.Contains(s, "not in set") ||
			strings.Contains(s, "already exists") {
			return nil
		}
		return fmt.Errorf("ipset %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (m *IPSetManager) runOut(ctx context.Context, args ...string) (string, error) {
	if m.dryRun {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.IPSetBin, args...) //nolint:gosec // see run()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ipset %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// parseIPSetList extracts the MAC entries from `ipset list <name>` output.
// Example header + entries:
//
//	Name: mac_paid
//	Type: hash:mac
//	Revision: 4
//	Header: family inet hashsize 1024 maxelem 65536 counters
//	Size in memory: 280
//	References: 0
//	Number of entries: 2
//	Members:
//	AA:BB:CC:DD:EE:FF packets 0 bytes 0
//	11:22:33:44:55:66 packets 12 bytes 1024
func parseIPSetList(out string) []string {
	var members []string
	inMembers := false
	for _, line := range strings.Split(out, "\n") {
		if !inMembers {
			if strings.HasPrefix(line, "Members:") {
				inMembers = true
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if validMAC(fields[0]) {
			members = append(members, strings.ToUpper(fields[0]))
		}
	}
	return members
}

// parseIPSetCounters parses the same output but extracts per-MAC counters.
func parseIPSetCounters(out string) map[string]MACCounter {
	res := map[string]MACCounter{}
	inMembers := false
	for _, line := range strings.Split(out, "\n") {
		if !inMembers {
			if strings.HasPrefix(line, "Members:") {
				inMembers = true
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || !validMAC(fields[0]) {
			continue
		}
		mac := strings.ToUpper(fields[0])
		var c MACCounter
		// Look for "packets <n>" and "bytes <n>" anywhere on the line.
		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "packets":
				c.Packets, _ = parseUint(fields[i+1])
			case "bytes":
				c.Bytes, _ = parseUint(fields[i+1])
			}
		}
		res[mac] = c
	}
	return res
}

func parseUint(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty input")
	}
	var n uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a uint: %q", s)
		}
		n = n*10 + uint64(r-'0')
	}
	return n, nil
}

// Compile-time check: IPSetManager satisfies API.
var _ API = (*IPSetManager)(nil)
