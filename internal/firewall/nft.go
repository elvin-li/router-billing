package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Manager keeps the nftables `mac_paid` set in sync with the DB.
//
// Layout managed externally by /etc/firewall.user.billing:
//
//	table inet billing {
//	    set mac_paid { type ether_addr; }
//	    chain pre  { type nat    hook prerouting priority -1;
//	                 iifname "br-paid" ether saddr @mac_paid return
//	                 iifname "br-paid" tcp dport 80 redirect to :8080
//	                 iifname "br-paid" tcp dport 443 reject }
//	    chain fwd  { type filter hook forward    priority -1;
//	                 iifname "br-paid" ether saddr @mac_paid return
//	                 iifname "br-paid" drop }
//	}
type Manager struct {
	Family string // inet
	Table  string // billing
	Set    string // mac_paid
	Iface  string // br-paid (for logging only)
	NftBin string // /usr/sbin/nft
	mu     sync.Mutex
	dryRun bool
}

func New(family, table, setName, iface string) *Manager {
	bin, err := exec.LookPath("nft")
	if err != nil {
		bin = "/usr/sbin/nft"
	}
	return &Manager{
		Family: family,
		Table:  table,
		Set:    setName,
		Iface:  iface,
		NftBin: bin,
	}
}

// SetDryRun is for development on machines without nft.
func (m *Manager) SetDryRun(v bool) { m.dryRun = v }

// EnsureSet creates the table+set if missing. Idempotent.
//
// We always request the `counter` flag so per-MAC byte/packet counters are
// available via List/Counters. nft treats `add set` as a no-op if a matching
// set already exists. If an old install has a set without `counter`, the
// admin can drop the table (`nft delete table inet billing`) and restart —
// the new set will then have counters.
func (m *Manager) EnsureSet(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.run(ctx, "add", "table", m.Family, m.Table); err != nil {
		return fmt.Errorf("ensure table: %w", err)
	}
	// First try with counter flag. Falls back to plain set on failure (e.g.,
	// existing set without counter, very old kernels).
	if err := m.run(ctx, "add", "set", m.Family, m.Table, m.Set,
		"{ type ether_addr; counter; }"); err != nil {
		if isExistsError(err) {
			return nil
		}
		// Retry without counter flag.
		if err2 := m.run(ctx, "add", "set", m.Family, m.Table, m.Set,
			"{ type ether_addr; }"); err2 != nil && !isExistsError(err2) {
			return fmt.Errorf("ensure set: %w", err2)
		}
	}
	return nil
}

// Add inserts one MAC. Idempotent.
func (m *Manager) Add(ctx context.Context, mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.add(ctx, mac)
}

func (m *Manager) add(ctx context.Context, mac string) error {
	if !validMAC(mac) {
		return fmt.Errorf("invalid mac: %q", mac)
	}
	err := m.run(ctx, "add", "element", m.Family, m.Table, m.Set,
		fmt.Sprintf("{ %s }", mac))
	if err != nil && isExistsError(err) {
		return nil
	}
	return err
}

// Remove deletes one MAC. Idempotent (missing element is not an error).
func (m *Manager) Remove(ctx context.Context, mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.remove(ctx, mac)
}

func (m *Manager) remove(ctx context.Context, mac string) error {
	if !validMAC(mac) {
		return fmt.Errorf("invalid mac: %q", mac)
	}
	err := m.run(ctx, "delete", "element", m.Family, m.Table, m.Set,
		fmt.Sprintf("{ %s }", mac))
	if err != nil && (isNotFoundError(err) || isExistsError(err)) {
		return nil
	}
	return err
}

// EnsureWalledGardenSet creates a per-IP allowlist set. Idempotent.
// Elements are added with a 25h timeout so a stopped resolver gradually drains
// the set instead of trapping a stale IP forever.
func (m *Manager) EnsureWalledGardenSet(ctx context.Context, setName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.run(ctx, "add", "table", m.Family, m.Table); err != nil {
		return fmt.Errorf("ensure wg table: %w", err)
	}
	if err := m.run(ctx, "add", "set", m.Family, m.Table, setName,
		"{ type ipv4_addr; flags timeout; }"); err != nil && !isExistsError(err) {
		return fmt.Errorf("ensure wg set: %w", err)
	}
	return nil
}

// AddWalledGardenIPs inserts IPs with a 25h timeout. Idempotent.
func (m *Manager) AddWalledGardenIPs(ctx context.Context, setName string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip+" timeout 25h")
	}
	arg := "{ " + strings.Join(parts, ", ") + " }"
	if err := m.run(ctx, "add", "element", m.Family, m.Table, setName, arg); err != nil {
		if isExistsError(err) {
			return nil
		}
		return err
	}
	return nil
}

// RemoveWalledGardenIPs deletes IPs. Idempotent on missing entries.
func (m *Manager) RemoveWalledGardenIPs(ctx context.Context, setName string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	arg := "{ " + strings.Join(ips, ", ") + " }"
	if err := m.run(ctx, "delete", "element", m.Family, m.Table, setName, arg); err != nil {
		if isNotFoundError(err) || isExistsError(err) {
			return nil
		}
		return err
	}
	return nil
}

// Sync rebuilds the set atomically from the given list of MACs.
func (m *Manager) Sync(ctx context.Context, macs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.run(ctx, "flush", "set", m.Family, m.Table, m.Set); err != nil {
		return fmt.Errorf("flush set: %w", err)
	}
	if len(macs) == 0 {
		return nil
	}
	// nft accepts comma-separated elements in one shot.
	parts := make([]string, 0, len(macs))
	for _, mac := range macs {
		if !validMAC(mac) {
			log.Printf("firewall: skip invalid mac %q during sync", mac)
			continue
		}
		parts = append(parts, mac)
	}
	if len(parts) == 0 {
		return nil
	}
	arg := "{ " + strings.Join(parts, ", ") + " }"
	if err := m.run(ctx, "add", "element", m.Family, m.Table, m.Set, arg); err != nil {
		return fmt.Errorf("populate set: %w", err)
	}
	log.Printf("firewall: synced %d MACs into %s/%s/%s", len(parts), m.Family, m.Table, m.Set)
	return nil
}

// MACCounter is the per-MAC byte/packet counter from nftables.
// Zero values mean either no counter flag on the set or no traffic yet.
type MACCounter struct {
	Packets uint64
	Bytes   uint64
}

// Counters returns the per-MAC counter map. Empty map (not nil) on a set
// without the counter flag. Errors only on nft exec / json parse failures.
func (m *Manager) Counters(ctx context.Context) (map[string]MACCounter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dryRun {
		return map[string]MACCounter{}, nil
	}
	out, err := m.runOut(ctx, "-j", "list", "set", m.Family, m.Table, m.Set)
	if err != nil {
		return nil, err
	}
	return parseCounters(out)
}

// parseCounters handles both with- and without-counter JSON shapes:
//
//	{"set":{"elem":["aa:bb..."]}}                     // no counter
//	{"set":{"elem":[{"elem":{"val":"aa:bb..","counter":{"packets":..,"bytes":..}}}]}}
func parseCounters(j string) (map[string]MACCounter, error) {
	if j == "" {
		return map[string]MACCounter{}, nil
	}
	var doc struct {
		NFT []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(j), &doc); err != nil {
		return nil, fmt.Errorf("nft json: %w", err)
	}
	out := map[string]MACCounter{}
	for _, item := range doc.NFT {
		if item.Set == nil {
			continue
		}
		for _, raw := range item.Set.Elem {
			// Try plain string first.
			var s string
			if err := json.Unmarshal(raw, &s); err == nil {
				if mac := strings.ToUpper(s); validMAC(mac) {
					out[mac] = MACCounter{}
				}
				continue
			}
			// Otherwise expect {"elem":{"val":"...","counter":{...}}}
			var wrap struct {
				Elem struct {
					Val     string `json:"val"`
					Counter struct {
						Packets uint64 `json:"packets"`
						Bytes   uint64 `json:"bytes"`
					} `json:"counter"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(raw, &wrap); err == nil {
				mac := strings.ToUpper(wrap.Elem.Val)
				if validMAC(mac) {
					out[mac] = MACCounter{
						Packets: wrap.Elem.Counter.Packets,
						Bytes:   wrap.Elem.Counter.Bytes,
					}
				}
			}
		}
	}
	return out, nil
}

// List returns currently-present elements in the set (for debugging).
func (m *Manager) List(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, err := m.runOut(ctx, "-a", "list", "set", m.Family, m.Table, m.Set)
	if err != nil {
		return nil, err
	}
	return parseNftListOutput(out), nil
}

// parseNftListOutput extracts the MACs from `nft list set` output, which
// wraps the set in the table declaration:
//
//	table inet billing { # handle 5
//	    set mac_paid { # handle 1
//	        type ether_addr
//	        elements = { aa:bb:... counter packets 4 bytes 260, 11:22:... }
//	    }
//	}
//
// The parse must anchor on the "elements" clause — the first "{" in the
// output belongs to the table, so a first-brace/last-brace scan glues the
// first MAC onto the set preamble and loses it.
func parseNftListOutput(out string) []string {
	idx := strings.Index(out, "elements")
	if idx < 0 {
		return nil
	}
	open := strings.Index(out[idx:], "{")
	if open < 0 {
		return nil
	}
	open += idx
	length := strings.Index(out[open:], "}")
	if length < 0 {
		return nil
	}
	body := out[open+1 : open+length]
	var macs []string
	for _, tok := range strings.Split(body, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// strip trailing "counter packets N bytes N" / "# handle N"
		if i := strings.IndexAny(tok, " \t"); i > 0 {
			tok = tok[:i]
		}
		if validMAC(tok) {
			macs = append(macs, strings.ToUpper(tok))
		}
	}
	return macs
}

// run executes nft with args and returns the stderr-tagged error.
func (m *Manager) run(ctx context.Context, args ...string) error {
	if m.dryRun {
		log.Printf("firewall(dry-run): nft %s", strings.Join(args, " "))
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// G204 nolint: NftBin is resolved by exec.LookPath at construction time
	// from a fixed list ("nft" / "/usr/sbin/nft"), never user-controlled. args
	// are built internally (set/element ops), not from external input.
	cmd := exec.CommandContext(ctx, m.NftBin, args...) //nolint:gosec
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (m *Manager) runOut(ctx context.Context, args ...string) (string, error) {
	if m.dryRun {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.NftBin, args...) //nolint:gosec // see run()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func isExistsError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "file exists") || strings.Contains(s, "already exists")
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such file") || strings.Contains(s, "does not exist") ||
		strings.Contains(s, "not found")
}

func validMAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i, c := range s {
		switch i % 3 {
		case 0, 1:
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
				return false
			}
		case 2:
			if c != ':' {
				return false
			}
		}
	}
	return true
}
