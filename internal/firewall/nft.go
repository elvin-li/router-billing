package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Manager keeps the nftables `mac_paid` set in sync with the DB.
//
// Layout managed externally by firewall-billing.sh (chain names are the
// script's concern — this package only touches the set):
//
//	table inet billing {
//	    set mac_paid { type ether_addr; }
//	    chain pre      { type nat    hook prerouting priority -1;
//	                     iifname "br-paid" ether saddr @mac_paid return
//	                     iifname "br-paid" tcp dport 80 redirect to :8080
//	                     iifname "br-paid" tcp dport 443 reject }
//	    chain forward  { type filter hook forward    priority -1;
//	                     iifname "br-paid" ether saddr @mac_paid return
//	                     iifname "br-paid" drop }
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
// Elements carry a 25h timeout so a stopped resolver gradually drains
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

// SyncWalledGardenIPs atomically replaces the walled-garden set with the
// given IPs, each with a fresh 25h timeout, in ONE nft transaction
// (flush + add via `nft -f -`). Callers pass the FULL resolved list every
// refresh cycle.
//
// This must be a full rebuild, not an add-only diff: the kernel does NOT
// refresh an element's timeout on re-add (verified on nft 1.0.9 / kernel
// 6.12 — `add element` of an existing timed element exits 0 and leaves the
// old expiry ticking). A diff-based "only add new IPs" strategy therefore
// let every stable payment-server IP silently expire after 25h of daemon
// uptime, permanently cutting unpaid clients off from the payment flow.
func (m *Manager) SyncWalledGardenIPs(ctx context.Context, setName string, ips []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	payload, kept := nftWGSyncPayload(m.Family, m.Table, setName, ips)
	if err := m.runStdin(ctx, payload); err != nil {
		return fmt.Errorf("sync walled garden: %w", err)
	}
	log.Printf("firewall: walled garden %s/%s/%s ← %d IPs (timeouts refreshed)",
		m.Family, m.Table, setName, kept)
	return nil
}

// nftWGSyncPayload builds the atomic flush+add transaction for the walled
// garden set. IPs that don't parse as plain IPv4 are dropped — the input
// ultimately comes from DNS answers, which an upstream resolver controls,
// and must never reach the nft script unvalidated. Returns the payload and
// the number of elements kept.
func nftWGSyncPayload(family, table, setName string, ips []string) (string, int) {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set %s %s %s\n", family, table, setName)
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		p := net.ParseIP(strings.TrimSpace(ip))
		if p == nil || p.To4() == nil {
			log.Printf("firewall: skip non-IPv4 walled-garden entry %q", ip)
			continue
		}
		parts = append(parts, p.To4().String()+" timeout 25h")
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n",
			family, table, setName, strings.Join(parts, ", "))
	}
	return b.String(), len(parts)
}

// Sync rebuilds the set from the given list of MACs in ONE nft transaction.
//
// Pre-v0.107 this was two separate nft invocations (flush, then add): a
// crash or error between them left the set EMPTY — every paying customer
// portal-redirected/dropped until the next resync — and concurrent readers
// saw the flushed window. `nft -f` submits both operations in a single
// netlink batch, so the swap is atomic: readers observe either the old or
// the new membership, never the gap, and a failed transaction leaves the
// old membership intact.
func (m *Manager) Sync(ctx context.Context, macs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	payload, kept := nftSyncPayload(m.Family, m.Table, m.Set, macs)
	if err := m.runStdin(ctx, payload); err != nil {
		return fmt.Errorf("sync set: %w", err)
	}
	log.Printf("firewall: synced %d MACs into %s/%s/%s", kept, m.Family, m.Table, m.Set)
	return nil
}

// nftSyncPayload builds the atomic flush+add transaction for the MAC set.
// Invalid MACs are dropped (logged), never emitted into the nft script.
func nftSyncPayload(family, table, set string, macs []string) (string, int) {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set %s %s %s\n", family, table, set)
	parts := make([]string, 0, len(macs))
	for _, mac := range macs {
		if !validMAC(mac) {
			log.Printf("firewall: skip invalid mac %q during sync", mac)
			continue
		}
		parts = append(parts, mac)
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, "add element %s %s %s { %s }\n",
			family, table, set, strings.Join(parts, ", "))
	}
	return b.String(), len(parts)
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

// List returns currently-present elements in the set, uppercase and sorted.
//
// Uses the JSON output (`nft -j list set`) and the same parser as Counters.
// The previous text-based parser grabbed everything between the FIRST "{"
// (the table's opening brace, not the elements') and the last "}", split on
// commas, and truncated each token at its first space: the first MAC always
// landed in the same comma-token as "set mac_paid { ... elements = {" and
// was silently dropped from every listing.
func (m *Manager) List(ctx context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dryRun {
		return nil, nil
	}
	out, err := m.runOut(ctx, "-j", "list", "set", m.Family, m.Table, m.Set)
	if err != nil {
		return nil, err
	}
	counters, err := parseCounters(out)
	if err != nil {
		return nil, err
	}
	macs := make([]string, 0, len(counters))
	for mac := range counters {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return macs, nil
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

// runStdin feeds a script to `nft -f -` so all contained operations commit
// as a single atomic netlink batch.
func (m *Manager) runStdin(ctx context.Context, script string) error {
	if m.dryRun {
		log.Printf("firewall(dry-run): nft -f - <<EOF\n%sEOF", script)
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.NftBin, "-f", "-") //nolint:gosec // see run()
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f -: %w (%s)", err, strings.TrimSpace(stderr.String()))
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
