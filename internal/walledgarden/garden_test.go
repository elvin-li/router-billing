package walledgarden

import (
	"context"
	"sort"
	"testing"
	"time"
)

// recordingFW captures every SyncWalledGardenIPs call so tests can assert
// what would be pushed into the kernel set.
type recordingFW struct {
	ensured bool
	syncs   [][]string
}

func (f *recordingFW) EnsureWalledGardenSet(_ context.Context, _ string) error {
	f.ensured = true
	return nil
}

func (f *recordingFW) SyncWalledGardenIPs(_ context.Context, _ string, ips []string) error {
	cp := append([]string(nil), ips...)
	sort.Strings(cp)
	f.syncs = append(f.syncs, cp)
	return nil
}

func TestResolverSyncsFullListEveryCycle(t *testing.T) {
	fw := &recordingFW{}
	r := &Resolver{
		FW:              fw,
		SetName:         "wg_paid",
		Domains:         []string{"weixin.qq.com", "alipay.com"},
		RefreshInterval: time.Hour,
		Lookup: func(_ context.Context, host string) ([]string, error) {
			switch host {
			case "weixin.qq.com":
				return []string{"1.1.1.1", "2.2.2.2"}, nil
			case "alipay.com":
				return []string{"3.3.3.3"}, nil
			}
			return nil, nil
		},
	}

	r.refresh(context.Background())
	if len(fw.syncs) != 1 {
		t.Fatalf("first refresh: %d syncs, want 1", len(fw.syncs))
	}
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if got := fw.syncs[0]; !equal(got, want) {
		t.Errorf("first sync = %v, want %v", got, want)
	}

	// Second refresh with UNCHANGED DNS answers must push the full list
	// again: the kernel does not refresh element timeouts on re-add, so
	// only a full rebuild keeps stable payment-server IPs alive past the
	// 25h element timeout. (Regression: the old diff-based version pushed
	// nothing here and the garden silently emptied after 25h of uptime.)
	r.refresh(context.Background())
	if len(fw.syncs) != 2 {
		t.Fatalf("second refresh: %d syncs, want 2", len(fw.syncs))
	}
	if got := fw.syncs[1]; !equal(got, want) {
		t.Errorf("second sync = %v, want %v (full list, not a diff)", got, want)
	}

	// Third refresh: an IP rotates. Full new list replaces the old one.
	r.Lookup = func(_ context.Context, host string) ([]string, error) {
		switch host {
		case "weixin.qq.com":
			return []string{"1.1.1.1", "4.4.4.4"}, nil // 2.2.2.2 gone
		case "alipay.com":
			return []string{"3.3.3.3"}, nil
		}
		return nil, nil
	}
	r.refresh(context.Background())
	want = []string{"1.1.1.1", "3.3.3.3", "4.4.4.4"}
	if got := fw.syncs[2]; !equal(got, want) {
		t.Errorf("third sync = %v, want %v", got, want)
	}
	if !r.lastIPs["4.4.4.4"] || r.lastIPs["2.2.2.2"] {
		t.Errorf("lastIPs not updated: %+v", r.lastIPs)
	}
}

// Regression: sync is a full rebuild, so a domain whose lookup fails would
// otherwise have its IPs flushed from the kernel set on that very cycle —
// one flaky DNS answer and unpaid clients instantly lose that payment
// provider. The resolver must stand in the domain's last successful answer
// (up to 25h) instead.
func TestResolverReusesCachedIPsOnPartialDNSFailure(t *testing.T) {
	fw := &recordingFW{}
	weixinUp := true
	r := &Resolver{
		FW: fw, SetName: "wg_paid",
		Domains: []string{"weixin.qq.com", "alipay.com"},
		Lookup: func(_ context.Context, host string) ([]string, error) {
			switch host {
			case "weixin.qq.com":
				if !weixinUp {
					return nil, context.DeadlineExceeded
				}
				return []string{"1.1.1.1"}, nil
			case "alipay.com":
				return []string{"3.3.3.3"}, nil
			}
			return nil, nil
		},
	}

	r.refresh(context.Background())
	if len(fw.syncs) != 1 || !equal(fw.syncs[0], []string{"1.1.1.1", "3.3.3.3"}) {
		t.Fatalf("first sync = %+v, want [[1.1.1.1 3.3.3.3]]", fw.syncs)
	}

	// weixin's DNS starts failing; its cached IP must stay in the pushed list.
	weixinUp = false
	r.refresh(context.Background())
	if len(fw.syncs) != 2 || !equal(fw.syncs[1], []string{"1.1.1.1", "3.3.3.3"}) {
		t.Fatalf("partial-failure sync = %+v, want cached weixin IP kept", fw.syncs)
	}

	// Once the cached answer is older than cacheTTL the domain drains out —
	// same schedule as a total outage — instead of pinning stale IPs forever.
	r.mu.Lock()
	c := r.cache["weixin.qq.com"]
	c.at = time.Now().Add(-cacheTTL - time.Minute)
	r.cache["weixin.qq.com"] = c
	r.mu.Unlock()
	r.refresh(context.Background())
	if len(fw.syncs) != 3 || !equal(fw.syncs[2], []string{"3.3.3.3"}) {
		t.Fatalf("expired-cache sync = %+v, want [[3.3.3.3]]", fw.syncs)
	}
}

func TestResolverKeepsSetOnTotalDNSFailure(t *testing.T) {
	fw := &recordingFW{}
	r := &Resolver{
		FW: fw, SetName: "wg_paid",
		Domains: []string{"weixin.qq.com"},
		Lookup: func(_ context.Context, _ string) ([]string, error) {
			return nil, context.DeadlineExceeded
		},
	}
	r.refresh(context.Background())
	if len(fw.syncs) != 0 {
		t.Errorf("DNS outage must not touch the set (drain via timeout), got %d syncs", len(fw.syncs))
	}
}

func TestResolverEmpty(t *testing.T) {
	fw := &recordingFW{}
	r := &Resolver{FW: fw, SetName: "wg_paid"}
	// No domains → Run returns immediately
	r.Run(context.Background())
	if fw.ensured {
		t.Error("Run without domains should not touch the firewall")
	}
}

func TestResolverSkipsIPv6(t *testing.T) {
	fw := &recordingFW{}
	r := &Resolver{
		FW: fw, SetName: "wg_paid",
		Domains: []string{"ipv6host"},
		Lookup: func(_ context.Context, host string) ([]string, error) {
			// ::ffff:9.9.9.9 is an IPv4-mapped answer (some resolvers emit
			// these): it must be normalized to dotted-quad, not discarded.
			// 127.0.0.1 is IPv4 but non-public and must still be rejected.
			return []string{"::1", "8.8.8.8", "127.0.0.1", "2001:db8::1", "::ffff:9.9.9.9"}, nil
		},
	}
	r.refresh(context.Background())
	if r.lastIPs["::1"] || r.lastIPs["2001:db8::1"] {
		t.Errorf("IPv6 should be skipped: %+v", r.lastIPs)
	}
	if r.lastIPs["127.0.0.1"] {
		t.Errorf("loopback IPv4 from DNS must not enter the garden: %+v", r.lastIPs)
	}
	if !r.lastIPs["8.8.8.8"] || !r.lastIPs["9.9.9.9"] {
		t.Errorf("public IPv4 (incl. mapped) should be kept: %+v", r.lastIPs)
	}
}

// DNS answers pointing into loopback / RFC1918 / link-local / CGNAT /
// multicast space must never enter the bypass set — a hostile or
// misconfigured upstream resolver answering 192.168.1.1 for a garden CDN
// domain would otherwise let UNPAID devices reach the router itself (or
// other LAN hosts) before the drop rule.
func TestResolverRejectsNonPublicDNSAnswers(t *testing.T) {
	fw := &recordingFW{}
	r := &Resolver{
		FW: fw, SetName: "wg_paid",
		Domains: []string{"evil-cdn.example"},
		Lookup: func(_ context.Context, host string) ([]string, error) {
			return []string{
				"127.0.0.1",       // loopback → router's own services
				"0.0.0.0",         // unspecified
				"10.1.2.3",        // RFC1918
				"172.16.0.1",      // RFC1918
				"192.168.1.1",     // RFC1918 (typical router admin IP)
				"169.254.1.1",     // link-local
				"100.64.0.1",      // CGNAT
				"224.0.0.1",       // multicast
				"255.255.255.255", // broadcast
				"241.0.0.1",       // 240/4 reserved
				"93.184.216.34",   // legit public answer
			}, nil
		},
	}
	r.refresh(context.Background())
	if len(r.lastIPs) != 1 || !r.lastIPs["93.184.216.34"] {
		t.Errorf("only the public answer should survive; got %+v", r.lastIPs)
	}
}

// A literal IP configured directly in walled_garden.domains is explicit
// admin intent (e.g. a LAN payment relay) — it bypasses the public-IP
// filter that applies to DNS answers.
func TestResolverKeepsLiteralIPEntries(t *testing.T) {
	fw := &recordingFW{}
	lookups := 0
	r := &Resolver{
		FW: fw, SetName: "wg_paid",
		Domains: []string{"192.168.10.5", "203.0.113.7"},
		Lookup: func(_ context.Context, host string) ([]string, error) {
			lookups++
			return nil, nil
		},
	}
	r.refresh(context.Background())
	if lookups != 0 {
		t.Errorf("literal IPs should not hit DNS; got %d lookups", lookups)
	}
	if !r.lastIPs["192.168.10.5"] || !r.lastIPs["203.0.113.7"] {
		t.Errorf("literal IP entries missing: %+v", r.lastIPs)
	}
	if len(fw.syncs) != 1 || !equal(fw.syncs[0], []string{"192.168.10.5", "203.0.113.7"}) {
		t.Errorf("sync = %+v, want both literal IPs pushed", fw.syncs)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
