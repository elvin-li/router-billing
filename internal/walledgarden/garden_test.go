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
			return []string{"::1", "127.0.0.1", "2001:db8::1"}, nil
		},
	}
	r.refresh(context.Background())
	if r.lastIPs["::1"] || r.lastIPs["2001:db8::1"] {
		t.Errorf("IPv6 should be skipped: %+v", r.lastIPs)
	}
	if !r.lastIPs["127.0.0.1"] {
		t.Errorf("IPv4 should be kept: %+v", r.lastIPs)
	}
	if len(fw.syncs) != 1 || !equal(fw.syncs[0], []string{"127.0.0.1"}) {
		t.Errorf("sync = %+v, want [[127.0.0.1]]", fw.syncs)
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
