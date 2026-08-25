package walledgarden

import (
	"context"
	"testing"
	"time"

	"router-billing/internal/firewall"
)

func TestResolverDiff(t *testing.T) {
	fw := firewall.New("inet", "billing", "mac_paid", "br-paid")
	fw.SetDryRun(true)

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
	if got := len(r.lastIPs); got != 3 {
		t.Errorf("first refresh: got %d IPs, want 3", got)
	}

	// Second refresh: one IP changes. Expect diff add/remove (dry-run, no error).
	r.Lookup = func(_ context.Context, host string) ([]string, error) {
		switch host {
		case "weixin.qq.com":
			return []string{"1.1.1.1", "4.4.4.4"}, nil // drop 2.2, add 4.4
		case "alipay.com":
			return []string{"3.3.3.3"}, nil
		}
		return nil, nil
	}
	r.refresh(context.Background())
	if got := len(r.lastIPs); got != 3 {
		t.Errorf("after diff: got %d IPs, want 3", got)
	}
	if !r.lastIPs["4.4.4.4"] || r.lastIPs["2.2.2.2"] {
		t.Errorf("diff did not apply correctly: %+v", r.lastIPs)
	}
}

func TestResolverEmpty(t *testing.T) {
	fw := firewall.New("inet", "billing", "mac_paid", "br-paid")
	fw.SetDryRun(true)
	r := &Resolver{FW: fw, SetName: "wg_paid"}
	// No domains → Run returns immediately
	r.Run(context.Background())
}

func TestResolverSkipsIPv6(t *testing.T) {
	fw := firewall.New("inet", "billing", "mac_paid", "br-paid")
	fw.SetDryRun(true)
	r := &Resolver{
		FW: fw, SetName: "wg_paid",
		Domains: []string{"ipv6host"},
		Lookup: func(_ context.Context, host string) ([]string, error) {
			return []string{"::1", "8.8.8.8", "2001:db8::1"}, nil
		},
	}
	r.refresh(context.Background())
	if r.lastIPs["::1"] || r.lastIPs["2001:db8::1"] {
		t.Errorf("IPv6 should be skipped: %+v", r.lastIPs)
	}
	if !r.lastIPs["8.8.8.8"] {
		t.Errorf("public IPv4 should be kept: %+v", r.lastIPs)
	}
}

// DNS answers pointing into loopback / RFC1918 / link-local / CGNAT /
// multicast space must never enter the bypass set — a hostile or
// misconfigured upstream resolver answering 192.168.1.1 for a garden CDN
// domain would otherwise let UNPAID devices reach the router itself (or
// other LAN hosts) before the drop rule.
func TestResolverRejectsNonPublicDNSAnswers(t *testing.T) {
	fw := firewall.New("inet", "billing", "mac_paid", "br-paid")
	fw.SetDryRun(true)
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
	fw := firewall.New("inet", "billing", "mac_paid", "br-paid")
	fw.SetDryRun(true)
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
}
