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
}
