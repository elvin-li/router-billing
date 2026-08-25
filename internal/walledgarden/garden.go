// Package walledgarden lets unpaid devices on the paid SSID reach a short list
// of admin-configured domains (typically WeChat / Alipay servers, NTP, captive
// portal probes) so they can actually complete the payment flow.
//
// Mechanism: a separate nftables set `wg_paid` (type ipv4_addr) is matched
// before the drop rule. We periodically resolve the configured domains and
// atomically rebuild the set with the FULL result, refreshing every
// element's 25h timeout. The kernel does not refresh a timed element's
// expiry on re-add, so an add-only diff would let stable payment-server IPs
// expire out of the set after 25h of uptime — permanently blocking unpaid
// devices from the payment flow. The timeout still drains the set gracefully
// if the resolver stops running.
package walledgarden

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// FW is the slice of firewall.Manager the resolver needs; an interface so
// tests can record what actually gets pushed to the kernel set.
type FW interface {
	EnsureWalledGardenSet(ctx context.Context, setName string) error
	SyncWalledGardenIPs(ctx context.Context, setName string, ips []string) error
}

type Resolver struct {
	FW              FW
	SetName         string        // e.g. "wg_paid"
	Domains         []string      // admin-supplied
	RefreshInterval time.Duration // default 5 minutes
	// Lookup overrides DNS (used in tests). nil → net.DefaultResolver.
	Lookup func(ctx context.Context, host string) ([]string, error)

	mu      sync.Mutex
	lastIPs map[string]bool // most recent resolved set (lowercase host stripped, IPs)
}

func (r *Resolver) Run(ctx context.Context) {
	if r.FW == nil || len(r.Domains) == 0 || r.SetName == "" {
		return
	}
	if r.RefreshInterval <= 0 {
		r.RefreshInterval = 5 * time.Minute
	}
	if err := r.FW.EnsureWalledGardenSet(ctx, r.SetName); err != nil {
		log.Printf("walledgarden: ensure set: %v", err)
	}
	r.refresh(ctx)
	t := time.NewTicker(r.RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refresh(ctx)
		}
	}
}

func (r *Resolver) refresh(ctx context.Context) {
	resolved := map[string]bool{}
	for _, raw := range r.Domains {
		host := strings.TrimSpace(strings.ToLower(raw))
		if host == "" {
			continue
		}
		host = strings.TrimPrefix(host, "*.")
		// A literal IP entry is explicit admin intent — honor it verbatim
		// (including RFC1918, e.g. a LAN payment relay) without the
		// public-IP filter applied to DNS answers below.
		if lit := net.ParseIP(host); lit != nil {
			if v4 := lit.To4(); v4 != nil { // IPv4 only for now
				resolved[v4.String()] = true
			}
			continue
		}
		ips, err := r.lookup(ctx, host)
		if err != nil {
			log.Printf("walledgarden: lookup %s: %v", host, err)
			continue
		}
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			v4 := parsed.To4()
			if v4 == nil { // IPv4 only for now
				continue
			}
			// SECURITY: only public unicast answers make it into the
			// bypass set. The garden domains resolve via external DNS —
			// an upstream that answers with 127.0.0.1, 192.168.1.1,
			// 169.254.x.x etc. (misconfiguration or a deliberate
			// rebinding-style answer for a garden CDN domain) must not
			// punch a hole letting UNPAID devices reach the router
			// itself or other LAN hosts before the drop rule.
			if !publicIPv4(v4) {
				log.Printf("walledgarden: skip non-public answer %s for %s", v4, host)
				continue
			}
			resolved[v4.String()] = true
		}
	}
	// Total resolution failure (DNS outage): keep whatever the kernel set
	// holds — the per-element timeout drains it if the outage persists.
	if len(resolved) == 0 {
		return
	}

	r.mu.Lock()
	r.lastIPs = resolved
	r.mu.Unlock()

	// Push the FULL list every cycle: SyncWalledGardenIPs rebuilds the set
	// atomically, which is the only way to refresh element timeouts (the
	// kernel ignores re-adds of live timed elements). Also self-heals after
	// a failed previous push and prunes IPs that stopped resolving.
	all := make([]string, 0, len(resolved))
	for ip := range resolved {
		all = append(all, ip)
	}
	if err := r.FW.SyncWalledGardenIPs(ctx, r.SetName, all); err != nil {
		log.Printf("walledgarden: sync: %v", err)
		return
	}
	log.Printf("walledgarden: %d domains → %d IPs (timeouts refreshed)", len(r.Domains), len(resolved))
}

// publicIPv4 reports whether v4 (guaranteed 4-byte) is a publicly
// routable unicast address. Everything else — loopback, RFC1918,
// link-local, CGNAT (100.64/10), multicast, unspecified, broadcast —
// is rejected from DNS-sourced walled-garden entries.
func publicIPv4(v4 net.IP) bool {
	switch {
	case v4.IsUnspecified(), v4.IsLoopback(), v4.IsPrivate(),
		v4.IsLinkLocalUnicast(), v4.IsLinkLocalMulticast(), v4.IsMulticast():
		return false
	}
	if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10 CGNAT
		return false
	}
	if v4[0] >= 240 || v4.Equal(net.IPv4bcast) { // 240/4 reserved + broadcast
		return false
	}
	return true
}

func (r *Resolver) lookup(ctx context.Context, host string) ([]string, error) {
	if r.Lookup != nil {
		return r.Lookup(ctx, host)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}
