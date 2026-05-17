// Package walledgarden lets unpaid devices on the paid SSID reach a short list
// of admin-configured domains (typically WeChat / Alipay servers, NTP, captive
// portal probes) so they can actually complete the payment flow.
//
// Mechanism: a separate nftables set `wg_paid` (type ipv4_addr) is matched
// before the drop rule. We periodically resolve the configured domains and
// keep the set in sync. Each element has a 24h timeout so dead IPs eventually
// drain out.
package walledgarden

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"router-billing/internal/firewall"
)

type Resolver struct {
	FW              *firewall.Manager
	SetName         string        // e.g. "wg_paid"
	Domains         []string      // admin-supplied
	RefreshInterval time.Duration // default 5 minutes
	// Lookup overrides DNS (used in tests). nil → net.DefaultResolver.
	Lookup func(ctx context.Context, host string) ([]string, error)

	mu       sync.Mutex
	lastIPs  map[string]bool // most recent resolved set (lowercase host stripped, IPs)
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
		ips, err := r.lookup(ctx, host)
		if err != nil {
			log.Printf("walledgarden: lookup %s: %v", host, err)
			continue
		}
		for _, ip := range ips {
			if net.ParseIP(ip) != nil && !strings.Contains(ip, ":") { // IPv4 only for now
				resolved[ip] = true
			}
		}
	}
	if len(resolved) == 0 {
		return
	}

	r.mu.Lock()
	prev := r.lastIPs
	r.lastIPs = resolved
	r.mu.Unlock()

	var add, remove []string
	for ip := range resolved {
		if !prev[ip] {
			add = append(add, ip)
		}
	}
	for ip := range prev {
		if !resolved[ip] {
			remove = append(remove, ip)
		}
	}

	if len(add) > 0 {
		if err := r.FW.AddWalledGardenIPs(ctx, r.SetName, add); err != nil {
			log.Printf("walledgarden: add: %v", err)
		}
	}
	if len(remove) > 0 {
		if err := r.FW.RemoveWalledGardenIPs(ctx, r.SetName, remove); err != nil {
			log.Printf("walledgarden: remove: %v", err)
		}
	}
	log.Printf("walledgarden: %d domains → %d IPs (+%d -%d)", len(r.Domains), len(resolved), len(add), len(remove))
}

func (r *Resolver) lookup(ctx context.Context, host string) ([]string, error) {
	if r.Lookup != nil {
		return r.Lookup(ctx, host)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}
