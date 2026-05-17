// Package sightings keeps a history of MACs seen on the paid interface so the
// admin UI can suggest "recently seen but unsubscribed" devices even after
// they leave the live ARP table.
package sightings

import (
	"context"
	"log"
	"time"

	"router-billing/internal/arp"
	"router-billing/internal/db"
	"router-billing/internal/dnsmasq"
)

// Tracker runs in the background and upserts entries into device_sightings.
type Tracker struct {
	DB         *db.DB
	Iface      string        // e.g. "br-paid"
	LeasesPath string        // e.g. "/tmp/dhcp.leases"
	Interval   time.Duration // poll cadence; default 30s
	Retain     time.Duration // older sightings get purged; default 24h
}

func (t *Tracker) Run(ctx context.Context) {
	if t.Interval <= 0 {
		t.Interval = 30 * time.Second
	}
	if t.Retain <= 0 {
		t.Retain = 24 * time.Hour
	}
	// Initial scan so a freshly-restarted server doesn't show empty.
	t.scan(ctx)
	tick := time.NewTicker(t.Interval)
	defer tick.Stop()
	purge := time.NewTicker(1 * time.Hour)
	defer purge.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.scan(ctx)
		case <-purge.C:
			if err := t.DB.PurgeOldSightings(ctx, t.Retain); err != nil {
				log.Printf("sightings: purge: %v", err)
			}
		}
	}
}

func (t *Tracker) scan(ctx context.Context) {
	if t.Iface == "" {
		return
	}
	entries, err := arp.ListOnInterface(ctx, t.Iface)
	if err != nil {
		log.Printf("sightings: arp list: %v", err)
		return
	}
	hosts := dnsmasq.HostnameByMAC(t.LeasesPath)
	for _, e := range entries {
		if e.MAC == "" {
			continue
		}
		if err := t.DB.UpsertSighting(ctx, e.MAC, e.IP, hosts[e.MAC]); err != nil {
			log.Printf("sightings: upsert %s: %v", e.MAC, err)
		}
	}
}
