package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"router-billing/internal/arp"
	"router-billing/internal/dnsmasq"
	"router-billing/internal/models"
)

// adminSessionAlive re-checks that the request still carries a live admin
// session. requireAdmin only runs once — at connection time — so a
// long-lived SSE stream would otherwise keep pushing live device data
// (MACs, IPs, hostnames, revenue) forever after the admin session was
// revoked ("panic button", revoke-all, logout elsewhere) or expired.
// Called on every tick; the sessions lookup is a single indexed SQLite
// read, negligible at the 5s stream cadence.
func (a *App) adminSessionAlive(r *http.Request) bool {
	c, err := r.Cookie(adminCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	sess, err := a.DB.GetSession(r.Context(), c.Value)
	return err == nil && sess != nil && sess.Kind == "admin"
}

// sseTickInterval is the stats/devices stream push cadence. Overridable
// so tests don't need to wait 5 real seconds per frame.
func (a *App) sseTickInterval() time.Duration {
	if a.sseTick > 0 {
		return a.sseTick
	}
	return 5 * time.Second
}

// GET /admin/devices/stream — Server-Sent Events.
// Pushes the device list every 5 seconds while the client is connected.
// On the page side, JS replaces the table rows on each event so the admin
// sees live updates without full-page reload.
func (a *App) handleAdminDevicesStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	send := func() {
		devs := a.buildDeviceList(r.Context())
		buf, _ := json.Marshal(devs)
		fmt.Fprintf(w, "event: devices\ndata: %s\n\n", buf)
		flusher.Flush()
	}

	send() // initial frame, no wait

	t := time.NewTicker(a.sseTickInterval())
	defer t.Stop()
	// Heartbeat comment line every 25s keeps the connection alive through
	// any proxies that might idle-time it out.
	hb := time.NewTicker(25 * time.Second)
	defer hb.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
			if !a.adminSessionAlive(r) {
				return
			}
			send()
		case <-hb.C:
			if !a.adminSessionAlive(r) {
				return
			}
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// deviceJSON is the wire format the SSE consumer expects.
type deviceJSON struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	Hostname   string `json:"hostname"`
	Online     bool   `json:"online"`
	Known      bool   `json:"known"`
	Active     bool   `json:"active"`
	Label      string `json:"label,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LastSeenAt string `json:"last_seen_at"`
	Bytes      uint64 `json:"bytes"`
	Packets    uint64 `json:"packets"`
	BytesHuman string `json:"bytes_human"`
}

func (a *App) buildDeviceList(ctx context.Context) []deviceJSON {
	iface := a.Cfg.PaidIface
	entries, err := arp.ListOnInterface(ctx, iface)
	if err != nil {
		log.Printf("stream: arp list: %v", err)
	}
	online := map[string]string{}
	for _, e := range entries {
		online[e.MAC] = e.IP
	}
	sightings, _ := a.DB.ListRecentSightings(ctx, 10*time.Minute)
	hostnames := dnsmasq.HostnameByMAC(dnsmasq.DefaultLeasesPath)
	counters, _ := a.MACSvc.FW.Counters(ctx)

	seen := map[string]bool{}
	out := make([]deviceJSON, 0, len(sightings)+len(entries))
	now := time.Now()

	add := func(mac, ip, host string, last time.Time) {
		if seen[mac] {
			return
		}
		seen[mac] = true
		d := deviceJSON{
			MAC: mac, IP: ip, Hostname: host,
			LastSeenAt: last.Local().Format("2006-01-02 15:04:05"),
		}
		if onlineIP, ok := online[mac]; ok {
			d.Online = true
			if d.IP == "" {
				d.IP = onlineIP
			}
		}
		if m, _ := a.DB.GetMAC(ctx, mac); m != nil {
			d.Known = true
			d.Label = m.Label
			d.ExpiresAt = m.ExpiresAt.Local().Format("2006-01-02 15:04")
			d.Active = m.Status == models.MACActive && m.ExpiresAt.After(now)
		}
		if c, ok := counters[mac]; ok {
			d.Bytes = c.Bytes
			d.Packets = c.Packets
			d.BytesHuman = humanBytes(c.Bytes)
		}
		out = append(out, d)
	}
	for _, s := range sightings {
		h := s.Hostname
		if h == "" {
			h = hostnames[s.MAC]
		}
		add(s.MAC, s.LastIP, h, s.LastSeen)
	}
	for _, e := range entries {
		add(e.MAC, e.IP, hostnames[e.MAC], now)
	}
	// Same ranking the initial HTML render uses (sortDevices): unauthorized
	// online first, then unauthorized offline, then authorized. Pre-v0.108
	// SSE frames were emitted in raw sighting order, so five seconds after
	// page load the sorted table silently reshuffled.
	rank := func(d deviceJSON) int {
		switch {
		case !d.Active && d.Online:
			return 0
		case !d.Active && !d.Online:
			return 1
		case d.Active && d.Online:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}
