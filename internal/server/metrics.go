package server

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

// /metrics — Prometheus text exposition. Optionally protected by
// `metrics_token` in config; if unset, the endpoint is open.
func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if tok := a.Cfg.MetricsToken; tok != "" {
		got := r.Header.Get("Authorization")
		if got != "Bearer "+tok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	stats, _ := a.DB.Stats(r.Context())
	fwMACs, _ := a.MACSvc.FW.List(r.Context())
	dbSize := int64(-1)
	if st, err := os.Stat(a.Cfg.DBPath); err == nil {
		dbSize = st.Size()
	}
	wxOn := boolToFloat(a.WeChat != nil)
	aliOn := boolToFloat(a.Alipay != nil)
	uptime := int(time.Since(a.StartAt).Seconds())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	mw := metricWriter{w: w}
	mw.gauge("router_billing_uptime_seconds", "Process uptime in seconds.", float64(uptime), nil)
	mw.gauge("router_billing_db_size_bytes", "Size of the SQLite file.", float64(dbSize), nil)
	mw.gauge("router_billing_mac_total", "Total MACs known.", float64(stats.Total), nil)
	mw.gauge("router_billing_mac_active", "Active (non-expired) MACs.", float64(stats.Active), nil)
	mw.gauge("router_billing_mac_expired", "Expired/blocked MACs.", float64(stats.Expired), nil)
	mw.gauge("router_billing_users_total", "Registered users.", float64(stats.Users), nil)
	mw.gauge("router_billing_revenue_cents_total", "Cumulative paid order amount in cents.", float64(stats.RevenueCents), nil)
	mw.gauge("router_billing_firewall_set_size", "Number of MACs currently in the nftables set.", float64(len(fwMACs)), nil)
	mw.gauge("router_billing_provider_enabled", "1 if the payment provider is enabled.", wxOn, map[string]string{"provider": "wechat"})
	mw.gauge("router_billing_provider_enabled", "", aliOn, map[string]string{"provider": "alipay"})

	// Shadowsocks proxy metrics. Always emit the enabled gauge (0 when the
	// proxy is off) so dashboards can chart adoption; emit the counters only
	// when the proxy is running.
	ssOn := a.SSMetrics != nil
	mw.gauge("router_billing_shadowsocks_enabled", "1 if the built-in Shadowsocks proxy is enabled.", boolToFloat(ssOn), nil)
	if ssOn {
		s := a.SSMetrics.Snapshot()
		mw.counter("router_billing_shadowsocks_connections_total", "Total accepted Shadowsocks connections.", float64(s.ConnectionsTotal), nil)
		mw.gauge("router_billing_shadowsocks_active_connections", "Currently-open Shadowsocks relays.", float64(s.ActiveConns), nil)
		mw.counter("router_billing_shadowsocks_bytes_in_total", "Bytes relayed client→target.", float64(s.BytesIn), nil)
		mw.counter("router_billing_shadowsocks_bytes_out_total", "Bytes relayed target→client.", float64(s.BytesOut), nil)
		mw.counter("router_billing_shadowsocks_handshake_errors_total", "Failed/rejected Shadowsocks handshakes.", float64(s.HandshakeErrors), nil)
		mw.counter("router_billing_shadowsocks_dial_errors_total", "Failed target dials.", float64(s.DialErrors), nil)
		mw.counter("router_billing_shadowsocks_replay_rejected_total", "Connections rejected for salt replay.", float64(s.ReplayRejected), nil)
		mw.counter("router_billing_shadowsocks_blocked_by_acl_total", "Connections rejected by allowed_cidrs.", float64(s.BlockedByACL), nil)
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

type metricWriter struct {
	w        http.ResponseWriter
	declared map[string]bool
}

func (m *metricWriter) gauge(name, help string, v float64, labels map[string]string) {
	m.emit("gauge", name, help, v, labels)
}

// counter emits a Prometheus counter (monotonic). Same wire shape as gauge
// but with TYPE counter so scrapers apply rate() correctly.
func (m *metricWriter) counter(name, help string, v float64, labels map[string]string) {
	m.emit("counter", name, help, v, labels)
}

func (m *metricWriter) emit(typ, name, help string, v float64, labels map[string]string) {
	if m.declared == nil {
		m.declared = map[string]bool{}
	}
	if !m.declared[name] {
		if help != "" {
			fmt.Fprintf(m.w, "# HELP %s %s\n", name, help)
		}
		fmt.Fprintf(m.w, "# TYPE %s %s\n", name, typ)
		m.declared[name] = true
	}
	if len(labels) == 0 {
		fmt.Fprintf(m.w, "%s %g\n", name, v)
		return
	}
	fmt.Fprintf(m.w, "%s{", name)
	first := true
	for k, val := range labels {
		if !first {
			fmt.Fprintf(m.w, ",")
		}
		fmt.Fprintf(m.w, `%s="%s"`, k, val)
		first = false
	}
	fmt.Fprintf(m.w, "} %g\n", v)
}
