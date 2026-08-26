package server

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"time"
)

// /metrics — Prometheus text exposition. Optionally protected by
// `metrics_token` in config; if unset, the endpoint is open.
func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if tok := a.Cfg.MetricsToken; tok != "" {
		// Constant-time compare, same as the API-token path — a plain
		// string == lets a remote caller confirm the token byte-by-byte.
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+tok)) != 1 {
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
	if m.declared == nil {
		m.declared = map[string]bool{}
	}
	if !m.declared[name] {
		if help != "" {
			fmt.Fprintf(m.w, "# HELP %s %s\n", name, help)
		}
		fmt.Fprintf(m.w, "# TYPE %s gauge\n", name)
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
