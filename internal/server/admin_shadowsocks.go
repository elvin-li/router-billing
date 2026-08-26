package server

import (
	"bytes"
	"image/png"
	"net/http"

	"rsc.io/qr"

	"router-billing/internal/shadowsocks"
)

// GET /admin/shadowsocks — status + share link/QR for the built-in proxy.
//
// The ss:// link embeds the password, so it is masked by default and only
// rendered (plus the matching QR) when the admin explicitly clicks reveal
// (?reveal=1). Each reveal writes an audit row — viewing a credential is a
// security-relevant action worth a trail. The password never appears in any
// URL or server log (logMiddleware logs only the request path).
func (a *App) handleAdminShadowsocks(w http.ResponseWriter, r *http.Request) {
	ss := a.Cfg.Shadowsocks
	reveal := r.URL.Query().Get("reveal") == "1" && ss.Enabled && ss.Password != ""

	host := ss.AdvertiseHostOr(a.Cfg.PortalHost)
	if host == "" {
		host = "192.168.5.1"
	}

	data := map[string]any{
		"Enabled":       ss.Enabled,
		"Listen":        ss.Listen,
		"Method":        ss.Method,
		"Host":          host,
		"Port":          ss.ListenPort(),
		"Tag":           ss.TagOr(),
		"AllowedCIDRs":  ss.AllowedCIDRs,
		"FirewallIface": ss.FirewallIface,
		"OpenFirewall":  ss.OpenFirewall,
		"Reveal":        reveal,
		"Methods":       shadowsocks.SupportedMethods(),
		"HasPassword":   ss.Password != "",
	}

	if reveal {
		uri, err := shadowsocks.ShareURI(ss.Method, ss.Password, host, ss.ListenPort(), ss.TagOr())
		if err == nil {
			data["URI"] = uri
		}
		a.DB.Audit(r.Context(), a.adminActor(r), "shadowsocks_uri_view", "", "ip="+clientIP(r))
	}

	if a.SSMetrics != nil {
		snap := a.SSMetrics.Snapshot()
		data["Metrics"] = map[string]any{
			"ConnectionsTotal": snap.ConnectionsTotal,
			"ActiveConns":      snap.ActiveConns,
			"BytesIn":          snap.BytesIn,
			"BytesOut":         snap.BytesOut,
			"HandshakeErrors":  snap.HandshakeErrors,
			"DialErrors":       snap.DialErrors,
			"ReplayRejected":   snap.ReplayRejected,
			"BlockedByACL":     snap.BlockedByACL,
		}
	}

	a.render(w, "admin_shadowsocks.html", a.adminCtx(r, "shadowsocks", data))
}

// GET /admin/shadowsocks/qr — PNG QR of the ss:// share link. Built entirely
// server-side from config so the password is never carried in a query string
// or the access log. Admin-only (behind requireAdmin).
func (a *App) handleAdminShadowsocksQR(w http.ResponseWriter, r *http.Request) {
	ss := a.Cfg.Shadowsocks
	if !ss.Enabled || ss.Password == "" {
		http.Error(w, "shadowsocks not enabled", http.StatusNotFound)
		return
	}
	host := ss.AdvertiseHostOr(a.Cfg.PortalHost)
	if host == "" {
		host = "192.168.5.1"
	}
	uri, err := shadowsocks.ShareURI(ss.Method, ss.Password, host, ss.ListenPort(), ss.TagOr())
	if err != nil {
		http.Error(w, "uri: "+err.Error(), http.StatusInternalServerError)
		return
	}
	code, err := qr.Encode(uri, qr.M)
	if err != nil {
		http.Error(w, "qr: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, code.Image()); err != nil {
		http.Error(w, "png: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// The QR encodes a secret — never let a shared cache store it.
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, private")
	_, _ = w.Write(buf.Bytes())
}

// adminActor derives an "admin:<username>" actor string from the caller's
// session cookie, falling back to "admin" when the subject can't be resolved.
// Mirrors the inline pattern used elsewhere (admin_extra.go).
func (a *App) adminActor(r *http.Request) string {
	if c, err := r.Cookie(adminCookieName); err == nil {
		if sess, _ := a.DB.GetSession(r.Context(), c.Value); sess != nil && sess.Subject != "" {
			return "admin:" + sess.Subject
		}
	}
	return "admin"
}
