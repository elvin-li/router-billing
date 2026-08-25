package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"router-billing/internal/config"
)

// securityHeaders sets a conservative set of headers on every response.
//
// CSP is intentionally permissive on 'unsafe-inline' for styles because some
// templates use inline style="..." attributes for tiny tweaks. Scripts are
// strictly self-only.
//
// HSTS only fires on TLS-detected requests (TLS != nil OR
// X-Forwarded-Proto: https). Max-age + preload/includeSubDomains directives
// come from config.Security — defaults are safe (1-year max-age, no preload,
// no subdomain coverage) so a fresh deploy doesn't accidentally pin itself.
func (a *App) securityHeaders(h http.Handler) http.Handler {
	hsts := buildHSTSHeader(a.Cfg.Security)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "interest-cohort=()")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"img-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'self'; "+
				"base-uri 'self'")
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set("Strict-Transport-Security", hsts)
		}
		h.ServeHTTP(w, r)
	})
}

// realIPCtxKey carries the resolved client IP planted by realIPMiddleware.
// clientIP (user.go) reads it back.
const realIPCtxKey ctxKey = 2

// realIPMiddleware resolves the client IP once per request and stores it in
// the request context for clientIP().
//
// X-Forwarded-For is only believed when the direct peer (RemoteAddr) is one
// of config.security.trusted_proxies — the header is plain client input
// otherwise, and honoring it let anyone rotate a made-up address per request
// to sidestep every per-IP rate limiter (login, register, forgot-password)
// and forge the ip=... recorded in audit rows. When trusted, we take the
// LAST valid entry: an appending proxy puts the real peer address at the
// end, while any leading entries arrived from the client and stay untrusted.
func (a *App) realIPMiddleware(h http.Handler) http.Handler {
	nets := parseTrustedProxies(a.Cfg.Security.TrustedProxies)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := remoteHost(r)
		if fromTrustedProxy(ip, nets) {
			if fwd := lastForwardedFor(r.Header.Get("X-Forwarded-For")); fwd != "" {
				ip = fwd
			}
		}
		ctx := context.WithValue(r.Context(), realIPCtxKey, ip)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// remoteHost strips the port off RemoteAddr, tolerating port-less values.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// parseTrustedProxies turns the config strings into networks. Bare IPs
// become single-address networks; malformed entries are logged and skipped
// (never silently widened).
func parseTrustedProxies(entries []string) []*net.IPNet {
	var out []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			out = append(out, n)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		log.Printf("security.trusted_proxies: ignoring unparseable entry %q", e)
	}
	return out
}

func fromTrustedProxy(host string, nets []*net.IPNet) bool {
	if len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// lastForwardedFor returns the last entry of an X-Forwarded-For list that
// parses as an IP, or "" when none does.
func lastForwardedFor(header string) string {
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		v := strings.TrimSpace(parts[i])
		if v != "" && net.ParseIP(v) != nil {
			return v
		}
	}
	return ""
}

// buildHSTSHeader composes the Strict-Transport-Security header value from
// the config. Pure function so it's trivially testable.
func buildHSTSHeader(s config.Security) string {
	maxAge := s.HSTSMaxAgeSeconds
	if maxAge <= 0 {
		maxAge = 31536000 // 1 year default
	}
	out := fmt.Sprintf("max-age=%d", maxAge)
	if s.HSTSIncludeSubdomains {
		out += "; includeSubDomains"
	}
	if s.HSTSPreload {
		out += "; preload"
	}
	return out
}
