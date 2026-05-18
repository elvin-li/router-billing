package server

import (
	"fmt"
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
