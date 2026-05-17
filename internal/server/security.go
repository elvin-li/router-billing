package server

import (
	"net/http"
	"strings"
)

// securityHeaders sets a conservative set of headers on every response.
//
// CSP is intentionally permissive on 'unsafe-inline' for styles because some
// templates use inline style="..." attributes for tiny tweaks. Scripts are
// strictly self-only.
func securityHeaders(h http.Handler) http.Handler {
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
		// Only set HSTS if the request actually came over TLS (so we don't
		// burn a header on an HTTP-only deploy that can't honor it).
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}
