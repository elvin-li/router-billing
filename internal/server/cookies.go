package server

import (
	"net/http"
	"strings"
)

// isHTTPS returns true if the request reached the server over TLS, or via a
// reverse proxy that forwarded X-Forwarded-Proto: https.
//
// We never bind TLS in-process (cgo-free static binary on a tiny ARM router
// means we'd rather leave that to a reverse proxy). When the admin DOES put
// nginx/Caddy in front, we want all cookies marked Secure so they're never
// sent on the http:// fallback.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}
