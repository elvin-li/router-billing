package server

import (
	"context"
	"crypto/subtle"
	"net/http"
)

// CSRF — double-submit cookie pattern. SameSite=Lax on our session cookies
// already blocks most cross-site POSTs, but this is belt-and-suspenders.
//
//   - Every response includes an `rb_csrf` cookie (set on first request).
//   - Templates inject the cookie value via the {{csrf .}} helper
//     (reads from request context).
//   - Authed POST handlers reject when the form value (or X-CSRF-Token
//     header) doesn't match the cookie.
//
// Skipped paths: /notify/* (signed by upstream), /metrics, /redeem,
// /user/login, /user/register, /admin/login — for those the cookie still
// gets set so subsequent authed pages have one.
const csrfCookieName = "rb_csrf"

type ctxKey int

const csrfCtxKey ctxKey = 1

// csrfMiddleware ensures every request has an rb_csrf cookie and exposes its
// value via context for the template helper.
func csrfMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie(csrfCookieName); err == nil && len(c.Value) >= 32 {
			token = c.Value
		} else {
			token = randomToken(32)
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: false, // template helper reads it client-side (defense-in-depth, not a session secret)
				Secure:   isHTTPS(r),
				SameSite: http.SameSiteLaxMode,
				MaxAge:   30 * 24 * 3600,
			})
		}
		ctx := context.WithValue(r.Context(), csrfCtxKey, token)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// csrfFromContext reads the token planted by the middleware.
func csrfFromContext(ctx context.Context) string {
	v, _ := ctx.Value(csrfCtxKey).(string)
	return v
}

// verifyCSRF returns true if a POST request carries a matching csrf token in
// either the `_csrf` form value or the `X-CSRF-Token` header.
//
// Non-POST requests are always allowed.
func verifyCSRF(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	c, err := r.Cookie(csrfCookieName)
	if err != nil || len(c.Value) < 32 {
		return false
	}
	tok := r.FormValue("_csrf")
	if tok == "" {
		tok = r.Header.Get("X-CSRF-Token")
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(c.Value)) == 1
}
