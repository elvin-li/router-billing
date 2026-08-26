package server

import (
	"time"
)

// One-time server-side flash values.
//
// Some admin flows need to show a secret exactly once after a POST-redirect
// (e.g. the temporary password from /admin/users/reset-password). Putting
// the secret in the redirect's query string leaks it into browser history,
// any intermediary access logs, and screenshots of the URL bar. Instead the
// handler stashes the value here and redirects with an opaque one-shot
// token; the next page render pops (and deletes) it.
//
// Entries expire after flashTTL so an unconsumed token (admin closed the
// tab mid-redirect) doesn't keep the secret in memory forever. The store
// is in-process only — a restart drops pending flashes, which is fine:
// the admin just re-runs the reset.

const flashTTL = 2 * time.Minute

type flashEntry struct {
	value   string
	expires time.Time
}

// stashFlash stores value and returns the opaque one-shot token to embed
// in the redirect URL. Also sweeps expired entries so the map can't grow
// unbounded under pathological use.
func (a *App) stashFlash(value string) string {
	token := randomToken(16)
	now := time.Now()
	a.flashMu.Lock()
	defer a.flashMu.Unlock()
	for k, e := range a.flashes {
		if e.expires.Before(now) {
			delete(a.flashes, k)
		}
	}
	a.flashes[token] = flashEntry{value: value, expires: now.Add(flashTTL)}
	return token
}

// popFlash consumes the token: returns the stored value and deletes it.
// Unknown or expired tokens return "".
func (a *App) popFlash(token string) string {
	if token == "" {
		return ""
	}
	a.flashMu.Lock()
	defer a.flashMu.Unlock()
	e, ok := a.flashes[token]
	if !ok {
		return ""
	}
	delete(a.flashes, token)
	if e.expires.Before(time.Now()) {
		return ""
	}
	return e.value
}
