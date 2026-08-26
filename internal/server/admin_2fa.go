package server

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"router-billing/internal/totp"
)

// attemptTracker counts wrong-code attempts per pending-2FA token so a
// brute force on the 6-digit space can't burn down the 5-minute pending
// session. After 5 wrong codes the caller invalidates the token.
//
// Entries used to be deleted only on success or lockout — a pending login
// that was simply abandoned (tab closed, session TTL expired) leaked its
// entry forever, so the map grew without bound over a router's months of
// uptime. Entries now carry their first-attempt time and anything older
// than the tracker TTL is swept once the map is non-trivially sized.
type attemptTracker struct {
	mu  sync.Mutex
	m   map[string]attemptEntry
	ttl time.Duration
}

type attemptEntry struct {
	n     int
	first time.Time
}

// twoFAAttemptTTL comfortably outlives the 5-minute pending-session TTL —
// once the session row is gone the counter is dead weight either way.
const twoFAAttemptTTL = 15 * time.Minute

// attemptSweepThreshold keeps the O(n) sweep away from the common case of
// a handful of live logins; above it, stale entries are purged on insert.
const attemptSweepThreshold = 128

func newAttemptTracker(ttl time.Duration) *attemptTracker {
	return &attemptTracker{m: map[string]attemptEntry{}, ttl: ttl}
}

// next increments and returns the attempt count for token.
func (t *attemptTracker) next(token string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if len(t.m) > attemptSweepThreshold {
		for k, e := range t.m {
			if now.Sub(e.first) > t.ttl {
				delete(t.m, k)
			}
		}
	}
	e := t.m[token]
	if e.n == 0 {
		e.first = now
	}
	e.n++
	t.m[token] = e
	return e.n
}

func (t *attemptTracker) reset(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, token)
}

func (t *attemptTracker) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

var twoFAAttempts = newAttemptTracker(twoFAAttemptTTL)

func twoFANextAttempt(token string) int { return twoFAAttempts.next(token) }

func twoFAReset(token string) { twoFAAttempts.reset(token) }

// GET /admin/login/2fa  — render the 6-digit input form, gated by an
// rb_admin_pending cookie.
// POST /admin/login/2fa — verify code; on success swap to a real admin session.
func (a *App) handleAdminLogin2FA(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(adminPendingCookie)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/admin/login?err=2fa_expired", http.StatusSeeOther)
		return
	}
	sess, err := a.DB.GetSession(r.Context(), c.Value)
	if err != nil || sess == nil || sess.Kind != "pending_2fa" {
		http.Redirect(w, r, "/admin/login?err=2fa_expired", http.StatusSeeOther)
		return
	}
	username := sess.Subject

	if r.Method == http.MethodGet {
		a.render(w, "admin_2fa.html", map[string]any{
			"Error":     "",
			"Username":  username,
			"CSRFToken": csrfFromContext(r.Context()),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	// The user-side 2FA verify checks CSRF; this one historically didn't —
	// a cross-site form could burn the 5-attempt budget and lock the admin
	// out of their pending login. Checked before the attempt counter so a
	// missing token never consumes an attempt.
	if !verifyCSRF(r) {
		http.Error(w, "CSRF token invalid — please refresh the page and retry", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}

	// Cap attempts per pending token so the 6-digit space can't be brute-forced
	// inside the 5-minute window.
	if n := twoFANextAttempt(c.Value); n > 5 {
		_ = a.DB.DeleteSession(r.Context(), c.Value)
		twoFAReset(c.Value)
		a.DB.Audit(r.Context(), "admin-attempt:"+username, "2fa_locked", "", "attempts>5 ip="+clientIP(r))
		http.Redirect(w, r, "/admin/login?err=2fa_locked", http.StatusSeeOther)
		return
	}

	admin := a.Cfg.LookupAdmin(username)
	if admin == nil || admin.TOTPSecret == "" {
		// Shouldn't happen (handleAdminLogin only sets pending if TOTPSecret).
		http.Redirect(w, r, "/admin/login?err=2fa_misconfigured", http.StatusSeeOther)
		return
	}

	code := strings.TrimSpace(r.PostForm.Get("code"))
	// Drop everything that isn't a digit so paste-friendly UX works.
	code = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, code)

	step, codeOK := totp.MatchingStep(admin.TOTPSecret, code, time.Now())
	// One-time use (RFC 6238 §5.2): a code that already completed a login
	// can't be replayed for a second session inside its validity window.
	if codeOK && !totpConsumeStep(admin.TOTPSecret, step) {
		codeOK = false
	}
	if !codeOK {
		a.DB.Audit(r.Context(), "admin-attempt:"+username, "2fa_failed", "", "ip="+clientIP(r))
		a.render(w, "admin_2fa.html", map[string]any{
			"Error":     "验证码错误，请再试一次",
			"Username":  username,
			"CSRFToken": csrfFromContext(r.Context()),
		})
		return
	}

	// Code is good. Swap pending → real session.
	if err := a.DB.DeleteSession(r.Context(), c.Value); err != nil {
		log.Printf("delete pending session: %v", err)
	}
	twoFAReset(c.Value)
	a.DB.Audit(r.Context(), "admin:"+username, "2fa_ok", "", "ip="+clientIP(r))
	a.issueAdminSession(w, r, username)
}
