package server

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"router-billing/internal/totp"
)

// per-pending-token counter so a brute force on the 6-digit space can't burn
// down the 5-minute pending session. After 5 wrong codes we invalidate.
var twoFAAttempts = struct {
	sync.Mutex
	m map[string]int
}{m: map[string]int{}}

func twoFANextAttempt(token string) int {
	twoFAAttempts.Lock()
	defer twoFAAttempts.Unlock()
	twoFAAttempts.m[token]++
	return twoFAAttempts.m[token]
}

func twoFAReset(token string) {
	twoFAAttempts.Lock()
	defer twoFAAttempts.Unlock()
	delete(twoFAAttempts.m, token)
}

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
			"Error":    "",
			"Username": username,
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
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
		a.DB.Audit(r.Context(), "admin-attempt:"+username, "2fa_locked", "", "attempts>5 ip="+a.clientIP(r))
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

	if !totp.Verify(admin.TOTPSecret, code, time.Now()) {
		a.DB.Audit(r.Context(), "admin-attempt:"+username, "2fa_failed", "", "ip="+a.clientIP(r))
		a.render(w, "admin_2fa.html", map[string]any{
			"Error":    "验证码错误，请再试一次",
			"Username": username,
		})
		return
	}

	// Code is good. Swap pending → real session.
	if err := a.DB.DeleteSession(r.Context(), c.Value); err != nil {
		log.Printf("delete pending session: %v", err)
	}
	twoFAReset(c.Value)
	a.DB.Audit(r.Context(), "admin:"+username, "2fa_ok", "", "ip="+a.clientIP(r))
	a.issueAdminSession(w, r, username)
}
