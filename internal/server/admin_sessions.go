package server

import (
	"log"
	"net/http"
	"strings"
)

// GET /admin/sessions — list all live sessions (admin + user) and let admin
// revoke individual ones or all-other-admin in one click ("I lost my laptop").
func (a *App) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	list, err := a.DB.ListActiveSessions(r.Context(), 500)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	// Mark which row matches the requesting browser's cookie.
	myTok := ""
	if c, err := r.Cookie(adminCookieName); err == nil {
		myTok = c.Value
	}
	for i := range list {
		if list[i].Token == myTok {
			list[i].IsCurrent = true
		}
	}
	a.render(w, "admin_sessions.html", a.adminCtx(r, "sessions", map[string]any{
		"Sessions": list,
		"MyToken":  myTok,
		"AdminTTL": int(a.Cfg.Security.AdminSessionTTL().Hours()),
		"UserTTL":  int(a.Cfg.Security.UserSessionTTL().Hours() / 24),
	}))
}

// POST /admin/sessions/revoke  {token}
func (a *App) handleAdminSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/sessions", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	tok := strings.TrimSpace(r.PostForm.Get("token"))
	if tok == "" {
		http.Redirect(w, r, "/admin/sessions?err=invalid", http.StatusSeeOther)
		return
	}
	if err := a.DB.DeleteSession(r.Context(), tok); err != nil {
		log.Printf("revoke session: %v", err)
		http.Redirect(w, r, "/admin/sessions?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "session_revoke", maskTok(tok), "ip="+clientIP(r))
	http.Redirect(w, r, "/admin/sessions?ok=1", http.StatusSeeOther)
}

// POST /admin/sessions/panic — emergency response: signs out every admin
// session except the requesting one AND every user session everywhere.
// Use after a confirmed breach. Each user has to re-authenticate (with
// 2FA if enrolled). The calling admin keeps working uninterrupted.
//
// Audited as "panic_logout" with the killed-counts in the detail so the
// reviewing team can see "we kicked 47 user sessions and 3 admin sessions
// at 2026-05-19 14:32".
func (a *App) handleAdminSessionPanic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/sessions", http.StatusSeeOther)
		return
	}
	keep := ""
	if c, err := r.Cookie(adminCookieName); err == nil {
		keep = c.Value
	}
	if keep == "" {
		http.Redirect(w, r, "/admin/sessions?err=internal", http.StatusSeeOther)
		return
	}
	adminKilled, err := a.DB.DeleteAllAdminSessionsExcept(r.Context(), keep)
	if err != nil {
		log.Printf("panic admin: %v", err)
		http.Redirect(w, r, "/admin/sessions?err=internal", http.StatusSeeOther)
		return
	}
	userKilled, err := a.DB.DeleteAllUserSessions(r.Context())
	if err != nil {
		log.Printf("panic users: %v", err)
		http.Redirect(w, r, "/admin/sessions?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "panic_logout", "",
		"admin_killed="+mustItoa(adminKilled)+" user_killed="+mustItoa(userKilled)+" ip="+clientIP(r))
	http.Redirect(w, r, "/admin/sessions?ok=panic", http.StatusSeeOther)
}

// POST /admin/sessions/revoke-all-admin — kills every admin session except
// the requesting one. The classic "I lost my laptop" panic button.
func (a *App) handleAdminSessionRevokeAllAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/sessions", http.StatusSeeOther)
		return
	}
	keep := ""
	if c, err := r.Cookie(adminCookieName); err == nil {
		keep = c.Value
	}
	if keep == "" {
		// Shouldn't happen — requireAdmin already validated the session.
		http.Redirect(w, r, "/admin/sessions?err=internal", http.StatusSeeOther)
		return
	}
	n, err := a.DB.DeleteAllAdminSessionsExcept(r.Context(), keep)
	if err != nil {
		log.Printf("revoke-all-admin: %v", err)
		http.Redirect(w, r, "/admin/sessions?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "session_revoke_all_admin", "",
		mustItoa(n)+" sessions killed; ip="+clientIP(r))
	http.Redirect(w, r, "/admin/sessions?ok=1", http.StatusSeeOther)
}

// maskTok shows just the first/last 4 chars of a 64-char token so the audit
// log is useful but doesn't leak the full secret.
func maskTok(t string) string {
	if len(t) < 12 {
		return "***"
	}
	return t[:4] + "..." + t[len(t)-4:]
}

func mustItoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
