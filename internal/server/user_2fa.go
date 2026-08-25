package server

import (
	"bytes"
	"image/png"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"rsc.io/qr"

	"router-billing/internal/totp"
)

// User-side 2FA (TOTP — RFC 6238). Mirrors the admin flow in admin_2fa.go
// with the same attempt-cap-per-pending-token guard, but keyed off a
// separate cookie (`rb_user_pending`) so a logged-in admin browsing the
// same machine can't accidentally have their pending session crossed.
//
// Routes:
//
//	GET  /user/login/2fa            -> show 6-digit input (only valid with rb_user_pending)
//	POST /user/login/2fa            -> verify; on success swap to real session
//	GET  /user/2fa                  -> settings page: enroll / disable
//	POST /user/2fa/begin            -> generate pending secret, render QR
//	POST /user/2fa/confirm          -> verify pending code, promote to live
//	POST /user/2fa/disable          -> require current code + password, wipe
//	GET  /user/2fa/qr               -> PNG of otpauth:// URL for the pending or live secret
//
// All POST routes are CSRF-checked. /user/login/2fa is NOT behind
// requireUser (the user isn't fully logged in yet) but verifies CSRF
// explicitly. /user/2fa* are behind requireUser → CSRF runs in the
// middleware.
const userPendingSessionKind = "user_pending_2fa"

// userTwoFAAttempts mirrors twoFAAttempts in admin_2fa.go but separately
// keyed so user attempts don't share a counter with admin attempts.
var userTwoFAAttempts = struct {
	sync.Mutex
	m map[string]int
}{m: map[string]int{}}

func userTwoFANextAttempt(token string) int {
	userTwoFAAttempts.Lock()
	defer userTwoFAAttempts.Unlock()
	userTwoFAAttempts.m[token]++
	return userTwoFAAttempts.m[token]
}

func userTwoFAReset(token string) {
	userTwoFAAttempts.Lock()
	defer userTwoFAAttempts.Unlock()
	delete(userTwoFAAttempts.m, token)
}

// GET / POST /user/login/2fa
func (a *App) handleUserLogin2FA(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(userPendingCookie)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/user/login?err=2fa_expired", http.StatusSeeOther)
		return
	}
	sess, err := a.DB.GetSession(r.Context(), c.Value)
	if err != nil || sess == nil || sess.Kind != userPendingSessionKind || sess.UserID == nil {
		http.Redirect(w, r, "/user/login?err=2fa_expired", http.StatusSeeOther)
		return
	}
	user, err := a.DB.GetUser(r.Context(), *sess.UserID)
	if err != nil || user == nil || user.TOTPSecret == "" || user.Suspended {
		http.Redirect(w, r, "/user/login?err=2fa_expired", http.StatusSeeOther)
		return
	}
	// v0.99: the raw query value was previously trusted as-is — a crafted
	// login link could bounce a just-authenticated user to an external
	// phishing domain. Same-site relative paths only.
	next := safeNextPath(r.URL.Query().Get("next"), "/user/me")

	if r.Method == http.MethodGet {
		a.render(w, "user_2fa_login.html", a.userCtx(r, "2fa", map[string]any{
			"Phone": user.Phone,
			"Next":  next,
		}))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
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
	if n := userTwoFANextAttempt(c.Value); n > 5 {
		_ = a.DB.DeleteSession(r.Context(), c.Value)
		userTwoFAReset(c.Value)
		a.DB.Audit(r.Context(), "user-attempt:"+user.Phone, "2fa_locked", "", "attempts>5 ip="+clientIP(r))
		http.Redirect(w, r, "/user/login?err=2fa_locked", http.StatusSeeOther)
		return
	}

	raw := r.PostForm.Get("code")
	totpCode := extractDigits(raw)
	via := "totp"
	ok := totp.Verify(user.TOTPSecret, totpCode, time.Now())
	if !ok && looksLikeBackupCode(raw) {
		// Fallback path: the user lost their authenticator but kept the
		// backup codes printout. Each code is single-use.
		used, err := a.verifyAndConsumeBackupCode(r.Context(), *sess.UserID, raw)
		if err != nil {
			log.Printf("backup-code verify %d: %v", *sess.UserID, err)
		}
		if used {
			ok = true
			via = "backup_code"
		}
	}
	if !ok {
		a.DB.Audit(r.Context(), "user-attempt:"+user.Phone, "2fa_failed", "", "ip="+clientIP(r))
		a.render(w, "user_2fa_login.html", a.userCtx(r, "2fa", map[string]any{
			"Phone": user.Phone,
			"Next":  next,
			"Err":   "验证码错误，请再试一次",
		}))
		return
	}

	// 2FA accepted — swap pending session for the real one.
	if err := a.DB.DeleteSession(r.Context(), c.Value); err != nil {
		log.Printf("delete user pending session: %v", err)
	}
	userTwoFAReset(c.Value)
	// Wipe the pending cookie now that it's consumed.
	http.SetCookie(w, &http.Cookie{
		Name: userPendingCookie, Value: "", Path: "/user", MaxAge: -1, HttpOnly: true,
	})

	// "trust this device" checkbox — opt-in 30-day bypass of the 2FA gate
	// on this browser. Stored row carries a User-Agent hint so /user/2fa
	// can render a useful device list.
	if r.PostForm.Get("trust_device") == "1" {
		if err := a.issueTrustedDeviceCookie(w, r, user.ID); err != nil {
			log.Printf("issue trusted device for %d: %v", user.ID, err)
			// Non-fatal — proceed with login.
		} else {
			a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_trusted_device_issued", "", "ip="+clientIP(r))
		}
	}

	a.startUserSession(w, r, user)
	a.DB.Audit(r.Context(), "user:"+user.Phone, "login", "", "via="+via+" ip="+clientIP(r))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// GET /user/2fa — settings page. Shows enrollment state and, if a pending
// secret exists, the QR + confirmation form.
func (a *App) handleUser2FA(w http.ResponseWriter, r *http.Request) {
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	var backupTotal, backupRemaining int
	type deviceView struct {
		ID         int64
		Label      string
		LastSeen   string
		CreatedAt  string
		ExpiresAt  string
		IsCurrent  bool
		IsExpired  bool
		ExpiresInD int
	}
	var devices []deviceView
	currentToken := ""
	if c, err := r.Cookie(userTrustedCookie); err == nil {
		currentToken = c.Value
	}
	if user.TOTPSecret != "" {
		codes, _ := a.DB.ListBackupCodes(r.Context(), uid)
		backupTotal = len(codes)
		for _, c := range codes {
			if c.UsedAt == nil {
				backupRemaining++
			}
		}
		rows, _ := a.DB.ListTrustedDevices(r.Context(), uid)
		now := time.Now().UTC()
		for _, d := range rows {
			dv := deviceView{
				ID:         d.ID,
				Label:      d.Label,
				LastSeen:   formatRelativeTime(d.LastSeen),
				CreatedAt:  d.CreatedAt.Format("2006-01-02"),
				ExpiresAt:  d.ExpiresAt.Format("2006-01-02"),
				IsCurrent:  currentToken != "" && d.Token == currentToken,
				IsExpired:  d.ExpiresAt.Before(now),
				ExpiresInD: int(time.Until(d.ExpiresAt).Hours() / 24),
			}
			devices = append(devices, dv)
		}
	}
	a.render(w, "user_2fa.html", a.userCtx(r, "2fa", map[string]any{
		"User":            user,
		"Enabled":         user.TOTPSecret != "",
		"HasPending":      user.TOTPPending != "",
		"PendingSecret":   user.TOTPPending,
		"PendingPretty":   prettySecret(user.TOTPPending),
		"OTPAuthURL":      "/user/2fa/qr",
		"BackupTotal":     backupTotal,
		"BackupRemaining": backupRemaining,
		"BackupLow":       backupRemaining > 0 && backupRemaining <= 3,
		"BackupEmpty":     user.TOTPSecret != "" && backupRemaining == 0,
		"TrustedDevices":  devices,
		"HasDevices":      len(devices) > 0,
	}))
}

// POST /user/2fa/begin — generate a fresh pending secret.
func (a *App) handleUser2FABegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/2fa", http.StatusSeeOther)
		return
	}
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	if user.TOTPSecret != "" {
		http.Redirect(w, r, "/user/2fa?err=2fa_already_on", http.StatusSeeOther)
		return
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		http.Redirect(w, r, "/user/2fa?err=internal", http.StatusSeeOther)
		return
	}
	if err := a.DB.SetUserTOTPPending(r.Context(), uid, secret); err != nil {
		log.Printf("set user totp pending %d: %v", uid, err)
		http.Redirect(w, r, "/user/2fa?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_enroll_begin", "", "ip="+clientIP(r))
	http.Redirect(w, r, "/user/2fa", http.StatusSeeOther)
}

// POST /user/2fa/confirm — verify pending code, promote.
func (a *App) handleUser2FAConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/2fa", http.StatusSeeOther)
		return
	}
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	if user.TOTPPending == "" {
		http.Redirect(w, r, "/user/2fa?err=2fa_not_enrolled", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	code := extractDigits(r.PostForm.Get("code"))
	if !totp.Verify(user.TOTPPending, code, time.Now()) {
		a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_enroll_failed", "", "ip="+clientIP(r))
		http.Redirect(w, r, "/user/2fa?err=2fa_failed", http.StatusSeeOther)
		return
	}
	if err := a.DB.ConfirmUserTOTP(r.Context(), uid); err != nil {
		log.Printf("confirm user totp %d: %v", uid, err)
		http.Redirect(w, r, "/user/2fa?err=internal", http.StatusSeeOther)
		return
	}
	// Re-load so the rendered "Codes" page shows the now-enabled state.
	user, _ = a.DB.GetUser(r.Context(), uid)
	a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_enrolled", "", "ip="+clientIP(r))

	// Generate + display backup codes — last chance to save them before
	// they're hashed-and-forgotten. If generation fails we still leave 2FA
	// on (it's already confirmed in the DB); the user can hit
	// /user/2fa/regenerate-codes manually.
	codes, err := a.generateAndStoreBackupCodes(r.Context(), uid)
	if err != nil {
		log.Printf("backup codes after enrollment %d: %v", uid, err)
		http.Redirect(w, r, "/user/2fa?ok=2fa_enabled&err=backup_codes_failed", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_backup_codes_issued", "", "count=10 ip="+clientIP(r))
	a.renderBackupCodesOnce(w, r, user, codes)
}

// POST /user/2fa/disable — require current password + current TOTP, then wipe.
//
// Rationale: just-password lets a stolen-cookie attacker turn 2FA off (their
// session is already logged in). Just-TOTP defeats lost-phone recovery (the
// user can't disable). Both together is the standard pattern.
func (a *App) handleUser2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/2fa", http.StatusSeeOther)
		return
	}
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	if user.TOTPSecret == "" {
		http.Redirect(w, r, "/user/2fa?err=2fa_not_enrolled", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	pwd := r.PostForm.Get("password")
	code := extractDigits(r.PostForm.Get("code"))
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(pwd)) != nil {
		a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_disable_failed", "", "reason=bad_password ip="+clientIP(r))
		http.Redirect(w, r, "/user/2fa?err=bad_credentials", http.StatusSeeOther)
		return
	}
	if !totp.Verify(user.TOTPSecret, code, time.Now()) {
		a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_disable_failed", "", "reason=bad_code ip="+clientIP(r))
		http.Redirect(w, r, "/user/2fa?err=2fa_failed", http.StatusSeeOther)
		return
	}
	if err := a.DB.ClearUserTOTP(r.Context(), uid); err != nil {
		log.Printf("clear user totp %d: %v", uid, err)
		http.Redirect(w, r, "/user/2fa?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_disabled", "", "ip="+clientIP(r))
	http.Redirect(w, r, "/user/2fa?ok=2fa_disabled", http.StatusSeeOther)
}

// GET /user/2fa/qr — returns a 256x256 PNG QR for the pending (or live) secret.
//
// We prefer the pending secret if both exist — the only realistic case is "I
// clicked enable again before confirming" and that branch must show the new
// secret, not the old one.
func (a *App) handleUser2FAQR(w http.ResponseWriter, r *http.Request) {
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Error(w, "auth", http.StatusUnauthorized)
		return
	}
	secret := user.TOTPPending
	if secret == "" {
		secret = user.TOTPSecret
	}
	if secret == "" {
		http.Error(w, "no secret", http.StatusNotFound)
		return
	}
	uri := totp.ProvisioningURI(secret, user.Phone, "router-billing")
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
	w.Header().Set("Content-Type", "image/png")
	// Never cache the QR — the secret may change on re-enrollment.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// --- helpers ---

// extractDigits drops everything that isn't [0-9] so paste-friendly UX works
// with codes copied as "123 456" or "123-456".
func extractDigits(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// prettySecret formats a 32-char base32 secret into 4-char groups for
// readability when the user wants to type it instead of scan.
func prettySecret(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if s == "" {
		return ""
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}
