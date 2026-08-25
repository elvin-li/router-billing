package server

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Trusted-device (a.k.a. "remember this browser") flow:
//
// At successful /user/login/2fa, if the form field `trust_device=1` is
// present we generate a fresh 32-byte random token, persist a row in
// user_trusted_devices with a 30-day TTL, and set the `rb_user_trusted`
// cookie carrying the token. On subsequent /user/login the password-only
// path checks for the cookie; on hit (non-expired row belonging to the
// authenticated user) we skip the 2FA challenge entirely.
//
// Crucially, the trust cookie alone never authenticates — it only acts as
// a second-factor bypass AFTER the password is verified. So a stolen
// cookie still needs the password to be useful.

// labelFromUserAgent extracts a short readable label from the request's
// User-Agent — enough to disambiguate "Chrome on my laptop" from "Safari
// on the iPhone" but not a full fingerprint. Capped at 80 chars.
func labelFromUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "(unknown browser)"
	}
	if len(ua) > 80 {
		ua = ua[:80] + "…"
	}
	return ua
}

// consumeTrustedDeviceCookie returns true iff the request carries a valid
// trust cookie for `userID`. On a stale-but-present cookie we wipe it.
func (a *App) consumeTrustedDeviceCookie(w http.ResponseWriter, r *http.Request, userID int64) bool {
	c, err := r.Cookie(userTrustedCookie)
	if err != nil || c.Value == "" {
		return false
	}
	dev, err := a.DB.GetTrustedDevice(r.Context(), c.Value)
	if err != nil {
		log.Printf("trusted-device lookup: %v", err)
		return false
	}
	if dev == nil || dev.UserID != userID {
		// Stale cookie — clear it so the browser stops re-sending.
		clearTrustedCookie(w, r)
		return false
	}
	return true
}

// issueTrustedDeviceCookie writes a fresh row + cookie. Called from the
// 2FA verify success path when the user opted in.
func (a *App) issueTrustedDeviceCookie(w http.ResponseWriter, r *http.Request, userID int64) error {
	token := randomToken(32)
	if _, err := a.DB.CreateTrustedDevice(r.Context(), userID, token, labelFromUserAgent(r.Header.Get("User-Agent")), userTrustedTTL); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     userTrustedCookie,
		Value:    token,
		Path:     "/user",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(userTrustedTTL.Seconds()),
	})
	return nil
}

// clearTrustedCookie zeroes the trust cookie. Used when:
//   - a stale cookie hits the server,
//   - the user revokes a device,
//   - the user disables 2FA.
func clearTrustedCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     userTrustedCookie,
		Value:    "",
		Path:     "/user",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		MaxAge:   -1,
	})
}

// POST /user/2fa/trusted-devices/revoke {device_id}
func (a *App) handleUserTrustedDeviceRevoke(w http.ResponseWriter, r *http.Request) {
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	deviceID, _ := strconv.ParseInt(r.PostForm.Get("device_id"), 10, 64)
	if deviceID <= 0 {
		http.Redirect(w, r, "/user/2fa?err=internal", http.StatusSeeOther)
		return
	}
	if err := a.DB.DeleteTrustedDevice(r.Context(), uid, deviceID); err != nil {
		log.Printf("revoke trusted device %d: %v", deviceID, err)
		http.Redirect(w, r, "/user/2fa?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_trusted_device_revoked",
		strconv.FormatInt(deviceID, 10), "ip="+a.clientIP(r))
	http.Redirect(w, r, "/user/2fa?ok=device_revoked", http.StatusSeeOther)
}

// POST /user/2fa/trusted-devices/revoke-all
func (a *App) handleUserTrustedDeviceRevokeAll(w http.ResponseWriter, r *http.Request) {
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
	if err := a.DB.DeleteAllTrustedDevices(r.Context(), uid); err != nil {
		log.Printf("revoke all trusted devices for %d: %v", uid, err)
		http.Redirect(w, r, "/user/2fa?err=internal", http.StatusSeeOther)
		return
	}
	// Also clear the cookie on this browser so its next login challenges.
	clearTrustedCookie(w, r)
	a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_trusted_devices_revoked_all",
		"", "ip="+a.clientIP(r))
	http.Redirect(w, r, "/user/2fa?ok=devices_revoked", http.StatusSeeOther)
}

// formatRelativeTime is a tiny helper used by the template to show
// "5 分钟前" instead of a full timestamp. Templates that want absolute
// times can still use {{formatTime}}.
func formatRelativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " 分钟前"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + " 小时前"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + " 天前"
	}
}
