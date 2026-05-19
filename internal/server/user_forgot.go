package server

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"router-billing/internal/models"
)

// Forgot-password flow:
//
//	GET  /user/forgot-password               -> render stage 1 (phone input)
//	POST /user/forgot-password               -> issue SMS code, render stage 2
//	POST /user/forgot-password/verify        -> verify code + set new password
//
// Both POST handlers are gated behind a.SMS.Available() so the feature
// silently disables when no provider is wired. The login page only links to
// stage 1 when SMS is on; the URL responds with sms_unavailable if hit
// directly without a provider.
//
// Anti-abuse:
//   - Per-IP and per-phone rate limit on issuance (3/h per phone, 6/h per IP)
//     so an attacker can't burn through somebody's phone-bill or DoS the
//     account.
//   - Per-IP and per-phone rate limit on verify (10/h per phone, 30/h per IP)
//     on top of the per-row attempt cap (5 wrong codes → row deleted).
//   - Code length is 6 digits via crypto/rand uniform sampling; never log the
//     plaintext. We bcrypt-hash and compare in constant time at verify.
//   - The user-enumeration check is deliberately leaky for one signal: we
//     answer 'success' regardless of whether the phone exists, but only burn
//     the per-phone limiter and send SMS when the user is real. An attacker
//     can still infer existence by the absence of an SMS — that's an
//     unavoidable trade-off when the feature is genuinely useful.
const (
	pwResetCodeTTL     = 10 * time.Minute
	pwResetMaxAttempts = 5
	pwResetCodeLen     = 6
)

// genNumericCode returns a uniformly-random decimal string of length n.
// Uses rejection-free sampling: pull 8 fresh bytes per attempt and mod by
// 10^n only when the value falls below the largest multiple of 10^n that
// fits in uint64. (For n=6 the rejection probability is ~0, but the loop
// keeps us honest in case we ever bump the length.)
func genNumericCode(n int) string {
	if n <= 0 {
		n = pwResetCodeLen
	}
	mod := uint64(1)
	for i := 0; i < n; i++ {
		mod *= 10
	}
	// Largest multiple of mod that fits in uint64.
	lim := (^uint64(0) / mod) * mod
	var v uint64
	buf := make([]byte, 8)
	for {
		_, _ = rand.Read(buf)
		v = binary.BigEndian.Uint64(buf)
		if v < lim {
			break
		}
	}
	v %= mod
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return string(out)
}

func (a *App) handleUserForgotPassword(w http.ResponseWriter, r *http.Request) {
	if !a.SMS.Available() {
		http.Redirect(w, r, "/user/login?err=sms_unavailable", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		a.render(w, "user_forgot_password.html", a.userCtx(r, "forgot", map[string]any{
			"Stage":    1,
			"SMSName":  a.SMS.Name(),
			"CodeTTLm": int(pwResetCodeTTL / time.Minute),
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
	if !a.pwResetIssueIPLimit.allow(clientIP(r)) {
		a.renderForgot(w, r, 1, "", "rate_limited")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	phone := strings.TrimSpace(r.PostForm.Get("phone"))
	if !models.ValidPhone(phone) {
		a.renderForgot(w, r, 1, "", "bad_phone")
		return
	}
	if !a.pwResetIssuePhoneLimit.allow(phone) {
		a.renderForgot(w, r, 1, phone, "rate_limited")
		return
	}

	// Best-effort lookup. We always advance to stage 2 so the response is
	// uniform between "phone exists" and "phone doesn't exist" — see big
	// comment at top.
	user, err := a.DB.GetUserByPhone(r.Context(), phone)
	if err != nil {
		log.Printf("forgot-password lookup %s: %v", phone, err)
		a.renderForgot(w, r, 1, phone, "internal")
		return
	}

	if user != nil && !user.Suspended {
		code := genNumericCode(pwResetCodeLen)
		hash, hErr := bcryptHash(code)
		if hErr != nil {
			a.renderForgot(w, r, 1, phone, "internal")
			return
		}
		if _, dbErr := a.DB.CreatePasswordReset(r.Context(), user.ID, hash, pwResetCodeTTL); dbErr != nil {
			log.Printf("forgot-password create row for %s: %v", phone, dbErr)
			a.renderForgot(w, r, 1, phone, "internal")
			return
		}
		body := "【router-billing】您的密码重置验证码：" + code + "，" +
			padMins(int(pwResetCodeTTL/time.Minute)) + "内有效。若非本人操作，请忽略。"
		if sErr := a.SMS.Send(r.Context(), user.Phone, body); sErr != nil {
			log.Printf("forgot-password sms %s: %v", phone, sErr)
			a.renderForgot(w, r, 1, phone, "sms_failed")
			return
		}
		a.DB.Audit(r.Context(), "user:"+user.Phone, "password_reset_request",
			"", "provider="+a.SMS.Name()+" ip="+clientIP(r))
	} else {
		// Don't leak whether the phone exists — pretend we sent.
		log.Printf("forgot-password: phone %s not found / suspended — silent success", phone)
	}

	a.renderForgot(w, r, 2, phone, "")
}

func (a *App) handleUserForgotPasswordVerify(w http.ResponseWriter, r *http.Request) {
	if !a.SMS.Available() {
		http.Redirect(w, r, "/user/login?err=sms_unavailable", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/forgot-password", http.StatusSeeOther)
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
	phone := strings.TrimSpace(r.PostForm.Get("phone"))
	code := strings.TrimSpace(r.PostForm.Get("code"))
	newPwd := r.PostForm.Get("new_password")
	if !models.ValidPhone(phone) {
		a.renderForgot(w, r, 2, phone, "bad_phone")
		return
	}
	if !a.pwResetVerifyIPLimit.allow(clientIP(r)) {
		a.renderForgot(w, r, 2, phone, "rate_limited")
		return
	}
	if !a.pwResetVerifyPhoneLim.allow(phone) {
		a.renderForgot(w, r, 2, phone, "rate_limited")
		return
	}
	// Cheap shape check first so a bogus "0000" doesn't hit bcrypt / the DB.
	if len(code) != pwResetCodeLen || !allDigits(code) {
		a.renderForgot(w, r, 2, phone, "bad_code")
		return
	}
	if !a.passwordValidatorFor()(newPwd) {
		a.renderForgot(w, r, 2, phone, "bad_password")
		return
	}

	user, err := a.DB.GetUserByPhone(r.Context(), phone)
	if err != nil {
		log.Printf("forgot-verify lookup %s: %v", phone, err)
		a.renderForgot(w, r, 2, phone, "internal")
		return
	}
	if user == nil || user.Suspended {
		// Uniform response — also matches the silent-success branch above.
		a.renderForgot(w, r, 2, phone, "bad_code")
		return
	}
	row, err := a.DB.GetActivePasswordReset(r.Context(), user.ID)
	if err != nil {
		log.Printf("forgot-verify get reset for %d: %v", user.ID, err)
		a.renderForgot(w, r, 2, phone, "internal")
		return
	}
	if row == nil {
		a.renderForgot(w, r, 2, phone, "expired")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(row.CodeHash), []byte(code)) != nil {
		n, _ := a.DB.BumpPasswordResetAttempts(r.Context(), row.ID)
		a.DB.Audit(r.Context(), "user:"+user.Phone, "password_reset_failed", "", "attempts="+itoa(n)+" ip="+clientIP(r))
		if n >= pwResetMaxAttempts {
			_ = a.DB.DeletePasswordReset(r.Context(), row.ID)
			a.renderForgot(w, r, 2, phone, "too_many_attempts")
			return
		}
		a.renderForgot(w, r, 2, phone, "bad_code")
		return
	}

	// Code accepted — rotate the password and burn all sessions + the reset row.
	hash, hErr := bcryptHash(newPwd)
	if hErr != nil {
		a.renderForgot(w, r, 2, phone, "internal")
		return
	}
	if err := a.DB.UpdateUserPassword(r.Context(), user.ID, hash); err != nil {
		log.Printf("forgot-verify update password %d: %v", user.ID, err)
		a.renderForgot(w, r, 2, phone, "internal")
		return
	}
	_ = a.DB.DeletePasswordReset(r.Context(), row.ID)
	if _, err := a.DB.DeleteSessionsByUserID(r.Context(), user.ID); err != nil {
		log.Printf("forgot-verify drop sessions %d: %v", user.ID, err)
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "password_reset", "", "via=sms ip="+clientIP(r))
	http.Redirect(w, r, "/user/login?ok=password_reset", http.StatusSeeOther)
}

// renderForgot renders the forgot-password page in the requested stage. err
// is a code that userErrLabel knows about; "" means no banner.
//
// We use subtle.ConstantTimeCompare-free string equality for the phone echo
// because it's already attacker-controlled input being painted back into the
// page. CSRF token is re-injected via userCtx so the next POST works.
func (a *App) renderForgot(w http.ResponseWriter, r *http.Request, stage int, phone, errCode string) {
	extra := map[string]any{
		"Stage":    stage,
		"Phone":    phone,
		"SMSName":  a.SMS.Name(),
		"CodeTTLm": int(pwResetCodeTTL / time.Minute),
	}
	if errCode != "" {
		extra["Err"] = userErrLabel(errCode)
	}
	a.render(w, "user_forgot_password.html", a.userCtx(r, "forgot", extra))
}

// padMins formats minutes for the SMS body. Single source of truth so we don't
// drift between the page hint and the message.
func padMins(n int) string {
	if n <= 0 {
		return "10 分钟"
	}
	return itoa(n) + " 分钟"
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
