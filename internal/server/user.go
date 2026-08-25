package server

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"router-billing/internal/db"
	"router-billing/internal/models"
)

const userCookieName = "rb_user"
const userPendingCookie = "rb_user_pending"
const userTrustedCookie = "rb_user_trusted"
const userPending2FATTL = 5 * time.Minute
const userTrustedTTL = 30 * 24 * time.Hour // 30-day trust window

// User session lifetime is config.Security.UserSessionTTL() — defaults to
// 30d, range 1..365. See internal/config/config.go.

// bcryptTimingDummy is a hash of a random throwaway value, compared against
// when a login names an unregistered phone — so the "no such user" path
// costs the same bcrypt work as a real password check and timing doesn't
// enumerate accounts. Hashed once at startup; the plaintext is discarded.
var bcryptTimingDummy = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte(randomToken(16)), bcrypt.DefaultCost)
	if err != nil {
		// bcrypt only errors on cost/length misuse — ours are constants.
		panic("bcrypt timing dummy: " + err.Error())
	}
	return h
}()

// userCtx assembles the common data passed to every user-facing template.
func (a *App) userCtx(r *http.Request, page string, extra map[string]any) map[string]any {
	out := map[string]any{
		"Version":   a.Version,
		"Page":      page,
		"OK":        r.URL.Query().Get("ok"),
		"Err":       userErrLabel(r.URL.Query().Get("err")),
		"CSRFToken": csrfFromContext(r.Context()),
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func userErrLabel(code string) string {
	switch code {
	case "":
		return ""
	case "bad_phone":
		return "手机号格式不正确（11 位，1[3-9] 开头）"
	case "bad_password":
		return "密码至少 6 位，不超过 72 位"
	case "phone_exists":
		return "该手机号已注册，请直接登录"
	case "bad_credentials":
		return "手机号或密码错误"
	case "rate_limited":
		return "请求过于频繁，请稍候再试"
	case "suspended":
		return "账号已停用，请联系管理员"
	case "sms_unavailable":
		return "短信功能未启用，无法重置密码，请联系管理员"
	case "sms_failed":
		return "短信发送失败，请稍候重试"
	case "bad_code":
		return "验证码错误"
	case "expired":
		return "验证码已过期，请重新申请"
	case "too_many_attempts":
		return "验证次数过多，请重新申请验证码"
	case "password_reset":
		return ""
	case "2fa_expired":
		return "二步验证会话已过期，请重新登录"
	case "2fa_failed":
		return "验证码错误，请重试"
	case "2fa_locked":
		return "验证失败次数过多，请重新登录"
	case "2fa_required":
		return "请输入二步验证码"
	case "2fa_already_on":
		return "二步验证已开启，无需重复开启"
	case "2fa_not_enrolled":
		return "尚未开启二步验证"
	case "2fa_disabled":
		return ""
	case "signed_out_others":
		return ""
	case "no_mac":
		return "未检测到本设备 MAC，请连接到收费 SSID 后重试"
	case "replace_failed":
		return "替换失败：可能 MAC 不属于你 / 已过期 / 目标 MAC 已被使用"
	case "internal":
		return "内部错误，请重试"
	default:
		return code
	}
}

func (a *App) requireUser(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := a.currentUserID(r)
		if uid == 0 {
			http.Redirect(w, r, "/user/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if !verifyCSRF(r) {
			http.Error(w, "CSRF token invalid — please refresh the page and retry", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func (a *App) currentUserID(r *http.Request) int64 {
	c, err := r.Cookie(userCookieName)
	if err != nil || c.Value == "" {
		return 0
	}
	sess, err := a.DB.GetSession(r.Context(), c.Value)
	if err != nil || sess == nil || sess.Kind != "user" || sess.UserID == nil {
		return 0
	}
	// SECURITY: re-check the user's current state on every request. The
	// /admin/users/suspend handler already kills sessions on suspend, but
	// this defends against the (DB write failure, replay attack, race with
	// concurrent admin actions) where a stale session lingers.
	if u, err := a.DB.GetUser(r.Context(), *sess.UserID); err == nil && u != nil && u.Suspended {
		return 0
	}
	return *sess.UserID
}

// safeNextPath validates a post-login redirect target. Only same-site
// relative paths pass: must start with exactly one "/" (so "//evil.com"
// and "/\evil.com" — which browsers treat as protocol-relative external
// URLs — are rejected) and contain no backslashes anywhere (some browsers
// normalize "\" to "/" before resolving). Anything else → fallback.
//
// Pre-v0.99 the login path only checked strings.HasPrefix(next, "/") and
// the 2FA login path did no validation at all — both were open redirects.
func safeNextPath(next, fallback string) string {
	if next == "" || next[0] != '/' {
		return fallback
	}
	if len(next) > 1 && next[1] == '/' {
		return fallback
	}
	if strings.ContainsAny(next, "\\\r\n") {
		return fallback
	}
	return next
}

func (a *App) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.render(w, "user_login.html", a.userCtx(r, "login", map[string]any{
			"Next":         safeNextPath(r.URL.Query().Get("next"), ""),
			"SMSAvailable": a.SMS.Available(),
		}))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !a.loginLimiter.allow(clientIP(r)) {
		http.Redirect(w, r, "/user/login?err=rate_limited", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	phone := strings.TrimSpace(r.PostForm.Get("phone"))
	password := r.PostForm.Get("password")
	if !models.ValidPhone(phone) {
		http.Redirect(w, r, "/user/login?err=bad_phone", http.StatusSeeOther)
		return
	}
	// Phone-keyed rate limit prevents distributed attacks against one account.
	if !a.loginByPhoneLimit.allow(phone) {
		http.Redirect(w, r, "/user/login?err=rate_limited", http.StatusSeeOther)
		return
	}
	user, err := a.DB.GetUserByPhone(r.Context(), phone)
	if err != nil {
		log.Printf("user lookup: %v", err)
		http.Redirect(w, r, "/user/login?err=internal", http.StatusSeeOther)
		return
	}
	passOK := false
	if user != nil {
		passOK = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) == nil
	} else {
		// Burn the same bcrypt cost on unknown phones so response timing
		// doesn't reveal which numbers are registered.
		_ = bcrypt.CompareHashAndPassword(bcryptTimingDummy, []byte(password))
	}
	if !passOK {
		a.DB.Audit(r.Context(), "user:"+phone, "login_failed", "", clientIP(r))
		http.Redirect(w, r, "/user/login?err=bad_credentials", http.StatusSeeOther)
		return
	}
	if user.Suspended {
		a.DB.Audit(r.Context(), "user:"+phone, "login_suspended", "", clientIP(r))
		http.Redirect(w, r, "/user/login?err=suspended", http.StatusSeeOther)
		return
	}

	next := safeNextPath(r.PostForm.Get("next"), "/user/me")

	// If 2FA is enrolled, hold the session in pending state until the user
	// submits a valid TOTP code. Same shape as the admin 2FA flow (see
	// admin_2fa.go) so the security guarantees match.
	//
	// Exception: if the browser presents a valid trusted-device cookie for
	// this user, the password we just verified is treated as full auth and
	// we skip the 2FA challenge. The trust cookie alone isn't a free pass —
	// it requires the user's current password too.
	if user.TOTPSecret != "" {
		if a.consumeTrustedDeviceCookie(w, r, user.ID) {
			a.startUserSession(w, r, user)
			a.DB.Audit(r.Context(), "user:"+user.Phone, "login", "", "via=trusted_device ip="+clientIP(r))
			http.Redirect(w, r, next, http.StatusSeeOther)
			return
		}
		ptok := randomToken(32)
		if err := a.DB.CreateSession(r.Context(), ptok, "user_pending_2fa", user.Phone, &user.ID, userPending2FATTL); err != nil {
			log.Printf("create user pending 2fa session: %v", err)
			http.Redirect(w, r, "/user/login?err=internal", http.StatusSeeOther)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     userPendingCookie,
			Value:    ptok,
			Path:     "/user",
			HttpOnly: true,
			Secure:   isHTTPS(r),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(userPending2FATTL.Seconds()),
		})
		http.Redirect(w, r, "/user/login/2fa?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}

	a.startUserSession(w, r, user)
	a.DB.Audit(r.Context(), "user:"+user.Phone, "login", "", clientIP(r))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// passwordValidatorFor returns the password-policy function selected by
// config.security.password_strength. Used at register / password-change /
// forgot-password reset so all three paths share one policy.
func (a *App) passwordValidatorFor() func(string) bool {
	if a.Cfg.Security.PasswordStrengthStrict() {
		return models.ValidPasswordStrong
	}
	return models.ValidPassword
}

func (a *App) handleUserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.render(w, "user_register.html", a.userCtx(r, "register", nil))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !a.registerLimiter.allow(clientIP(r)) {
		http.Redirect(w, r, "/user/register?err=rate_limited", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	phone := strings.TrimSpace(r.PostForm.Get("phone"))
	password := r.PostForm.Get("password")
	if !models.ValidPhone(phone) {
		http.Redirect(w, r, "/user/register?err=bad_phone", http.StatusSeeOther)
		return
	}
	if !a.passwordValidatorFor()(password) {
		http.Redirect(w, r, "/user/register?err=bad_password", http.StatusSeeOther)
		return
	}
	if existing, _ := a.DB.GetUserByPhone(r.Context(), phone); existing != nil {
		http.Redirect(w, r, "/user/register?err=phone_exists", http.StatusSeeOther)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Redirect(w, r, "/user/register?err=internal", http.StatusSeeOther)
		return
	}
	user, err := a.DB.CreateUser(r.Context(), phone, string(hash))
	if err != nil {
		log.Printf("create user %s: %v", phone, err)
		http.Redirect(w, r, "/user/register?err=internal", http.StatusSeeOther)
		return
	}
	a.startUserSession(w, r, user)
	a.DB.Audit(r.Context(), "user:"+phone, "register", "", clientIP(r))
	http.Redirect(w, r, "/user/me?ok=registered", http.StatusSeeOther)
}

func (a *App) startUserSession(w http.ResponseWriter, r *http.Request, u *models.User) {
	ttl := a.Cfg.Security.UserSessionTTL()
	token := randomToken(32)
	uid := u.ID
	if err := a.DB.CreateSession(r.Context(), token, "user", u.Phone, &uid, ttl); err != nil {
		log.Printf("create user session: %v", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     userCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (a *App) handleUserLogout(w http.ResponseWriter, r *http.Request) {
	// POST-only: SameSite=Lax cookies DO ride along on top-level cross-site
	// GET navigations (and on speculative link prefetches some browsers
	// issue), so a hostile <a href=".../user/logout"> — or an eager
	// prefetcher — could sign the user out. GET now bounces back to the
	// account page with the session intact. Mirrors the /admin/logout
	// hardening; the user side was left as a plain GET link.
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/me", http.StatusSeeOther)
		return
	}
	// This route sits outside requireUser (logging out with an expired
	// session must still clear the cookie), so check CSRF here directly.
	if !verifyCSRF(r) {
		http.Error(w, "CSRF token invalid — please refresh the page and retry", http.StatusForbidden)
		return
	}
	if c, _ := r.Cookie(userCookieName); c != nil {
		_ = a.DB.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     userCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
	})
	http.Redirect(w, r, "/portal", http.StatusSeeOther)
}

// GET /user/me
func (a *App) handleUserMe(w http.ResponseWriter, r *http.Request) {
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	macs, _ := a.DB.ListMACsForUser(r.Context(), uid)
	orders, _ := a.DB.ListOrdersForUser(r.Context(), uid, 20)

	deviceMAC := a.detectMAC(r)
	deviceKnown := false
	for _, m := range macs {
		if m.Mac == deviceMAC {
			deviceKnown = true
			break
		}
	}

	// Last 10 audit entries for this account — login successes/failures,
	// 2FA events, password resets, etc. Filter by actor pattern that matches
	// both "user:<phone>" (real events) and "user-attempt:<phone>" (failed
	// logins that never got a session).
	activity, _ := a.DB.SearchAudit(r.Context(), db.AuditFilter{
		Actor: ":" + user.Phone,
		Limit: 10,
	})
	sessionCount, _ := a.DB.CountUserSessions(r.Context(), uid)

	a.render(w, "user_me.html", a.userCtx(r, "me", map[string]any{
		"User":           user,
		"MACs":           macs,
		"Orders":         orders,
		"DeviceMAC":      deviceMAC,
		"DeviceKnown":    deviceKnown,
		"Plans":          a.planViews(r.Context()),
		"WeChatOn":       a.WeChat != nil,
		"AlipayOn":       a.Alipay != nil,
		"Activity":       formatActivity(activity),
		"SessionCount":   sessionCount,
		"HasOtherActive": sessionCount > 1,
	}))
}

// activityView is what the template renders per row — a human-readable
// label + extracted timestamp + best-effort IP pulled from the detail
// string (which we write as "... ip=10.0.0.5").
type activityView struct {
	When   string
	Label  string
	IP     string
	Detail string
}

func formatActivity(entries []db.AuditEntry) []activityView {
	out := make([]activityView, 0, len(entries))
	for _, e := range entries {
		out = append(out, activityView{
			When:   e.At.Format("01-02 15:04"),
			Label:  activityLabel(e.Action),
			IP:     extractIPFromDetail(e.Detail),
			Detail: e.Detail,
		})
	}
	return out
}

// activityLabel translates the bare action string into a user-facing label.
// Unknown actions fall through as themselves so we never silently lose data.
func activityLabel(a string) string {
	switch a {
	case "login":
		return "登录"
	case "login_failed":
		return "登录失败（密码错误）"
	case "login_suspended":
		return "登录失败（账号已停用）"
	case "register":
		return "注册"
	case "password_change":
		return "修改密码"
	case "password_reset":
		return "密码已通过短信重置"
	case "password_reset_request":
		return "申请密码重置短信"
	case "password_reset_failed":
		return "密码重置验证码错误"
	case "2fa_failed":
		return "二步验证失败"
	case "2fa_locked":
		return "二步验证锁定（过多失败）"
	case "2fa_enroll_begin":
		return "开始绑定二步验证"
	case "2fa_enroll_failed":
		return "绑定二步验证失败"
	case "2fa_enrolled":
		return "已绑定二步验证"
	case "2fa_disabled":
		return "已关闭二步验证"
	case "2fa_disable_failed":
		return "关闭二步验证失败"
	case "2fa_backup_codes_issued":
		return "生成 10 个备用码"
	case "2fa_backup_codes_regenerated":
		return "重新生成备用码"
	case "2fa_trusted_device_issued":
		return "添加受信任设备"
	case "2fa_trusted_device_revoked":
		return "移除受信任设备"
	case "2fa_trusted_devices_revoked_all":
		return "移除所有受信任设备"
	case "replace":
		return "替换 MAC"
	case "claim":
		return "认领 MAC"
	case "label":
		return "修改 MAC 标签"
	default:
		return a
	}
}

// extractIPFromDetail pulls "ip=10.0.0.5" out of the detail string. Returns
// "" if no such substring; the template hides the column on empty.
func extractIPFromDetail(detail string) string {
	const key = "ip="
	idx := strings.Index(detail, key)
	if idx < 0 {
		return ""
	}
	rest := detail[idx+len(key):]
	for i, r := range rest {
		if r == ' ' || r == '\t' || r == ',' {
			return rest[:i]
		}
	}
	return rest
}

// POST /user/macs/replace  {old_mac, new_mac?}
// new_mac defaults to the detected MAC of the requesting device.
func (a *App) handleUserReplaceMAC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/me", http.StatusSeeOther)
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
	oldMac, ok := models.NormalizeMAC(r.PostForm.Get("old_mac"))
	if !ok {
		http.Redirect(w, r, "/user/me?err=replace_failed", http.StatusSeeOther)
		return
	}
	newRaw := r.PostForm.Get("new_mac")
	if newRaw == "" {
		newRaw = a.detectMAC(r)
	}
	newMac, ok := models.NormalizeMAC(newRaw)
	if !ok {
		http.Redirect(w, r, "/user/me?err=no_mac", http.StatusSeeOther)
		return
	}
	if oldMac == newMac {
		http.Redirect(w, r, "/user/me?ok=nochange", http.StatusSeeOther)
		return
	}
	if _, err := a.MACSvc.Replace(r.Context(), uid, oldMac, newMac, ""); err != nil {
		log.Printf("user replace %s->%s for %d: %v", oldMac, newMac, uid, err)
		http.Redirect(w, r, "/user/me?err=replace_failed", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "replace", newMac, "from="+oldMac)
	http.Redirect(w, r, "/user/me?ok=replaced", http.StatusSeeOther)
}

// POST /user/macs/claim  — claim the current device's MAC as their own.
// Only succeeds if the MAC has an active subscription that no other user owns.
func (a *App) handleUserClaimMAC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/me", http.StatusSeeOther)
		return
	}
	uid := a.currentUserID(r)
	user, _ := a.DB.GetUser(r.Context(), uid)
	if user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	mac := a.detectMAC(r)
	if mac == "" {
		http.Redirect(w, r, "/user/me?err=no_mac", http.StatusSeeOther)
		return
	}
	existing, _ := a.DB.GetMAC(r.Context(), mac)
	if existing == nil || existing.Status != models.MACActive || existing.ExpiresAt.Before(time.Now()) {
		// Nothing to claim — direct users to buy time instead.
		http.Redirect(w, r, "/portal?mac="+mac, http.StatusSeeOther)
		return
	}
	if existing.UserID != nil && *existing.UserID != uid {
		http.Redirect(w, r, "/user/me?err=replace_failed", http.StatusSeeOther)
		return
	}
	// Take ownership without changing expiry/days (days=0 + active+future-expiry → no-op).
	if _, err := a.DB.UpsertMAC(r.Context(), mac, "", 0, &uid); err != nil {
		http.Redirect(w, r, "/user/me?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "claim", mac, "")
	http.Redirect(w, r, "/user/me?ok=claimed", http.StatusSeeOther)
}

// POST /user/macs/label  {mac, label}
// Only allowed if the MAC belongs to the current user.
func (a *App) handleUserLabelMAC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/me", http.StatusSeeOther)
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
	mac, ok := models.NormalizeMAC(r.PostForm.Get("mac"))
	if !ok {
		http.Redirect(w, r, "/user/me?err=replace_failed", http.StatusSeeOther)
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if len(label) > 60 {
		label = label[:60]
	}
	existing, _ := a.DB.GetMAC(r.Context(), mac)
	if existing == nil || existing.UserID == nil || *existing.UserID != uid {
		http.Redirect(w, r, "/user/me?err=replace_failed", http.StatusSeeOther)
		return
	}
	if err := a.DB.SetMACLabel(r.Context(), mac, label); err != nil {
		log.Printf("user label %s: %v", mac, err)
		http.Redirect(w, r, "/user/me?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "label", mac, label)
	http.Redirect(w, r, "/user/me?ok=label", http.StatusSeeOther)
}

// POST /user/notifications  {notify_expiry=on|""}
//
// Toggle the per-user opt-out for the 套餐到期提醒 SMS loop. Posting with
// the `notify_expiry` field present (HTML checkbox semantics — value is
// "on" when checked, absent when unchecked) flips the flag accordingly.
func (a *App) handleUserNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/me", http.StatusSeeOther)
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
	on := r.PostForm.Get("notify_expiry") == "on" || r.PostForm.Get("notify_expiry") == "1"
	if err := a.DB.SetUserNotifyExpiry(r.Context(), uid, on); err != nil {
		log.Printf("user notify-expiry %d: %v", uid, err)
		http.Redirect(w, r, "/user/me?err=internal", http.StatusSeeOther)
		return
	}
	action := "notify_expiry_off"
	if on {
		action = "notify_expiry_on"
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, action, "", "ip="+clientIP(r))
	http.Redirect(w, r, "/user/me?ok=prefs", http.StatusSeeOther)
}

// GET /user/account/export
//
// User-driven data export — JSON file with everything we hold about the
// user (account profile, MACs, orders, last 100 audit entries). Companion
// to the /user/account/delete handler; together they give a basic
// portability + erasure surface for any privacy regime that asks.
//
// Excludes the obvious secrets: password hash, TOTP secret, trusted-
// device tokens. Anything that would help an attacker stays out.
func (a *App) handleUserAccountExport(w http.ResponseWriter, r *http.Request) {
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	macs, _ := a.DB.ListMACsForUser(r.Context(), uid)
	orders, _ := a.DB.ListOrdersForUser(r.Context(), uid, 500)
	activity, _ := a.DB.SearchAudit(r.Context(), db.AuditFilter{
		Actor: ":" + user.Phone,
		Limit: 100,
	})

	type activityEntry struct {
		At     time.Time `json:"at"`
		Action string    `json:"action"`
		Target string    `json:"target,omitempty"`
		Detail string    `json:"detail,omitempty"`
	}
	actOut := make([]activityEntry, 0, len(activity))
	for _, e := range activity {
		actOut = append(actOut, activityEntry{
			At: e.At, Action: e.Action, Target: e.Target, Detail: e.Detail,
		})
	}

	export := map[string]any{
		"export_format_version": 1,
		"exported_at":           time.Now().UTC(),
		"account": map[string]any{
			"id":           user.ID,
			"phone":        user.Phone,
			"suspended":    user.Suspended,
			"totp_enabled": user.TOTPSecret != "",
			"created_at":   user.CreatedAt,
			"updated_at":   user.UpdatedAt,
		},
		"macs":     macs,
		"orders":   orders,
		"activity": actOut,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="router-billing-data-`+user.Phone+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(export); err != nil {
		log.Printf("user account export %d: %v", uid, err)
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "account_export", "", "ip="+clientIP(r))
}

// POST /user/account/delete  {password}
//
// User-driven account deletion (GDPR-style "right to be forgotten"). Requires
// the current password to confirm intent. Cascades:
//   - users row hard-deleted
//   - sessions for this user dropped (DeleteUser already does this)
//   - macs.user_id / orders.user_id flip to NULL (FK ON DELETE SET NULL)
//   - audit_log entries stay (they're already keyed by phone, not user_id,
//     and the audit history is what makes "this account existed" recoverable
//     for fraud-investigation purposes)
//
// Browser is signed out via the same cookie-wipe the logout handler does.
func (a *App) handleUserAccountDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/me", http.StatusSeeOther)
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
	pw := r.PostForm.Get("password")
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(pw)) != nil {
		a.DB.Audit(r.Context(), "user:"+user.Phone, "account_delete_failed", "",
			"reason=bad_password ip="+clientIP(r))
		http.Redirect(w, r, "/user/me?err=bad_credentials", http.StatusSeeOther)
		return
	}
	if err := a.DB.DeleteUser(r.Context(), uid); err != nil {
		log.Printf("user self-delete %d: %v", uid, err)
		http.Redirect(w, r, "/user/me?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "account_self_deleted", "",
		"ip="+clientIP(r))
	// Wipe the cookie on the calling browser.
	http.SetCookie(w, &http.Cookie{
		Name: userCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name: userTrustedCookie, Value: "", Path: "/user", MaxAge: -1, HttpOnly: true,
	})
	http.Redirect(w, r, "/portal?ok=account_deleted", http.StatusSeeOther)
}

// POST /user/sessions/sign-out-others — kills every session for this user
// EXCEPT the one making the request. Useful from /user/me when the user
// suspects their account was accessed elsewhere.
func (a *App) handleUserSignOutOthers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/me", http.StatusSeeOther)
		return
	}
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	keep := ""
	if c, _ := r.Cookie(userCookieName); c != nil {
		keep = c.Value
	}
	n, err := a.DB.DeleteUserSessionsExcept(r.Context(), uid, keep)
	if err != nil {
		log.Printf("sign-out-others %d: %v", uid, err)
		http.Redirect(w, r, "/user/me?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "sessions_revoked_others", "",
		"killed="+strconv.Itoa(int(n))+" ip="+clientIP(r))
	http.Redirect(w, r, "/user/me?ok=signed_out_others", http.StatusSeeOther)
}

// POST /user/password  {old, new}
func (a *App) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/me", http.StatusSeeOther)
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
	old := r.PostForm.Get("old_password")
	newP := r.PostForm.Get("new_password")
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(old)) != nil {
		http.Redirect(w, r, "/user/me?err=bad_credentials", http.StatusSeeOther)
		return
	}
	if !a.passwordValidatorFor()(newP) {
		http.Redirect(w, r, "/user/me?err=bad_password", http.StatusSeeOther)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(newP), bcrypt.DefaultCost)
	if err := a.DB.UpdateUserPassword(r.Context(), uid, string(hash)); err != nil {
		http.Redirect(w, r, "/user/me?err=internal", http.StatusSeeOther)
		return
	}
	// A password change means every other login is untrusted: stolen
	// rb_user cookies must die. Keep the browser that just proved the
	// old password so the user is not bounced to /user/login.
	keep := ""
	if c, err := r.Cookie(userCookieName); err == nil {
		keep = c.Value
	}
	if keep != "" {
		if _, err := a.DB.DeleteUserSessionsExcept(r.Context(), uid, keep); err != nil {
			log.Printf("password-change drop other sessions %d: %v", uid, err)
		}
	} else if _, err := a.DB.DeleteSessionsByUserID(r.Context(), uid); err != nil {
		log.Printf("password-change drop sessions %d: %v", uid, err)
	}
	if err := a.DB.DeleteAllTrustedDevices(r.Context(), uid); err != nil {
		log.Printf("password-change drop trusted devices %d: %v", uid, err)
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "password_change", "", "")
	http.Redirect(w, r, "/user/me?ok=password", http.StatusSeeOther)
}

// --- small bits ---

// clientIP returns the address realIPMiddleware resolved for this request.
// X-Forwarded-For handling (only from security.trusted_proxies) lives in
// that middleware — previously the header's FIRST entry was trusted from
// anyone, which let a direct client pick a fresh fake IP per request and
// walk straight through every per-IP rate limit (voucher brute force,
// login floods, payment intent floods, forgot-password SMS pumping) and
// stamp forged IPs into the audit log.
func clientIP(r *http.Request) string {
	if v, ok := r.Context().Value(realIPCtxKey).(string); ok && v != "" {
		return v
	}
	return remoteHost(r)
}

// --- rate limiter ---

type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: make(map[string][]time.Time), max: max, window: window}
}

func (rl *rateLimiter) allow(key string) bool {
	if key == "" {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	h := rl.hits[key]
	out := h[:0]
	for _, t := range h {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	if len(out) >= rl.max {
		rl.hits[key] = out
		return false
	}
	out = append(out, now)
	rl.hits[key] = out
	// Cheap gc: if the map gets large, drop oldest.
	if len(rl.hits) > 4096 {
		for k, v := range rl.hits {
			if len(v) == 0 || v[len(v)-1].Before(cutoff) {
				delete(rl.hits, k)
			}
		}
	}
	return true
}
