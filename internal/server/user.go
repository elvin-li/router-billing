package server

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"router-billing/internal/models"
)

const userCookieName = "rb_user"
const userSessionTTL = 30 * 24 * time.Hour // 30 days

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
			http.Redirect(w, r, "/user/login?next="+r.URL.RequestURI(), http.StatusSeeOther)
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
	return *sess.UserID
}

func (a *App) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.render(w, "user_login.html", a.userCtx(r, "login", map[string]any{
			"Next": r.URL.Query().Get("next"),
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
	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		a.DB.Audit(r.Context(), "user:"+phone, "login_failed", "", clientIP(r))
		http.Redirect(w, r, "/user/login?err=bad_credentials", http.StatusSeeOther)
		return
	}
	if user.Suspended {
		a.DB.Audit(r.Context(), "user:"+phone, "login_suspended", "", clientIP(r))
		http.Redirect(w, r, "/user/login?err=suspended", http.StatusSeeOther)
		return
	}
	a.startUserSession(w, r, user)
	a.DB.Audit(r.Context(), "user:"+user.Phone, "login", "", clientIP(r))
	next := r.PostForm.Get("next")
	if !strings.HasPrefix(next, "/") {
		next = "/user/me"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
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
	if !models.ValidPassword(password) {
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
	token := randomToken(32)
	uid := u.ID
	if err := a.DB.CreateSession(r.Context(), token, "user", u.Phone, &uid, userSessionTTL); err != nil {
		log.Printf("create user session: %v", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     userCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(userSessionTTL.Seconds()),
	})
}

func (a *App) handleUserLogout(w http.ResponseWriter, r *http.Request) {
	if c, _ := r.Cookie(userCookieName); c != nil {
		_ = a.DB.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: userCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
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

	a.render(w, "user_me.html", a.userCtx(r, "me", map[string]any{
		"User":        user,
		"MACs":        macs,
		"Orders":      orders,
		"DeviceMAC":   deviceMAC,
		"DeviceKnown": deviceKnown,
		"Plans":       a.planViews(r.Context()),
		"WeChatOn":    a.WeChat != nil,
		"AlipayOn":    a.Alipay != nil,
	}))
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
	if !models.ValidPassword(newP) {
		http.Redirect(w, r, "/user/me?err=bad_password", http.StatusSeeOther)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(newP), bcrypt.DefaultCost)
	if err := a.DB.UpdateUserPassword(r.Context(), uid, string(hash)); err != nil {
		http.Redirect(w, r, "/user/me?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "password_change", "", "")
	http.Redirect(w, r, "/user/me?ok=password", http.StatusSeeOther)
}

// --- small bits ---

func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		if i := strings.Index(h, ","); i >= 0 {
			return strings.TrimSpace(h[:i])
		}
		return strings.TrimSpace(h)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
