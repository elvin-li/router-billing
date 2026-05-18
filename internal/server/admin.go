package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"router-billing/internal/arp"
	"router-billing/internal/db"
	"router-billing/internal/dnsmasq"
	"router-billing/internal/models"
	"router-billing/internal/notify"
)

const adminCookieName = "rb_admin"
const adminPendingCookie = "rb_admin_pending"

// Admin session lifetime is config.Security.AdminSessionTTL() — defaults
// to 12h, range 1..168 (1w). User session lifetime is .UserSessionTTL()
// — defaults to 30d, range 1..365.

// deviceView is one row in the /admin/devices table.
type deviceView struct {
	MAC       string
	IP        string
	Hostname  string
	Online    bool      // currently in ARP table
	LastSeen  time.Time // from sightings table
	Known     bool      // exists in macs table
	Active    bool      // known + status=active + not expired
	Label     string
	ExpiresAt time.Time
	Bytes     uint64 // forwarded bytes (per-MAC counter from nftables)
	Packets   uint64
}

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.render(w, "admin_login.html", map[string]any{"Error": ""})
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
	u := r.PostForm.Get("username")
	p := r.PostForm.Get("password")
	if !a.adminLoginLimiter.allow(clientIP(r)) {
		a.render(w, "admin_login.html", map[string]any{"Error": "尝试过于频繁，请稍候再试"})
		return
	}
	// SECURITY: per-username limiter too — a botnet rotating source IPs would
	// otherwise blow through the per-IP budget. 5 attempts / 5 min per
	// username is generous for fat-finger but stops sustained brute force.
	if a.adminLoginByUser != nil && !a.adminLoginByUser.allow(u) {
		a.render(w, "admin_login.html", map[string]any{"Error": "尝试过于频繁，请稍候再试"})
		return
	}
	admin, ok := a.Cfg.AuthenticateAdminFull(u, p)
	if !ok {
		a.DB.Audit(r.Context(), "admin-attempt:"+u, "login_failed", "", clientIP(r))
		a.render(w, "admin_login.html", map[string]any{"Error": "用户名或密码错误"})
		return
	}

	// If this admin has a TOTP secret configured, gate the real session
	// behind a second-factor prompt. Stash a short-lived (5 min) pending
	// session keyed by a separate cookie so the requireAdmin middleware
	// can't be tricked into accepting half-authed traffic.
	if admin.TOTPSecret != "" {
		ptok := randomToken(32)
		if err := a.DB.CreateSession(r.Context(), ptok, "pending_2fa", u, nil, 5*time.Minute); err != nil {
			log.Printf("create pending session: %v", err)
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     adminPendingCookie,
			Value:    ptok,
			Path:     "/admin",
			HttpOnly: true,
			Secure:   isHTTPS(r),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   300,
		})
		http.Redirect(w, r, "/admin/login/2fa", http.StatusSeeOther)
		return
	}

	a.issueAdminSession(w, r, u)
}

// issueAdminSession creates the real admin session row + cookie and bounces
// the browser to the dashboard. Used both from the pure-password path and
// from the 2FA-verified path.
func (a *App) issueAdminSession(w http.ResponseWriter, r *http.Request, username string) {
	ttl := a.Cfg.Security.AdminSessionTTL()
	token := randomToken(32)
	if err := a.DB.CreateSession(r.Context(), token, "admin", username, nil, ttl); err != nil {
		log.Printf("create session: %v", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	// Wipe any leftover pending cookie from the same browser.
	http.SetCookie(w, &http.Cookie{
		Name: adminPendingCookie, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true,
	})
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

func (a *App) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(adminCookieName)
	if c != nil {
		_ = a.DB.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
	})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *App) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(adminCookieName)
		if err != nil || c.Value == "" {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		sess, err := a.DB.GetSession(r.Context(), c.Value)
		if err != nil {
			http.Error(w, "session", http.StatusInternalServerError)
			return
		}
		if sess == nil || sess.Kind != "admin" {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		if !verifyCSRF(r) {
			http.Error(w, "CSRF token invalid — please refresh the page and retry", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// adminCtx assembles common data passed to every admin template:
// Version, Page (for sidebar highlight), and flash messages from ?ok=/?err=.
func (a *App) adminCtx(r *http.Request, page string, extra map[string]any) map[string]any {
	out := map[string]any{
		"Version": a.Version,
		"Page":    page,
		// OK carries the raw ok=... query value so templates can branch on it
		// with `{{if eq .OK "reset_sms"}}`. Empty string is falsy in Go
		// templates, so `{{if .OK}}` still works for generic-success blocks.
		"OK":        r.URL.Query().Get("ok"),
		"Err":       errLabel(r.URL.Query().Get("err")),
		"CSRFToken": csrfFromContext(r.Context()),
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func errLabel(code string) string {
	switch code {
	case "":
		return ""
	case "invalid_mac":
		return "MAC 格式不正确"
	case "invalid_days":
		return "请选择套餐或填入正整数天数"
	case "internal":
		return "内部错误，请重试"
	case "arp":
		return "无法读取在线设备列表（检查 paid_iface 是否正确）"
	case "refund_confirm":
		return "退款失败：请在确认框中输入完整订单号"
	case "refund_no_order":
		return "退款失败：找不到该订单"
	case "refund_not_paid":
		return "退款失败：只能退款已支付的订单"
	case "refund_failed":
		return "退款失败：请查看服务日志"
	case "revoked":
		return ""
	default:
		return code
	}
}

func (a *App) handleAdminMACs(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	var macs []models.MAC
	var err error
	if q == "" && status == "" {
		macs, err = a.DB.ListMACs(r.Context())
	} else {
		macs, err = a.DB.SearchMACs(r.Context(), q, status, 500)
	}
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	stats, err := a.DB.Stats(r.Context())
	if err != nil {
		log.Printf("stats: %v", err)
	}
	att, _ := a.DB.Attention(r.Context())
	planSales, _ := a.DB.PlanSalesSince(r.Context(), 30)
	a.render(w, "admin_macs.html", a.adminCtx(r, "macs", map[string]any{
		"MACs":      macs,
		"Plans":     a.planViews(r.Context()),
		"Stats":     stats,
		"Attention": att,
		"PlanSales": planSales,
		"Now":       time.Now(),
		"Query":     q,
		"Status":    status,
	}))
}

func (a *App) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	iface := a.Cfg.PaidIface
	now := time.Now()

	// 1) Live ARP for currently-online status.
	entries, err := arp.ListOnInterface(r.Context(), iface)
	if err != nil {
		log.Printf("arp list %s: %v", iface, err)
		// don't bail — sightings still have value
		entries = nil
	}
	online := map[string]string{} // mac -> ip
	for _, e := range entries {
		online[e.MAC] = e.IP
	}

	// 2) Historical sightings (last 10 min).
	sightings, _ := a.DB.ListRecentSightings(r.Context(), 10*time.Minute)

	// 3) DHCP leases for hostnames.
	hostnames := dnsmasq.HostnameByMAC(dnsmasq.DefaultLeasesPath)

	// 4) Per-MAC nftables counters (bytes/packets through forward chain).
	counters, _ := a.MACSvc.FW.Counters(r.Context())

	// Merge: every sighted MAC + every online MAC.
	seen := map[string]bool{}
	devices := make([]deviceView, 0, len(sightings)+len(entries))

	build := func(mac, ip, host string, lastSeen time.Time) {
		if seen[mac] {
			return
		}
		seen[mac] = true
		dv := deviceView{MAC: mac, IP: ip, Hostname: host, LastSeen: lastSeen}
		if onlineIP, ok := online[mac]; ok {
			dv.Online = true
			if dv.IP == "" {
				dv.IP = onlineIP
			}
		}
		if m, _ := a.DB.GetMAC(r.Context(), mac); m != nil {
			dv.Known = true
			dv.Label = m.Label
			dv.ExpiresAt = m.ExpiresAt
			dv.Active = m.Status == models.MACActive && m.ExpiresAt.After(now)
		}
		if c, ok := counters[mac]; ok {
			dv.Bytes = c.Bytes
			dv.Packets = c.Packets
		}
		devices = append(devices, dv)
	}

	for _, s := range sightings {
		host := s.Hostname
		if host == "" {
			host = hostnames[s.MAC]
		}
		build(s.MAC, s.LastIP, host, s.LastSeen)
	}
	for _, e := range entries {
		build(e.MAC, e.IP, hostnames[e.MAC], now)
	}

	// Sort: unsubscribed + online first, then unsubscribed offline, then subscribed.
	sortDevices(devices)

	a.render(w, "admin_devices.html", a.adminCtx(r, "devices", map[string]any{
		"Iface":       iface,
		"Devices":     devices,
		"AutoRefresh": 30, // seconds
	}))
}

func sortDevices(d []deviceView) {
	// rank: lower is shown first
	rank := func(v deviceView) int {
		switch {
		case !v.Active && v.Online:
			return 0
		case !v.Active && !v.Online:
			return 1
		case v.Active && v.Online:
			return 2
		default:
			return 3
		}
	}
	// insertion sort — small lists, stable
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && rank(d[j]) < rank(d[j-1]); j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

// GET /admin/users/detail?id=<id>
//
// Per-user drill-down — everything we know about one account in one place:
// profile (phone, suspended, 2FA enabled), all owned MACs (active + expired),
// recent orders, active sessions, last 30 audit-log entries (both "user:<phone>"
// successes and "user-attempt:<phone>" failures).
//
// Designed for the support workflow: a customer calls, admin opens this page,
// can immediately see the relevant context without flipping between three other
// pages.
func (a *App) handleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	user, err := a.DB.GetUser(r.Context(), id)
	if err != nil || user == nil {
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	macs, _ := a.DB.ListMACsForUser(r.Context(), id)
	orders, _ := a.DB.ListOrdersForUser(r.Context(), id, 50)
	sessions, _ := a.DB.ListSessionsForUser(r.Context(), id)
	activity, _ := a.DB.SearchAudit(r.Context(), db.AuditFilter{
		Actor: ":" + user.Phone,
		Limit: 30,
	})
	backupCount := 0
	if user.TOTPSecret != "" {
		codes, _ := a.DB.ListBackupCodes(r.Context(), id)
		for _, c := range codes {
			if c.UsedAt == nil {
				backupCount++
			}
		}
	}
	trustedDevices, _ := a.DB.ListTrustedDevices(r.Context(), id)
	a.render(w, "admin_user_detail.html", a.adminCtx(r, "users", map[string]any{
		"User":            user,
		"MACs":            macs,
		"Orders":          orders,
		"Sessions":        sessions,
		"Activity":        formatActivity(activity),
		"BackupRemaining": backupCount,
		"TrustedDevices":  trustedDevices,
		"SMSAvailable":    a.SMS != nil && a.SMS.Available(),
		"SMSProvider": func() string {
			if a.SMS == nil {
				return "none"
			}
			return a.SMS.Name()
		}(),
	}))
}

// GET /admin/dashboard — landing page with today/week stats, attention
// counts, recent activity, and quick links. The previous "/admin" redirect
// pointed to /admin/macs, which is fine but buries the operational
// summary that admins look at every morning.
func (a *App) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	stats, _ := a.DB.Stats(r.Context())
	snap, _ := a.DB.DashboardSnapshot(r.Context())
	att, _ := a.DB.Attention(r.Context())
	planSales, _ := a.DB.PlanSalesSince(r.Context(), 30)
	recent, _ := a.DB.SearchAudit(r.Context(), db.AuditFilter{Limit: 10})

	a.render(w, "admin_dashboard.html", a.adminCtx(r, "dashboard", map[string]any{
		"Stats":     stats,
		"Snapshot":  snap,
		"Attention": att,
		"PlanSales": planSales,
		"Recent":    recent,
	}))
}

// /admin/users — list with optional ?q= phone search.
func (a *App) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	users, err := a.DB.SearchUsers(r.Context(), q, 200)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	macCount := map[int64]int{}
	macs, _ := a.DB.ListMACs(r.Context())
	for _, m := range macs {
		if m.UserID != nil {
			macCount[*m.UserID]++
		}
	}
	// Allow the template to read raw query params (e.g. flash data from
	// reset-password redirects). Keeps the data shape simple.
	rawQuery := map[string]string{}
	for k := range r.URL.Query() {
		rawQuery[k] = r.URL.Query().Get(k)
	}
	a.render(w, "admin_users.html", a.adminCtx(r, "users", map[string]any{
		"Users":        users,
		"MacCount":     macCount,
		"Query":        q,
		"Query0":       rawQuery,
		"SMSAvailable": a.SMS != nil && a.SMS.Available(),
		"SMSProvider": func() string {
			if a.SMS == nil {
				return "none"
			}
			return a.SMS.Name()
		}(),
	}))
}

// POST /admin/users/suspend  {id, suspended:0|1}
func (a *App) handleAdminUserSuspend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	suspend := r.PostForm.Get("suspended") == "1"
	if id == 0 {
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	if err := a.DB.SuspendUser(r.Context(), id, suspend); err != nil {
		log.Printf("suspend user %d: %v", id, err)
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	action := "user_unsuspend"
	detail := ""
	if suspend {
		action = "user_suspend"
		// SECURITY: also kill every active session for this user so they're
		// logged out immediately instead of staying authed until their
		// session naturally expires (could be ~30 days).
		killed, err := a.DB.DeleteSessionsByUserID(r.Context(), id)
		if err != nil {
			log.Printf("suspend user %d: kill sessions: %v", id, err)
		}
		detail = fmt.Sprintf("killed_sessions=%d", killed)
	}
	a.DB.Audit(r.Context(), "admin", action, strconv.FormatInt(id, 10), detail)
	http.Redirect(w, r, "/admin/users?ok=1", http.StatusSeeOther)
}

// POST /admin/users/reset-2fa  {id}
// Wipes the user's TOTP secret + any half-enrolled pending secret so a
// locked-out user (lost phone, no backup) can recover. Kills their sessions
// too — anyone holding an authed cookie on the old 2FA-enrolled session
// would otherwise keep working with no second factor.
func (a *App) handleAdminUserReset2FA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	user, _ := a.DB.GetUser(r.Context(), id)
	if user == nil {
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	if err := a.DB.ClearUserTOTP(r.Context(), id); err != nil {
		log.Printf("admin clear user totp %d: %v", id, err)
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	// Drop sessions defensively: cookie-stealing aside, an active
	// post-2FA session would lose its "extra factor" property silently.
	_, _ = a.DB.DeleteSessionsByUserID(r.Context(), id)
	a.DB.Audit(r.Context(), "admin", "user_reset_2fa", strconv.FormatInt(id, 10),
		"phone="+user.Phone+" ip="+clientIP(r))
	http.Redirect(w, r, "/admin/users?ok=reset_2fa&reset_uid="+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// POST /admin/users/reset-password  {id}
// Generates a random 10-char temporary password, updates the user's hash,
// invalidates all their sessions, returns the plain text via flash so the
// admin can hand it over (won't be displayed again).
func (a *App) handleAdminUserResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	tmpPwd := randomPassword(10)
	hash, err := bcryptHash(tmpPwd)
	if err != nil {
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	if err := a.DB.UpdateUserPassword(r.Context(), id, hash); err != nil {
		log.Printf("reset user %d password: %v", id, err)
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	// Invalidate any existing sessions so the old password is gone.
	_, _ = a.DB.Exec(r.Context(), `DELETE FROM sessions WHERE kind='user' AND user_id = ?`, id)

	// If SMS is configured AND the admin checked "send via SMS", deliver
	// the temp password to the user's phone instead of returning it in
	// the redirect query. Falls back to the existing inline-display path
	// when SMS isn't wired or delivery fails.
	if r.PostForm.Get("via_sms") == "1" && a.SMS != nil && a.SMS.Available() {
		if user, err := a.DB.GetUser(r.Context(), id); err == nil && user != nil {
			sErr := a.SMS.Send(r.Context(), user.Phone, tmpPwd)
			if sErr == nil {
				a.DB.Audit(r.Context(), "admin", "user_reset_password", strconv.FormatInt(id, 10),
					"via=sms provider="+a.SMS.Name()+" ip="+clientIP(r))
				http.Redirect(w, r, "/admin/users?ok=reset_sms&reset_uid="+strconv.FormatInt(id, 10), http.StatusSeeOther)
				return
			}
			log.Printf("reset-password sms %s: %v — falling back to inline display", user.Phone, sErr)
		}
	}
	a.DB.Audit(r.Context(), "admin", "user_reset_password", strconv.FormatInt(id, 10), "via=inline ip="+clientIP(r))
	http.Redirect(w, r, "/admin/users?reset_pwd="+url.QueryEscape(tmpPwd)+"&reset_uid="+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// POST /admin/users/delete  {id}
func (a *App) handleAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	if err := a.DB.DeleteUser(r.Context(), id); err != nil {
		log.Printf("delete user %d: %v", id, err)
		http.Redirect(w, r, "/admin/users?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "user_delete", strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/admin/users?ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminMACAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/macs", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.PostForm.Get("mac"))
	mac, ok := models.NormalizeMAC(raw)
	if !ok {
		http.Redirect(w, r, redirectBack(r, "err=invalid_mac"), http.StatusSeeOther)
		return
	}
	days, _ := strconv.Atoi(r.PostForm.Get("days"))
	if days <= 0 {
		if p, ok := a.effectivePlans(r.Context())[r.PostForm.Get("plan")]; ok {
			days = p.Days
		}
	}
	if days <= 0 {
		http.Redirect(w, r, redirectBack(r, "err=invalid_days"), http.StatusSeeOther)
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if label == "" {
		label = "manual"
	}
	if _, err := a.MACSvc.Extend(r.Context(), mac, label, days, nil); err != nil {
		log.Printf("admin extend %s: %v", mac, err)
		http.Redirect(w, r, redirectBack(r, "err=internal"), http.StatusSeeOther)
		return
	}
	ip := clientIP(r)
	a.DB.Audit(r.Context(), "admin", "grant", mac, fmt.Sprintf("days=%d label=%s ip=%s", days, label, ip))
	a.Notifier.Send(notify.Event{Type: "grant", Actor: "admin", MAC: mac, Days: days, Detail: label})
	http.Redirect(w, r, redirectBack(r, "ok=1"), http.StatusSeeOther)
}

func (a *App) handleAdminMACDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/macs", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	mac, ok := models.NormalizeMAC(r.PostForm.Get("mac"))
	if !ok {
		http.Redirect(w, r, redirectBack(r, "err=invalid_mac"), http.StatusSeeOther)
		return
	}
	if err := a.MACSvc.Delete(r.Context(), mac); err != nil {
		log.Printf("admin delete %s: %v", mac, err)
	}
	a.DB.Audit(r.Context(), "admin", "revoke", mac, "ip="+clientIP(r))
	a.Notifier.Send(notify.Event{Type: "revoke", Actor: "admin", MAC: mac})
	http.Redirect(w, r, redirectBack(r, "ok=1"), http.StatusSeeOther)
}

// POST /admin/macs/bulk  {action=delete|extend, days?, mac=...&mac=...}
func (a *App) handleAdminMACBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/macs", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	action := r.PostForm.Get("action")
	rawMacs := r.PostForm["mac"]
	if len(rawMacs) == 0 || action == "" {
		http.Redirect(w, r, "/admin/macs", http.StatusSeeOther)
		return
	}
	macs := make([]string, 0, len(rawMacs))
	for _, m := range rawMacs {
		if norm, ok := models.NormalizeMAC(m); ok {
			macs = append(macs, norm)
		}
	}
	if len(macs) == 0 {
		http.Redirect(w, r, "/admin/macs?err=invalid_mac", http.StatusSeeOther)
		return
	}
	var ok, fail int
	switch action {
	case "delete":
		for _, m := range macs {
			if err := a.MACSvc.Delete(r.Context(), m); err != nil {
				log.Printf("bulk delete %s: %v", m, err)
				fail++
			} else {
				ok++
			}
		}
	case "extend":
		days, _ := strconv.Atoi(r.PostForm.Get("days"))
		if days <= 0 {
			http.Redirect(w, r, "/admin/macs?err=invalid_days", http.StatusSeeOther)
			return
		}
		for _, m := range macs {
			if _, err := a.MACSvc.Extend(r.Context(), m, "", days, nil); err != nil {
				log.Printf("bulk extend %s: %v", m, err)
				fail++
			} else {
				ok++
			}
		}
	default:
		http.Redirect(w, r, "/admin/macs?err=invalid_days", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "bulk_"+action, "",
		fmt.Sprintf("ok=%d fail=%d", ok, fail))
	http.Redirect(w, r, fmt.Sprintf("/admin/macs?ok=bulk&ok_n=%d&fail_n=%d", ok, fail), http.StatusSeeOther)
}

func (a *App) handleAdminMACExtend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/macs", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	mac, ok := models.NormalizeMAC(r.PostForm.Get("mac"))
	if !ok {
		http.Redirect(w, r, redirectBack(r, "err=invalid_mac"), http.StatusSeeOther)
		return
	}
	days, _ := strconv.Atoi(r.PostForm.Get("days"))
	if days == 0 {
		if p, ok := a.effectivePlans(r.Context())[r.PostForm.Get("plan")]; ok {
			days = p.Days
		}
	}
	if days <= 0 {
		http.Redirect(w, r, redirectBack(r, "err=invalid_days"), http.StatusSeeOther)
		return
	}
	if _, err := a.MACSvc.Extend(r.Context(), mac, "", days, nil); err != nil {
		log.Printf("admin extend %s: %v", mac, err)
		http.Redirect(w, r, redirectBack(r, "err=internal"), http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "extend", mac,
		"days="+strconv.Itoa(days)+" ip="+clientIP(r))
	http.Redirect(w, r, redirectBack(r, "ok=1"), http.StatusSeeOther)
}

// POST /admin/macs/revoke  {mac}
//
// Marks a MAC as `blocked` and removes it from the firewall set without
// deleting the row. Useful for "this MAC is connected with abuse — drop
// it from paid access but keep the audit trail and any associated
// orders". Reversible: a fresh payment / extend will flip it back to
// active and re-add it to the firewall.
func (a *App) handleAdminMACRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/macs", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	mac, ok := models.NormalizeMAC(r.PostForm.Get("mac"))
	if !ok {
		http.Redirect(w, r, redirectBack(r, "err=invalid_mac"), http.StatusSeeOther)
		return
	}
	if err := a.MACSvc.Revoke(r.Context(), mac); err != nil {
		log.Printf("admin revoke %s: %v", mac, err)
		http.Redirect(w, r, redirectBack(r, "err=internal"), http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "revoke", mac, "ip="+clientIP(r))
	http.Redirect(w, r, redirectBack(r, "ok=revoked"), http.StatusSeeOther)
}

func (a *App) handleAdminOrders(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	var orders []models.Order
	var err error
	if q == "" && status == "" {
		orders, err = a.DB.ListOrders(r.Context(), 200)
	} else {
		orders, err = a.DB.SearchOrders(r.Context(), q, status, 500)
	}
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	a.render(w, "admin_orders.html", a.adminCtx(r, "orders", map[string]any{
		"Orders": orders,
		"Query":  q,
		"Status": status,
	}))
}

// POST /admin/orders/refund  {order_no, confirm_order_no, reason?}
//
// Marks a paid order as refunded AND rolls back the MAC's expires_at by
// the order's `days` value (so a refund of a 30-day order pulls 30 days
// off the MAC's clock). The actual gateway-side refund is out of band —
// this handler just records the local-state transition once the merchant
// has confirmed the upstream refund is done.
//
// Anti-fat-finger: the form must include `confirm_order_no` matching the
// order_no exactly. The admin_orders.html template uses JS to demand the
// user type it.
func (a *App) handleAdminOrderRefund(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/orders", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	orderNo := strings.TrimSpace(r.PostForm.Get("order_no"))
	confirm := strings.TrimSpace(r.PostForm.Get("confirm_order_no"))
	reason := strings.TrimSpace(r.PostForm.Get("reason"))
	if orderNo == "" || orderNo != confirm {
		http.Redirect(w, r, "/admin/orders?err=refund_confirm", http.StatusSeeOther)
		return
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	mac, err := a.DB.MarkOrderRefunded(r.Context(), orderNo, reason)
	if err != nil {
		log.Printf("refund %s: %v", orderNo, err)
		// Surface the error type so admins see "order is already refunded"
		// vs. "order not found" — pretty straightforward triage.
		msg := "refund_failed"
		if strings.Contains(err.Error(), "not found") {
			msg = "refund_no_order"
		} else if strings.Contains(err.Error(), "only paid") {
			msg = "refund_not_paid"
		}
		http.Redirect(w, r, "/admin/orders?err="+msg, http.StatusSeeOther)
		return
	}
	// If the MAC was rolled back into the past, the firewall reconciler
	// needs a kick to revoke it from the active set immediately.
	if mac != nil && mac.Status == models.MACExpired {
		go func(macStr string) {
			ctx := context.Background()
			if err := a.MACSvc.Resync(ctx); err != nil {
				log.Printf("refund post-resync: %v", err)
			} else {
				log.Printf("refund: %s expired and removed from firewall", macStr)
			}
		}(mac.Mac)
	}
	a.DB.Audit(r.Context(), "admin", "order_refunded", orderNo,
		"reason="+reason+" ip="+clientIP(r))
	http.Redirect(w, r, "/admin/orders?ok=refunded", http.StatusSeeOther)
}

func (a *App) handleAdminResync(w http.ResponseWriter, r *http.Request) {
	if err := a.MACSvc.Resync(r.Context()); err != nil {
		log.Printf("admin resync: %v", err)
		a.DB.Audit(r.Context(), "admin", "firewall_resync_failed", "", "err="+err.Error()+" ip="+clientIP(r))
		http.Redirect(w, r, "/admin/macs?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "firewall_resync", "", "ip="+clientIP(r))
	http.Redirect(w, r, "/admin/macs?ok=1", http.StatusSeeOther)
}

// redirectBack returns the Referer's path (only if it's /admin/*) with a
// query suffix, falling back to /admin/macs. Used so a form on /admin/devices
// returns to /admin/devices after submit, while a form on /admin/macs returns
// to /admin/macs.
func redirectBack(r *http.Request, qs string) string {
	target := "/admin/macs"
	if u, err := url.Parse(r.Referer()); err == nil {
		p := u.Path
		if strings.HasPrefix(p, "/admin/") && !strings.Contains(p, "..") {
			target = p
		}
	}
	if qs == "" {
		return target
	}
	return target + "?" + qs
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
