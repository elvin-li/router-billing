package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"router-billing/internal/config"
	"router-billing/internal/db"
	"router-billing/internal/models"
	"router-billing/internal/notify"
	"router-billing/internal/pay"
	"router-billing/internal/service"
	"router-billing/internal/sms"
)

type App struct {
	Cfg      *config.Config
	DB       *db.DB
	MACSvc   *service.MACService
	WeChat   *pay.WeChat // nil if disabled
	Alipay   *pay.Alipay // nil if disabled
	Notifier *notify.Notifier
	SMS      *sms.Sender // wraps a possibly-nil Provider; check .Available()
	Version  string
	StartAt  time.Time
	tpl      *template.Template

	pollMu            sync.Mutex
	loginLimiter      *rateLimiter // user login, keyed by IP
	loginByPhoneLimit *rateLimiter // user login, keyed by phone
	registerLimiter   *rateLimiter
	adminLoginLimiter *rateLimiter // admin login, keyed by IP
	adminLoginByUser  *rateLimiter // admin login, keyed by username (defeats IP rotation)
	redeemLimiter     *rateLimiter // voucher redemption, keyed by IP
	payCreateLimiter  *rateLimiter // payment intent creation, keyed by IP

	// Forgot-password (SMS) — separate counters from login so a hostile actor
	// can't burn the legitimate user's login budget by spamming reset requests.
	pwResetIssueIPLimit    *rateLimiter // /user/forgot-password POST, keyed by IP
	pwResetIssuePhoneLimit *rateLimiter // /user/forgot-password POST, keyed by phone
	pwResetVerifyIPLimit   *rateLimiter // /user/forgot-password/verify, keyed by IP
	pwResetVerifyPhoneLim  *rateLimiter // /user/forgot-password/verify, keyed by phone

	// apiTokenLimiter is keyed by token label. Built lazily on first use
	// of each token (so a config with 50 tokens doesn't allocate 50
	// limiters that may never see traffic). nil → no limit configured.
	apiTokenLimiterMu sync.Mutex
	apiTokenLimiter   map[string]*rateLimiter

	waitMu  sync.Mutex
	waiters map[string][]chan struct{} // order_no → pending wait channels

	// One-time flash values (see flash.go) — secrets that must survive
	// exactly one POST-redirect-GET hop without touching the URL.
	flashMu sync.Mutex
	flashes map[string]flashEntry

	// trustedProxies is parsed once from config security.trusted_proxies.
	// clientIP only honors X-Forwarded-For when the TCP peer is in here.
	trustedProxies []*net.IPNet
}

func NewApp(cfg *config.Config, dbx *db.DB, svc *service.MACService) (*App, error) {
	app := &App{
		Cfg:               cfg,
		DB:                dbx,
		MACSvc:            svc,
		Notifier:          notify.New(cfg.Webhook.URL, cfg.Webhook.Secret),
		SMS:               buildSMSSender(cfg.SMS),
		StartAt:           time.Now(),
		loginLimiter:      newRateLimiter(8, 5*time.Minute),
		loginByPhoneLimit: newRateLimiter(5, 5*time.Minute),
		registerLimiter:   newRateLimiter(4, 1*time.Hour),
		adminLoginLimiter: newRateLimiter(8, 5*time.Minute),
		adminLoginByUser:  newRateLimiter(5, 5*time.Minute),
		redeemLimiter:     newRateLimiter(10, 10*time.Minute),
		payCreateLimiter:  newRateLimiter(20, time.Minute),

		pwResetIssueIPLimit:    newRateLimiter(6, 1*time.Hour),
		pwResetIssuePhoneLimit: newRateLimiter(3, 1*time.Hour),
		pwResetVerifyIPLimit:   newRateLimiter(30, 1*time.Hour),
		pwResetVerifyPhoneLim:  newRateLimiter(10, 1*time.Hour),

		apiTokenLimiter: map[string]*rateLimiter{},

		waiters: map[string][]chan struct{}{},
		flashes: map[string]flashEntry{},
	}

	// Validated at config load already; re-parse here to wire the value in.
	proxies, err := cfg.Security.TrustedProxyNets()
	if err != nil {
		return nil, fmt.Errorf("trusted proxies: %w", err)
	}
	app.trustedProxies = proxies

	// Wire the v0.49 webhook delivery logger: every Notifier attempt
	// (initial + each retry) lands a row in webhook_deliveries so
	// /admin/webhook-log can show the operator what's been happening.
	// Background context — the request that triggered the notification
	// may have completed long before the retry, and the row should land
	// either way.
	if app.Notifier != nil {
		app.Notifier.OnDelivery = func(ev notify.Event, attempt, status int, durationMs int64, err error) {
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			_ = app.DB.LogWebhookDelivery(context.Background(),
				ev.Type, ev.MAC, attempt, status, err == nil, durationMs, errMsg)
		}
	}

	if cfg.Pay.WeChat.Enabled {
		w, err := pay.NewWeChat(
			cfg.Pay.WeChat.MchID,
			cfg.Pay.WeChat.AppID,
			cfg.Pay.WeChat.APIv3Key,
			cfg.Pay.WeChat.SerialNo,
			cfg.Pay.WeChat.PrivateKeyPath,
			cfg.Pay.WeChat.NotifyURL,
		)
		if err != nil {
			return nil, fmt.Errorf("init wechat: %w", err)
		}
		app.WeChat = w
	}
	if cfg.Pay.Alipay.Enabled {
		a, err := pay.NewAlipay(
			cfg.Pay.Alipay.AppID,
			cfg.Pay.Alipay.PrivateKeyPath,
			cfg.Pay.Alipay.AlipayPublicKeyPath,
			cfg.Pay.Alipay.NotifyURL,
			cfg.Pay.Alipay.Gateway,
		)
		if err != nil {
			return nil, fmt.Errorf("init alipay: %w", err)
		}
		app.Alipay = a
	}

	tplGlob := filepath.Join(cfg.WebRoot, "templates", "*.html")
	tpl, err := template.New("").Funcs(tplFuncs()).ParseGlob(tplGlob)
	if err != nil {
		return nil, fmt.Errorf("parse templates %s: %w", tplGlob, err)
	}
	app.tpl = tpl
	return app, nil
}

func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()

	// Captive-portal probes — non-whitelisted clients land here via nftables.
	mux.HandleFunc("/", a.handlePortal)
	mux.HandleFunc("/portal", a.handlePortal)
	mux.HandleFunc("/generate_204", a.handlePortal)        // Android
	mux.HandleFunc("/gen_204", a.handlePortal)             // Android (newer)
	mux.HandleFunc("/hotspot-detect.html", a.handlePortal) // iOS
	mux.HandleFunc("/library/test/success.html", a.handlePortal)
	mux.HandleFunc("/ncsi.txt", a.handlePortal)        // Windows
	mux.HandleFunc("/connecttest.txt", a.handlePortal) // Windows

	// API for the portal page
	mux.HandleFunc("/api/pay/create", a.handlePayCreate)
	mux.HandleFunc("/api/pay/status", a.handlePayStatus)
	mux.HandleFunc("/api/pay/wait", a.handlePayWait) // long-poll, beats 2s tick
	mux.HandleFunc("/api/pay/qr", a.handlePayQR)
	mux.HandleFunc("/api/me", a.handleMe)

	mux.HandleFunc("/pay/success", a.handlePaySuccess)
	mux.HandleFunc("/receipt", a.handleReceipt)

	// Webhooks (optional — see /api/pay/status for the no-HTTPS fallback)
	mux.HandleFunc("/notify/wx", a.handleNotifyWeChat)
	mux.HandleFunc("/notify/ali", a.handleNotifyAlipay)

	// User
	mux.HandleFunc("/user/login", a.handleUserLogin)
	mux.HandleFunc("/user/register", a.handleUserRegister)
	mux.HandleFunc("/user/logout", a.handleUserLogout)
	mux.HandleFunc("/user/forgot-password", a.handleUserForgotPassword)
	mux.HandleFunc("/user/forgot-password/verify", a.handleUserForgotPasswordVerify)
	mux.HandleFunc("/user/login/2fa", a.handleUserLogin2FA)
	mux.HandleFunc("/user/2fa", a.requireUser(a.handleUser2FA))
	mux.HandleFunc("/user/2fa/begin", a.requireUser(a.handleUser2FABegin))
	mux.HandleFunc("/user/2fa/confirm", a.requireUser(a.handleUser2FAConfirm))
	mux.HandleFunc("/user/2fa/disable", a.requireUser(a.handleUser2FADisable))
	mux.HandleFunc("/user/2fa/qr", a.requireUser(a.handleUser2FAQR))
	mux.HandleFunc("/user/2fa/regenerate-codes", a.requireUser(a.handleUser2FARegenerateCodes))
	mux.HandleFunc("/user/2fa/trusted-devices/revoke", a.requireUser(a.handleUserTrustedDeviceRevoke))
	mux.HandleFunc("/user/2fa/trusted-devices/revoke-all", a.requireUser(a.handleUserTrustedDeviceRevokeAll))
	mux.HandleFunc("/user/me", a.requireUser(a.handleUserMe))
	mux.HandleFunc("/user/macs/replace", a.requireUser(a.handleUserReplaceMAC))
	mux.HandleFunc("/user/macs/claim", a.requireUser(a.handleUserClaimMAC))
	mux.HandleFunc("/user/password", a.requireUser(a.handleUserPassword))
	mux.HandleFunc("/user/sessions/sign-out-others", a.requireUser(a.handleUserSignOutOthers))
	mux.HandleFunc("/user/account/delete", a.requireUser(a.handleUserAccountDelete))
	mux.HandleFunc("/user/account/export", a.requireUser(a.handleUserAccountExport))
	mux.HandleFunc("/user/notifications", a.requireUser(a.handleUserNotificationPrefs))

	// Admin
	mux.HandleFunc("/admin", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
	}))
	mux.HandleFunc("/admin/dashboard", a.requireAdmin(a.handleAdminDashboard))
	mux.HandleFunc("/admin/login", a.handleAdminLogin)
	mux.HandleFunc("/admin/login/2fa", a.handleAdminLogin2FA)
	mux.HandleFunc("/admin/logout", a.handleAdminLogout)
	mux.HandleFunc("/admin/macs", a.requireAdmin(a.handleAdminMACs))
	mux.HandleFunc("/admin/macs/detail", a.requireAdmin(a.handleAdminMACDetail))
	mux.HandleFunc("/admin/macs/notes", a.requireAdmin(a.handleAdminMACNotes))
	mux.HandleFunc("/admin/macs/add", a.requireAdmin(a.handleAdminMACAdd))
	mux.HandleFunc("/admin/macs/delete", a.requireAdmin(a.handleAdminMACDelete))
	mux.HandleFunc("/admin/macs/extend", a.requireAdmin(a.handleAdminMACExtend))
	mux.HandleFunc("/admin/macs/revoke", a.requireAdmin(a.handleAdminMACRevoke))
	mux.HandleFunc("/admin/macs/bulk", a.requireAdmin(a.handleAdminMACBulk))
	mux.HandleFunc("/admin/macs/schedule", a.requireAdmin(a.handleAdminMACSchedule))
	mux.HandleFunc("/admin/devices", a.requireAdmin(a.handleAdminDevices))
	mux.HandleFunc("/admin/orders", a.requireAdmin(a.handleAdminOrders))
	mux.HandleFunc("/admin/orders/detail", a.requireAdmin(a.handleAdminOrderDetail))
	mux.HandleFunc("/admin/orders/refund", a.requireAdmin(a.handleAdminOrderRefund))
	mux.HandleFunc("/admin/orders/cancel", a.requireAdmin(a.handleAdminOrderCancel))
	mux.HandleFunc("/admin/orders/cancel-stale", a.requireAdmin(a.handleAdminOrderCancelStale))
	mux.HandleFunc("/admin/users", a.requireAdmin(a.handleAdminUsers))
	mux.HandleFunc("/admin/users/detail", a.requireAdmin(a.handleAdminUserDetail))
	mux.HandleFunc("/admin/users/suspend", a.requireAdmin(a.handleAdminUserSuspend))
	mux.HandleFunc("/admin/users/delete", a.requireAdmin(a.handleAdminUserDelete))
	mux.HandleFunc("/admin/users/reset-password", a.requireAdmin(a.handleAdminUserResetPassword))
	mux.HandleFunc("/admin/users/reset-2fa", a.requireAdmin(a.handleAdminUserReset2FA))
	mux.HandleFunc("/admin/audit", a.requireAdmin(a.handleAdminAudit))
	mux.HandleFunc("/admin/audit/note", a.requireAdmin(a.handleAdminAuditNote))
	mux.HandleFunc("/admin/sessions", a.requireAdmin(a.handleAdminSessions))
	mux.HandleFunc("/admin/sessions/revoke", a.requireAdmin(a.handleAdminSessionRevoke))
	mux.HandleFunc("/admin/sessions/revoke-all-admin", a.requireAdmin(a.handleAdminSessionRevokeAllAdmin))
	mux.HandleFunc("/admin/sessions/panic", a.requireAdmin(a.handleAdminSessionPanic))
	mux.HandleFunc("/admin/health", a.requireAdmin(a.handleAdminHealth))
	mux.HandleFunc("/admin/backup", a.requireAdmin(a.handleAdminBackup))
	mux.HandleFunc("/admin/backup/restore", a.requireAdmin(a.handleAdminBackupRestore))
	mux.HandleFunc("/admin/maintenance", a.requireAdmin(a.handleAdminMaintenance))
	mux.HandleFunc("/admin/webhook-log", a.requireAdmin(a.handleAdminWebhookLog))
	mux.HandleFunc("/admin/maintenance/test-webhook", a.requireAdmin(a.handleAdminTestWebhook))
	mux.HandleFunc("/admin/maintenance/expire-now", a.requireAdmin(a.handleAdminExpireNow))
	mux.HandleFunc("/admin/maintenance/audit-trim", a.requireAdmin(a.handleAdminAuditTrim))
	mux.HandleFunc("/admin/maintenance/optimize-now", a.requireAdmin(a.handleAdminOptimizeNow))
	mux.HandleFunc("/admin/maintenance/sms-log-trim", a.requireAdmin(a.handleAdminSMSLogTrim))
	mux.HandleFunc("/admin/maintenance/webhook-log-trim", a.requireAdmin(a.handleAdminWebhookLogTrim))
	mux.HandleFunc("/admin/sms-log", a.requireAdmin(a.handleAdminSMSLog))
	mux.HandleFunc("/admin/api-tokens", a.requireAdmin(a.handleAdminAPITokens))
	mux.HandleFunc("/admin/sms-log/test", a.requireAdmin(a.handleAdminSMSTest))
	mux.HandleFunc("/admin/sms-log/expiry-reminders", a.requireAdmin(a.handleAdminExpiryReminderTrigger))
	mux.HandleFunc("/admin/sms-log/digest", a.requireAdmin(a.handleAdminDigestTrigger))
	mux.HandleFunc("/admin/ssid-cards", a.requireAdmin(a.handleAdminSSIDCards))
	mux.HandleFunc("/admin/ssid-cards/qr", a.requireAdmin(a.handleAdminSSIDCardQR))
	mux.HandleFunc("/admin/devices/stream", a.requireAdmin(a.handleAdminDevicesStream))
	mux.HandleFunc("/admin/resync", a.requireAdmin(a.handleAdminResync))
	mux.HandleFunc("/admin/macs/import", a.requireAdmin(a.handleAdminMACImport))
	mux.HandleFunc("/admin/export/macs.csv", a.requireAdmin(a.handleAdminExportMACs))
	mux.HandleFunc("/admin/export/orders.csv", a.requireAdmin(a.handleAdminExportOrders))
	mux.HandleFunc("/admin/export/users.csv", a.requireAdmin(a.handleAdminExportUsers))
	mux.HandleFunc("/admin/export/audit.csv", a.requireAdmin(a.handleAdminExportAudit))
	mux.HandleFunc("/admin/export/sms-log.csv", a.requireAdmin(a.handleAdminExportSMSLog))
	mux.HandleFunc("/admin/export/webhook-log.csv", a.requireAdmin(a.handleAdminExportWebhookLog))

	// Public-but-tokened metrics endpoint
	mux.HandleFunc("/metrics", a.handleMetrics)

	// Public health endpoint — no auth, for load balancers / uptime
	// monitors / k8s readiness probes. Returns 200 if the DB ping
	// succeeds, 503 otherwise. /healthz is the k8s convention alias.
	mux.HandleFunc("/health", a.handlePublicHealth)
	mux.HandleFunc("/healthz", a.handlePublicHealth)

	// Programmatic admin API — Bearer tokens from config.api_tokens.
	// requireAPITokenRead accepts any token; requireAPITokenWrite blocks
	// tokens with `readonly: true` from mutating endpoints.
	mux.HandleFunc("/api/admin/health", a.requireAPITokenRead(a.handleAPIHealth))
	mux.HandleFunc("/api/admin/version", a.requireAPITokenRead(a.handleAPIVersion))
	mux.HandleFunc("/api/admin/dashboard", a.requireAPITokenRead(a.handleAPIDashboard))
	mux.HandleFunc("/api/admin/sightings", a.requireAPITokenRead(a.handleAPISightings))
	mux.HandleFunc("/api/admin/sessions", a.requireAPITokenRead(a.handleAPISessions))
	mux.HandleFunc("/api/admin/audit/distinct", a.requireAPITokenRead(a.handleAPIAuditDistinct))
	mux.HandleFunc("/api/admin/audit/totals", a.requireAPITokenRead(a.handleAPIAuditTotals))
	mux.HandleFunc("/api/admin/backup", a.requireAPITokenRead(a.handleAPIBackup))
	mux.HandleFunc("/api/admin/macs", a.requireAPITokenRead(a.handleAPIMACList))
	mux.HandleFunc("/api/admin/macs/get", a.requireAPITokenRead(a.handleAPIMACGet))
	mux.HandleFunc("/api/admin/users", a.requireAPITokenRead(a.handleAPIUserList))
	mux.HandleFunc("/api/admin/orders", a.requireAPITokenRead(a.handleAPIOrderList))
	mux.HandleFunc("/api/admin/orders/get", a.requireAPITokenRead(a.handleAPIOrderGet))
	mux.HandleFunc("/api/admin/audit", a.requireAPITokenRead(a.handleAPIAuditList))
	mux.HandleFunc("/api/admin/sms/log", a.requireAPITokenRead(a.handleAPISMSLog))
	mux.HandleFunc("/api/admin/webhook/log", a.requireAPITokenRead(a.handleAPIWebhookLog))
	mux.HandleFunc("/api/admin/vouchers", a.requireAPITokenRead(a.handleAPIVoucherList))
	mux.HandleFunc("/api/admin/macs/grant", a.requireAPITokenWrite(a.handleAPIMACGrant))
	mux.HandleFunc("/api/admin/macs/revoke", a.requireAPITokenWrite(a.handleAPIMACRevoke))
	mux.HandleFunc("/api/admin/macs/import", a.requireAPITokenWrite(a.handleAPIMACImport))
	mux.HandleFunc("/api/admin/macs/notes", a.requireAPITokenWrite(a.handleAPIMACNotes))
	mux.HandleFunc("/api/admin/macs/label", a.requireAPITokenWrite(a.handleAPIMACLabel))
	mux.HandleFunc("/api/admin/sms/send", a.requireAPITokenWrite(a.handleAPISMSSend))
	mux.HandleFunc("/api/admin/orders/refund", a.requireAPITokenWrite(a.handleAPIOrderRefund))
	mux.HandleFunc("/api/admin/orders/cancel", a.requireAPITokenWrite(a.handleAPIOrderCancel))
	mux.HandleFunc("/api/admin/orders/cancel-stale", a.requireAPITokenWrite(a.handleAPIOrderCancelStale))
	mux.HandleFunc("/api/admin/vouchers/generate", a.requireAPITokenWrite(a.handleAPIVoucherGenerate))
	mux.HandleFunc("/api/admin/vouchers/batch/revoke", a.requireAPITokenWrite(a.handleAPIVoucherBatchRevoke))
	mux.HandleFunc("/api/admin/users/grant", a.requireAPITokenWrite(a.handleAPIUserGrant))
	mux.HandleFunc("/api/admin/users/notify-expiry", a.requireAPITokenWrite(a.handleAPIUserNotifyExpiry))
	mux.HandleFunc("/api/admin/users/suspend", a.requireAPITokenWrite(a.handleAPIUserSuspend))
	mux.HandleFunc("/api/admin/users/grant-by-phone", a.requireAPITokenWrite(a.handleAPIUserGrantByPhone))
	mux.HandleFunc("/api/admin/webhook/test", a.requireAPITokenWrite(a.handleAPIWebhookTest))
	mux.HandleFunc("/api/admin/audit/note", a.requireAPITokenWrite(a.handleAPIAuditNote))
	mux.HandleFunc("/api/admin/maintenance/expire-now", a.requireAPITokenWrite(a.handleAPIExpireNow))
	mux.HandleFunc("/api/admin/maintenance/audit-trim", a.requireAPITokenWrite(a.handleAPIAuditTrim))
	mux.HandleFunc("/api/admin/maintenance/optimize-now", a.requireAPITokenWrite(a.handleAPIOptimizeNow))
	mux.HandleFunc("/api/admin/plans", a.requireAPITokenRead(a.handleAPIPlanList))
	mux.HandleFunc("/api/admin/plans/sales", a.requireAPITokenRead(a.handleAPIPlansSales))
	mux.HandleFunc("/api/admin/plans/save", a.requireAPITokenWrite(a.handleAPIPlanSave))
	mux.HandleFunc("/api/admin/plans/delete", a.requireAPITokenWrite(a.handleAPIPlanDelete))

	// User extras
	mux.HandleFunc("/user/macs/label", a.requireUser(a.handleUserLabelMAC))

	// Voucher (redemption code) flows
	mux.HandleFunc("/redeem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			a.handleRedeem(w, r)
			return
		}
		a.handleRedeemPage(w, r)
	})
	mux.HandleFunc("/admin/vouchers", a.requireAdmin(a.handleAdminVouchers))
	mux.HandleFunc("/admin/vouchers/generate", a.requireAdmin(a.handleAdminVouchersGenerate))
	mux.HandleFunc("/admin/vouchers/import", a.requireAdmin(a.handleAdminVouchersImport))
	mux.HandleFunc("/admin/vouchers/revoke", a.requireAdmin(a.handleAdminVouchersRevoke))
	mux.HandleFunc("/admin/vouchers/batch/revoke", a.requireAdmin(a.handleAdminVoucherBatchRevoke))
	mux.HandleFunc("/admin/vouchers/export.csv", a.requireAdmin(a.handleAdminVouchersExport))
	mux.HandleFunc("/admin/vouchers/print", a.requireAdmin(a.handleAdminVouchersPrint))
	mux.HandleFunc("/admin/vouchers/print/qr", a.requireAdmin(a.handleAdminVouchersPrintQR))

	// Plan management UI
	mux.HandleFunc("/admin/plans", a.requireAdmin(a.handleAdminPlans))
	mux.HandleFunc("/admin/plans/save", a.requireAdmin(a.handleAdminPlanSave))
	mux.HandleFunc("/admin/plans/delete", a.requireAdmin(a.handleAdminPlanDelete))

	// Sparkline data for dashboard
	mux.HandleFunc("/admin/charts.json", a.requireAdmin(a.handleAdminCharts))
	// Live dashboard stats over SSE
	mux.HandleFunc("/admin/stats/stream", a.requireAdmin(a.handleAdminStatsStream))

	// Static
	staticDir := filepath.Join(a.Cfg.WebRoot, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	// Service worker needs to be served from the root for scope '/'.
	mux.HandleFunc("/sw.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-cache") // never stale
		http.ServeFile(w, r, filepath.Join(staticDir, "sw.js"))
	})

	return a.securityHeaders(csrfMiddleware(logMiddleware(mux)))
}

func (a *App) Run(ctx context.Context) error {
	// Background goroutines that the App owns.
	go a.PollPendingOrders(ctx, 4*time.Second)
	go a.purgeLoop(ctx)
	go a.Notifier.Run(ctx)
	go a.expiryReminderLoop(ctx)
	go a.adminDigestLoop(ctx)

	srv := &http.Server{
		Addr:              a.Cfg.Listen,
		Handler:           a.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("http listening on %s", a.Cfg.Listen)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// purgeLoop keeps housekeeping tables small and runs SQLite maintenance.
func (a *App) purgeLoop(ctx context.Context) {
	short := time.NewTicker(2 * time.Hour)
	defer short.Stop()
	// Weekly: PRAGMA optimize (cheap, recommended in SQLite docs) and VACUUM
	// (reclaim pages from churn — voucher batches, audit purges, etc.).
	weekly := time.NewTicker(7 * 24 * time.Hour)
	defer weekly.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-short.C:
			_ = a.DB.PurgeExpiredSessions(ctx)
			_ = a.DB.PurgeAuditLog(ctx, a.Cfg.Security.AuditLogRetention())
			// SMS log gets the same retention cap as audit_log — both are
			// observability tables that accumulate forever otherwise.
			_ = a.DB.PurgeSMSLog(ctx, a.Cfg.Security.AuditLogRetention())
			// Webhook delivery log (v0.49) uses the same retention cap.
			_ = a.DB.PurgeWebhookDeliveries(ctx, a.Cfg.Security.AuditLogRetention())
			// These three were added in v0.13 (password reset codes,
			// trusted devices) but never plumbed into the janitor — so
			// stale rows accumulated until the user manually
			// re-triggered the flow. Tidy up here too.
			_ = a.DB.PurgeExpiredPasswordResets(ctx)
			_ = a.DB.PurgeExpiredTrustedDevices(ctx)
			// v0.60: auto-cancel stale pending orders if enabled. Skip
			// the audit row when count=0 to avoid the periodic-noop
			// audit-spam an enabled background sweep would otherwise
			// generate.
			if hours := a.Cfg.Security.AutoCancelStaleOrders(); hours > 0 {
				if n, err := a.DB.CancelStalePendingOrders(ctx, time.Duration(hours)*time.Hour); err == nil && n > 0 {
					a.DB.Audit(ctx, "system", "orders_cancel_stale", "",
						fmt.Sprintf("count=%d hours=%d via=purge_loop", n, hours))
				} else if err != nil {
					log.Printf("auto cancel stale: %v", err)
				}
			}
		case <-weekly.C:
			if _, err := a.DB.Exec(ctx, "PRAGMA optimize"); err != nil {
				log.Printf("sqlite optimize: %v", err)
			}
			if _, err := a.DB.Exec(ctx, "VACUUM"); err != nil {
				log.Printf("sqlite vacuum: %v", err)
			}
		}
	}
}

// auditTargetHref returns the smart drill-down URL for an audit target
// string, or "" if the target doesn't fit a known shape. v0.92 / v0.95.
//
// Shapes:
//   - MAC (NormalizeMAC accepts it)                    → /admin/macs/detail?mac=...
//   - "ORD" / "ord" prefix                             → /admin/orders/detail?order_no=...
//   - 11-digit starts-with-1 (CN mobile)               → /admin/sms-log?phone=...
//   - pure digits, 1-9 chars (user_id from user_grant) → /admin/users/detail?id=N
//   - anything else                                     → "" (plain text)
//
// Precedence: MAC → order → phone → user_id. A 11-digit string that
// starts with 1 routes to phone (the more common case in audit detail).
func auditTargetHref(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	// MAC?
	if mac, ok := models.NormalizeMAC(target); ok {
		return "/admin/macs/detail?mac=" + mac
	}
	// Order number — either the legacy "ORD"/"ord" prefix or the real
	// shape newOrderNo() emits: "B" + 14-digit UTC timestamp + 8 hex
	// chars (e.g. B20260824190000a1b2c3d4). The refund/cancel audit rows
	// use these as targets, so without this branch they rendered as
	// plain text.
	if strings.HasPrefix(target, "ORD") || strings.HasPrefix(target, "ord") || looksLikeOrderNo(target) {
		return "/admin/orders/detail?order_no=" + target
	}
	// All-digit shapes: 11-digit starts-with-1 → phone; 1-9 digits → user_id.
	allDigits := true
	for _, c := range target {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		if len(target) == 11 && target[0] == '1' {
			return "/admin/sms-log?phone=" + target
		}
		if len(target) >= 1 && len(target) <= 9 {
			return "/admin/users/detail?id=" + target
		}
	}
	return ""
}

// looksLikeOrderNo reports whether s matches the exact shape newOrderNo()
// generates: 'B' + 14 digits (yyyymmddhhmmss) + 8 lowercase hex chars.
func looksLikeOrderNo(s string) bool {
	if len(s) != 23 || s[0] != 'B' {
		return false
	}
	for _, c := range s[1:15] {
		if c < '0' || c > '9' {
			return false
		}
	}
	for _, c := range s[15:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func tplFuncs() template.FuncMap {
	return template.FuncMap{
		"auditTargetHref": auditTargetHref,
		"formatYuan": func(cents int) string {
			return fmt.Sprintf("%d.%02d", cents/100, cents%100)
		},
		"minusOne": func(n int) int { return n - 1 },
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"formatTimePtr": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"daysLeft": func(t time.Time) string {
			d := time.Until(t)
			if d <= 0 {
				return "已过期"
			}
			days := int(d.Hours() / 24)
			if days >= 1 {
				return fmt.Sprintf("%d 天", days)
			}
			hours := int(d.Hours())
			if hours >= 1 {
				return fmt.Sprintf("%d 小时", hours)
			}
			return "< 1 小时"
		},
		"ago": func(t time.Time) string {
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return fmt.Sprintf("%d 秒前", int(d.Seconds()))
			case d < time.Hour:
				return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
			case d < 24*time.Hour:
				return fmt.Sprintf("%d 小时前", int(d.Hours()))
			default:
				return fmt.Sprintf("%d 天前", int(d.Hours()/24))
			}
		},
		"shortMAC": func(s string) string {
			if len(s) >= 8 {
				return s[len(s)-8:]
			}
			return s
		},
		"humanBytes": humanBytes,
		"sub":        func(a, b int) int { return a - b },
		"prettyCode": func(s string) string {
			// 4-4-4 grouping
			if len(s) <= 4 {
				return s
			}
			out := make([]byte, 0, len(s)+(len(s)/4))
			for i, c := range s {
				if i > 0 && i%4 == 0 {
					out = append(out, '-')
				}
				out = append(out, byte(c))
			}
			return string(out)
		},
		"deref": func(t *time.Time) time.Time {
			if t == nil {
				return time.Time{}
			}
			return *t
		},
		"isPast": func(t time.Time) bool {
			return !t.IsZero() && t.Before(time.Now())
		},
		"list": func(args ...string) []string { return args },
		"add":  func(a, b int) int { return a + b },
		"div":  func(a, b int) int { return a / b },
		"mod":  func(a, b int) int { return a % b },
		"hasInt": func(haystack []int, needle int) bool {
			for _, x := range haystack {
				if x == needle {
					return true
				}
			}
			return false
		},
		"percent": func(n, total int) int {
			if total <= 0 {
				return 0
			}
			return int(float64(n) / float64(total) * 100)
		},
	}
}

func logMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusRecorder{ResponseWriter: w, status: 200}
		h.ServeHTTP(ww, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, ww.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer if it supports flushing. This is
// what lets SSE handlers (which type-assert http.Flusher) keep working even
// though we wrap the writer for status tracking.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
