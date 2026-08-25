package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"router-billing/internal/notify"
)

// GET /admin/maintenance — backup download, restore upload, and pending-restore status.
func (a *App) handleAdminMaintenance(w http.ResponseWriter, r *http.Request) {
	pending := a.Cfg.DBPath + ".pending-restore"
	pendingSize := uint64(0)
	if st, err := os.Stat(pending); err == nil {
		pendingSize = uint64(st.Size())
	}
	dbSize := uint64(0)
	if st, err := os.Stat(a.Cfg.DBPath); err == nil {
		dbSize = uint64(st.Size())
	}
	// Pass-through query params so the manual-trigger flash blocks can
	// read the result count ({{index .Query0 "expired"}}).
	rawQuery := map[string]string{}
	for k := range r.URL.Query() {
		rawQuery[k] = r.URL.Query().Get(k)
	}
	a.render(w, "admin_maintenance.html", a.adminCtx(r, "maintenance", map[string]any{
		"DBPath":        a.Cfg.DBPath,
		"DBSize":        dbSize,
		"PendingPath":   pending,
		"PendingSize":   pendingSize,
		"BackupDir":     a.Cfg.Backup.Dir,
		"BackupEnabled": a.Cfg.Backup.Enabled,
		"BackupRetain":  a.Cfg.Backup.RetainDays,
		"WebhookURL":    a.Cfg.Webhook.URL,
		"WebhookSigned": a.Cfg.Webhook.Secret != "",
		"AuditKeep":     a.Cfg.Security.AuditLogRetention(),
		"Query0":        rawQuery,
	}))
}

// POST /admin/maintenance/test-webhook
//
// Enqueues a "ping" event through the existing Notifier so admin can
// verify their webhook URL + HMAC signing is wired up. Mirrors the
// /admin/sms-log/test pattern.
//
// Returns immediately — delivery is async. The admin checks their
// upstream service for the test payload, or watches the server log for
// "notify: drop ..." if delivery fails.
func (a *App) handleAdminTestWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/maintenance", http.StatusSeeOther)
		return
	}
	if a.Notifier == nil || a.Cfg.Webhook.URL == "" {
		http.Redirect(w, r, "/admin/maintenance?err=webhook_not_configured", http.StatusSeeOther)
		return
	}
	a.Notifier.Send(notifyTestEvent("admin", a.clientIP(r)))
	log.Printf("admin test-webhook → %s ip=%s", a.Cfg.Webhook.URL, a.clientIP(r))
	a.DB.Audit(r.Context(), "admin", "webhook_test", "",
		"url="+a.Cfg.Webhook.URL+" ip="+a.clientIP(r))
	http.Redirect(w, r, "/admin/maintenance?ok=webhook_test", http.StatusSeeOther)
}

// notifyTestEvent is the shared body of the "test" event both the UI and
// the API webhook-test handlers enqueue. Pulled out so the audit / payload
// shape can't drift between paths.
func notifyTestEvent(actor, ip string) notify.Event {
	return notify.Event{
		Type:   "test",
		Actor:  actor,
		Detail: "manual webhook test ip=" + ip,
	}
}

// POST /admin/maintenance/optimize-now
//
// Runs `PRAGMA optimize` immediately. This is what purgeLoop runs once a
// week (recommended by SQLite docs for keeping query plans good after
// schema/data churn). Useful when ops just did a large data migration
// and want plans re-analyzed without waiting up to 7 days.
//
// VACUUM is deliberately NOT included here — it can take minutes on a
// large DB and holds a write lock. Ops who want a vacuum still go through
// the weekly scheduler or run sqlite3 ... "VACUUM" directly during a
// known-quiet window. PRAGMA optimize is sub-second on every realistic
// router-billing DB size.
func (a *App) handleAdminOptimizeNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/maintenance", http.StatusSeeOther)
		return
	}
	start := time.Now()
	if _, err := a.DB.Exec(r.Context(), "PRAGMA optimize"); err != nil {
		log.Printf("admin optimize-now: %v", err)
		a.DB.Audit(r.Context(), "admin", "optimize_now_failed", "",
			"err="+err.Error()+" ip="+a.clientIP(r))
		http.Redirect(w, r, "/admin/maintenance?err=optimize_failed", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "optimize_now", "",
		fmt.Sprintf("ms=%d ip=%s", time.Since(start).Milliseconds(), a.clientIP(r)))
	http.Redirect(w, r,
		fmt.Sprintf("/admin/maintenance?ok=optimize_now&ms=%d", time.Since(start).Milliseconds()),
		http.StatusSeeOther)
}

// POST /admin/maintenance/expire-now
//
// Manually triggers the expiry sweep that the background purgeLoop runs
// every 2 hours. Useful when ops just changed a plan or revoked a batch
// and wants the firewall to reflect reality NOW rather than after the
// next tick. Audited; idempotent — if nothing's due, it's a no-op.
//
// Resyncs the firewall set after the sweep so any newly-expired MACs are
// actually evicted from the allow list, not just flipped in the DB.
func (a *App) handleAdminExpireNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/maintenance", http.StatusSeeOther)
		return
	}
	// Detached from the request context (v0.106 finalize rationale): a
	// client disconnect between the DB flip and the firewall resync would
	// leave newly-expired MACs online until the next scheduler tick.
	ctx := context.WithoutCancel(r.Context())
	expired, err := a.DB.ExpireDueMACs(ctx)
	if err != nil {
		log.Printf("admin expire-now: %v", err)
		a.DB.Audit(ctx, "admin", "expire_now_failed", "",
			"err="+err.Error()+" ip="+a.clientIP(r))
		http.Redirect(w, r, "/admin/maintenance?err=expire_failed", http.StatusSeeOther)
		return
	}
	if rerr := a.MACSvc.Resync(ctx); rerr != nil {
		log.Printf("admin expire-now resync: %v", rerr)
	}
	a.DB.Audit(ctx, "admin", "expire_now", "",
		fmt.Sprintf("expired=%d ip=%s", len(expired), a.clientIP(r)))
	http.Redirect(w, r,
		fmt.Sprintf("/admin/maintenance?ok=expire_now&expired=%d", len(expired)),
		http.StatusSeeOther)
}

// POST /admin/maintenance/audit-trim
//
// Manually triggers the audit-log purge that the background purgeLoop
// runs every 2 hours. Useful when the cap was lowered in config and ops
// wants the new retention to take effect immediately rather than after
// the next tick. Audited (yes, the trim itself records an audit row).
func (a *App) handleAdminAuditTrim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/audit", http.StatusSeeOther)
		return
	}
	keep := a.Cfg.Security.AuditLogRetention()
	if err := a.DB.PurgeAuditLog(r.Context(), keep); err != nil {
		log.Printf("admin audit-trim: %v", err)
		a.DB.Audit(r.Context(), "admin", "audit_trim_failed", "",
			"err="+err.Error()+" ip="+a.clientIP(r))
		http.Redirect(w, r, "/admin/audit?err=trim_failed", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "audit_trim", "",
		fmt.Sprintf("keep=%d ip=%s", keep, a.clientIP(r)))
	http.Redirect(w, r, "/admin/audit?ok=audit_trim", http.StatusSeeOther)
}

// POST /admin/maintenance/sms-log-trim
//
// Mirrors handleAdminAuditTrim for the v0.43 sms_log table. Uses the same
// security.audit_log_keep cap.
func (a *App) handleAdminSMSLogTrim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/sms-log", http.StatusSeeOther)
		return
	}
	keep := a.Cfg.Security.AuditLogRetention()
	if err := a.DB.PurgeSMSLog(r.Context(), keep); err != nil {
		log.Printf("admin sms-log-trim: %v", err)
		a.DB.Audit(r.Context(), "admin", "sms_log_trim_failed", "",
			"err="+err.Error()+" ip="+a.clientIP(r))
		http.Redirect(w, r, "/admin/sms-log?err=trim_failed", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "sms_log_trim", "",
		fmt.Sprintf("keep=%d ip=%s", keep, a.clientIP(r)))
	http.Redirect(w, r, "/admin/sms-log?ok=sms_log_trim", http.StatusSeeOther)
}

// POST /admin/maintenance/webhook-log-trim
//
// Mirrors handleAdminAuditTrim for the v0.49 webhook_deliveries table.
func (a *App) handleAdminWebhookLogTrim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/webhook-log", http.StatusSeeOther)
		return
	}
	keep := a.Cfg.Security.AuditLogRetention()
	if err := a.DB.PurgeWebhookDeliveries(r.Context(), keep); err != nil {
		log.Printf("admin webhook-log-trim: %v", err)
		a.DB.Audit(r.Context(), "admin", "webhook_log_trim_failed", "",
			"err="+err.Error()+" ip="+a.clientIP(r))
		http.Redirect(w, r, "/admin/webhook-log?err=trim_failed", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "webhook_log_trim", "",
		fmt.Sprintf("keep=%d ip=%s", keep, a.clientIP(r)))
	http.Redirect(w, r, "/admin/webhook-log?ok=webhook_log_trim", http.StatusSeeOther)
}
