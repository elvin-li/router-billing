package server

import (
	"log"
	"net/http"
	"os"

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
	a.Notifier.Send(notify.Event{
		Type:   "test",
		Actor:  "admin",
		Detail: "manual test from /admin/maintenance ip=" + clientIP(r),
	})
	log.Printf("admin test-webhook → %s ip=%s", a.Cfg.Webhook.URL, clientIP(r))
	a.DB.Audit(r.Context(), "admin", "webhook_test", "",
		"url="+a.Cfg.Webhook.URL+" ip="+clientIP(r))
	http.Redirect(w, r, "/admin/maintenance?ok=webhook_test", http.StatusSeeOther)
}
