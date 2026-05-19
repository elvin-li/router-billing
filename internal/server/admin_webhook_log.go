package server

// /admin/webhook-log — DB-backed delivery history for the notify.Notifier.
// Companion to v0.43 sms_log: persistent observability for webhook output
// so the operator can answer "did this event ever reach the downstream?"
// without grepping stderr.

import (
	"net/http"
)

// GET /admin/webhook-log?only_failed=1
func (a *App) handleAdminWebhookLog(w http.ResponseWriter, r *http.Request) {
	onlyFailed := r.URL.Query().Get("only_failed") == "1"
	logs, _ := a.DB.RecentWebhookDeliveries(r.Context(), 200, onlyFailed)
	a.render(w, "admin_webhook_log.html", a.adminCtx(r, "webhook-log", map[string]any{
		"Logs":       logs,
		"OnlyFailed": onlyFailed,
		"WebhookURL": a.Cfg.Webhook.URL,
	}))
}
