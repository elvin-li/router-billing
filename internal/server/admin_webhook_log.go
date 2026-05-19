package server

// /admin/webhook-log — DB-backed delivery history for the notify.Notifier.
// Companion to v0.43 sms_log: persistent observability for webhook output
// so the operator can answer "did this event ever reach the downstream?"
// without grepping stderr.

import (
	"net/http"
	"strings"

	"router-billing/internal/db"
)

// GET /admin/webhook-log?event_type=&mac=&only_failed=1
//
// v0.69 wires the new EventType + MAC filters from SearchWebhookDeliveries
// through to the UI so admins can drill into "all `order_paid` events for
// this customer's MAC" without scraping JSON.
func (a *App) handleAdminWebhookLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := db.WebhookDeliveryFilter{
		EventType:  strings.TrimSpace(q.Get("event_type")),
		MAC:        strings.TrimSpace(q.Get("mac")),
		OnlyFailed: q.Get("only_failed") == "1",
		Since:      strings.TrimSpace(q.Get("since")),
		Until:      strings.TrimSpace(q.Get("until")),
		Limit:      200,
	}
	logs, _ := a.DB.SearchWebhookDeliveries(r.Context(), f)
	a.render(w, "admin_webhook_log.html", a.adminCtx(r, "webhook-log", map[string]any{
		"Logs":       logs,
		"OnlyFailed": f.OnlyFailed,
		"EventType":  f.EventType,
		"MAC":        f.MAC,
		"Since":      f.Since,
		"Until":      f.Until,
		"WebhookURL": a.Cfg.Webhook.URL,
	}))
}
