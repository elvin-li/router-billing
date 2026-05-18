package server

import (
	"net/http"

	"router-billing/internal/sms"
)

// GET /admin/sms-log — debug view of the SMS Console provider's ring buffer.
// Only useful when config.sms.provider == console; Aliyun has no in-process
// log to surface (its delivery state lives on Aliyun's dashboard).
func (a *App) handleAdminSMSLog(w http.ResponseWriter, r *http.Request) {
	var records []sms.Record
	var providerName string
	if a.SMS != nil && a.SMS.Available() {
		providerName = a.SMS.Name()
		if c, ok := a.SMS.P.(*sms.Console); ok {
			records = c.Recent()
		}
	} else {
		providerName = "none"
	}
	a.render(w, "admin_sms_log.html", a.adminCtx(r, "sms-log", map[string]any{
		"Provider": providerName,
		"Records":  records,
	}))
}
