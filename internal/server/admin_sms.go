package server

import (
	"log"
	"net/http"
	"strings"

	"router-billing/internal/db"
	"router-billing/internal/models"
	"router-billing/internal/sms"
)

// GET /admin/sms-log — DB-backed delivery history for every provider,
// plus the in-memory console ring buffer when the console provider is wired.
//
// Pre-v0.43 only the console provider's ring buffer was visible — useless
// for Aliyun (no logs) and lost across restarts. The DB log is universal:
// every SendSMS call records one row regardless of provider, so admins
// can troubleshoot delivery weeks after the fact.
func (a *App) handleAdminSMSLog(w http.ResponseWriter, r *http.Request) {
	var consoleRecords []sms.Record
	var providerName string
	available := false
	if a.SMS != nil && a.SMS.Available() {
		providerName = a.SMS.Name()
		available = true
		if c, ok := a.SMS.P.(*sms.Console); ok {
			consoleRecords = c.Recent()
		}
	} else {
		providerName = "none"
	}
	// DB-backed log, newest first. v0.68 wires the v0.45 SearchSMSLogs
	// filter — phone + only_failed — through from the URL so admins can
	// drill in without scraping the JSON endpoint.
	phoneFilter := strings.TrimSpace(r.URL.Query().Get("phone"))
	onlyFailed := r.URL.Query().Get("only_failed") == "1"
	sinceFilter := strings.TrimSpace(r.URL.Query().Get("since"))
	untilFilter := strings.TrimSpace(r.URL.Query().Get("until"))
	dbLogs, _ := a.DB.SearchSMSLogs(r.Context(), db.SMSLogFilter{
		Phone:      phoneFilter,
		OnlyFailed: onlyFailed,
		Since:      sinceFilter,
		Until:      untilFilter,
		Limit:      100,
	})
	// Pass through the raw query so the "reminders" flash can read
	// sent/skipped/errored counts.
	rawQuery := map[string]string{}
	for k := range r.URL.Query() {
		rawQuery[k] = r.URL.Query().Get(k)
	}
	a.render(w, "admin_sms_log.html", a.adminCtx(r, "sms-log", map[string]any{
		"Provider":         providerName,
		"Records":          consoleRecords,
		"DBLogs":           dbLogs,
		"Available":        available,
		"Query0":           rawQuery,
		"WindowDays":       a.Cfg.SMS.ExpiryReminderWindowDays(),
		"ReminderDisabled": a.Cfg.SMS.ExpiryReminderDisable,
		"PhoneFilter":      phoneFilter,
		"OnlyFailed":       onlyFailed,
		"Since":            sinceFilter,
		"Until":            untilFilter,
	}))
}

// POST /admin/sms-log/test  {phone, message}
//
// Sends a one-off SMS through whatever provider is wired. Lets the admin
// verify credentials + signature without waiting for a real user-triggered
// flow. Audited; rejected if no provider is configured.
func (a *App) handleAdminSMSTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/sms-log", http.StatusSeeOther)
		return
	}
	if a.SMS == nil || !a.SMS.Available() {
		http.Redirect(w, r, "/admin/sms-log?err=sms_disabled", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	phone := strings.TrimSpace(r.PostForm.Get("phone"))
	msg := strings.TrimSpace(r.PostForm.Get("message"))
	if !models.ValidPhone(phone) {
		http.Redirect(w, r, "/admin/sms-log?err=bad_phone", http.StatusSeeOther)
		return
	}
	if msg == "" {
		msg = "router-billing test message from " + clientIP(r)
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	if err := a.SendSMS(r.Context(), phone, msg); err != nil {
		log.Printf("admin sms test %s: %v", phone, err)
		a.DB.Audit(r.Context(), "admin", "sms_test_failed", phone,
			"provider="+a.SMS.Name()+" err="+err.Error()+" ip="+clientIP(r))
		http.Redirect(w, r, "/admin/sms-log?err=sms_failed", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "sms_test", phone,
		"provider="+a.SMS.Name()+" ip="+clientIP(r))
	http.Redirect(w, r, "/admin/sms-log?ok=sent", http.StatusSeeOther)
}
