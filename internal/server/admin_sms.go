package server

import (
	"log"
	"net/http"
	"strings"

	"router-billing/internal/models"
	"router-billing/internal/sms"
)

// GET /admin/sms-log — debug view of the SMS Console provider's ring buffer.
// Only useful when config.sms.provider == console; Aliyun has no in-process
// log to surface (its delivery state lives on Aliyun's dashboard).
func (a *App) handleAdminSMSLog(w http.ResponseWriter, r *http.Request) {
	var records []sms.Record
	var providerName string
	available := false
	if a.SMS != nil && a.SMS.Available() {
		providerName = a.SMS.Name()
		available = true
		if c, ok := a.SMS.P.(*sms.Console); ok {
			records = c.Recent()
		}
	} else {
		providerName = "none"
	}
	a.render(w, "admin_sms_log.html", a.adminCtx(r, "sms-log", map[string]any{
		"Provider":  providerName,
		"Records":   records,
		"Available": available,
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
	if err := a.SMS.Send(r.Context(), phone, msg); err != nil {
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
