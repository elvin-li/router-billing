package server

import (
	"context"
	"log"
	"net/http"
	"time"
)

// expiryReminderInterval is how often the background loop checks for
// MACs needing a reminder. Hardcoded — adjusting the dedup window via
// config is enough flexibility.
const expiryReminderInterval = 1 * time.Hour

// expiryReminderLoop sends one SMS per affected MAC owner per day when the
// MAC's subscription expires soon. Runs forever; cancel by ctx.
//
// We poll every hour rather than scheduling a per-MAC timer because the
// set of "expiring soon" MACs is small (capped at 200 in the DB query) and
// the cron-like cadence is easier to reason about than a forest of timers.
func (a *App) expiryReminderLoop(ctx context.Context) {
	if a.SMS == nil || !a.SMS.Available() {
		log.Printf("expiry reminder: SMS not configured, skipping background loop")
		return
	}
	if a.Cfg.SMS.ExpiryReminderDisable {
		log.Printf("expiry reminder: disabled via config.sms.expiry_reminder_disable")
		return
	}
	t := time.NewTicker(expiryReminderInterval)
	defer t.Stop()
	// Run once on boot so a freshly-deployed instance doesn't wait an hour.
	a.sendExpiryReminders(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.sendExpiryReminders(ctx)
		}
	}
}

// sendExpiryReminders does one pass — find eligible MACs, look up each
// owner's phone, send SMS, audit. Returns the (sent, skipped, errored)
// counts so tests can assert behavior without poking the SMS provider.
func (a *App) sendExpiryReminders(ctx context.Context) (sent, skipped, errored int) {
	// One pass at a time: the eligible-list query relies on audit rows the
	// pass itself writes only after each SMS is delivered, so the hourly
	// loop and the manual admin trigger running concurrently would both
	// list (and text) the same users. Serializing makes the second pass
	// see the first one's de-dup rows.
	a.expiryRemMu.Lock()
	defer a.expiryRemMu.Unlock()
	// The `expiry_reminder` audit row IS the de-dup marker for the next
	// 22h. It must land even when ctx is canceled between the SMS send
	// and the insert (admin closed the trigger page mid-pass, or the
	// server began shutdown): the SMS already went out, and a swallowed
	// audit failure meant every later hourly pass re-texted the same
	// users until the MAC expired.
	auditCtx := context.WithoutCancel(ctx)
	days := a.Cfg.SMS.ExpiryReminderWindowDays()
	macs, err := a.DB.ListExpiringMACsWithoutRecentReminder(ctx, days)
	if err != nil {
		log.Printf("expiry reminder list: %v", err)
		return 0, 0, 0
	}
	for _, m := range macs {
		// Stop the pass once ctx is dead (server shutdown mid-pass):
		// every remaining send would fail on the canceled context and
		// write one `expiry_reminder_failed` audit row per MAC — pure
		// noise that buried real delivery failures on every restart.
		// The next hourly pass picks these MACs up again (the de-dup
		// window only blocks MACs that actually got their SMS).
		if ctx.Err() != nil {
			log.Printf("expiry reminder pass aborted (%v) with %d MACs left", ctx.Err(), len(macs)-sent-skipped-errored)
			break
		}
		if m.UserID == nil {
			skipped++
			continue
		}
		user, err := a.DB.GetUser(ctx, *m.UserID)
		if err != nil || user == nil || user.Suspended {
			skipped++
			continue
		}
		body := formatExpiryReminderBody(m.Mac, m.Label, m.ExpiresAt)
		if err := a.SendSMS(ctx, user.Phone, body); err != nil {
			log.Printf("expiry reminder %s → %s: %v", m.Mac, user.Phone, err)
			errored++
			a.DB.Audit(auditCtx, "system", "expiry_reminder_failed", m.Mac,
				"phone="+user.Phone+" err="+err.Error())
			continue
		}
		// Audit BEFORE deciding "sent" so the de-dup query (last 22h) finds
		// this row on the next pass.
		a.DB.Audit(auditCtx, "system", "expiry_reminder", m.Mac,
			"phone="+user.Phone+" provider="+a.SMS.Name())
		sent++
	}
	if sent+errored > 0 {
		log.Printf("expiry reminder pass: sent=%d skipped=%d errored=%d", sent, skipped, errored)
	}
	return sent, skipped, errored
}

// POST /admin/sms-log/expiry-reminders
//
// Manual trigger for the expiry-reminder pass. Same DB query + same audit
// shape as the background loop — so manually-triggered sends are still
// deduplicated against the background ones via the 22h audit window. The
// admin sees a flash with sent/skipped/errored counts.
func (a *App) handleAdminExpiryReminderTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/sms-log", http.StatusSeeOther)
		return
	}
	if a.SMS == nil || !a.SMS.Available() {
		http.Redirect(w, r, "/admin/sms-log?err=sms_disabled", http.StatusSeeOther)
		return
	}
	// Detach from the request context (same rationale as the v0.106
	// payment-finalize fix): an admin disconnecting mid-pass must not
	// abort between "SMS delivered" and "de-dup audit row written".
	ctx := context.WithoutCancel(r.Context())
	sent, skipped, errored := a.sendExpiryReminders(ctx)
	a.DB.Audit(ctx, "admin", "expiry_reminder_pass", "",
		"sent="+itoaSmall(sent)+" skipped="+itoaSmall(skipped)+" errored="+itoaSmall(errored)+
			" ip="+clientIP(r))
	loc := "/admin/sms-log?ok=reminders&sent=" + itoaSmall(sent) +
		"&skipped=" + itoaSmall(skipped) + "&errored=" + itoaSmall(errored)
	http.Redirect(w, r, loc, http.StatusSeeOther)
}

// formatExpiryReminderBody builds the SMS body. Kept as a pure function so
// it can be unit-tested without spinning up the whole App.
func formatExpiryReminderBody(mac, label string, expiresAt time.Time) string {
	// Ceiling, not truncation: 71h out is "3 天" not "2 天" — truncating
	// understated the remaining time in every non-exact case, telling a
	// user with 2.9 days left they had 2.
	days := int((time.Until(expiresAt) + 24*time.Hour - 1) / (24 * time.Hour))
	if days < 1 {
		days = 1
	}
	target := mac
	if label != "" {
		target = label + " (" + mac + ")"
	}
	return "【router-billing】您的设备 " + target +
		" 套餐还有 " + itoaSmall(days) + " 天到期（" +
		expiresAt.Local().Format("01-02") + "）。请及时续费。"
}
