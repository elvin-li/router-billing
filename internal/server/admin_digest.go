package server

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"router-billing/internal/db"
	"router-billing/internal/models"
)

// adminDigestLoop fires once per day at the configured UTC hour (1..24)
// and SMSes the configured AdminLoginAlertPhone with a summary of:
//
//   - yesterday's revenue + paid-order count
//   - today's failed-order count
//   - count of MACs expiring within the next 3 days
//
// Disabled when AdminDigestHour is 0/invalid OR the SMS provider isn't
// configured OR AdminLoginAlertPhone is empty.
//
// Uses the same fire-and-forget Send pattern as the expiry-reminder loop.
// Audits every send (success + failure) so reviewers can confirm the
// schedule is firing.
func (a *App) adminDigestLoop(ctx context.Context) {
	hour := a.Cfg.SMS.AdminDigestHour
	if hour <= 0 || hour > 24 {
		log.Printf("admin digest: disabled (admin_digest_hour=%d)", hour)
		return
	}
	if a.SMS == nil || !a.SMS.Available() {
		log.Printf("admin digest: SMS provider not configured, loop skipped")
		return
	}
	if a.Cfg.SMS.AdminLoginAlertPhone == "" {
		log.Printf("admin digest: admin_login_alert_phone empty, loop skipped")
		return
	}
	if !models.ValidPhone(a.Cfg.SMS.AdminLoginAlertPhone) {
		log.Printf("admin digest: invalid admin_login_alert_phone %q, loop skipped", a.Cfg.SMS.AdminLoginAlertPhone)
		return
	}

	target := time.Date(time.Now().UTC().Year(), time.Now().UTC().Month(), time.Now().UTC().Day(), hour-1, 0, 0, 0, time.UTC)
	if target.Before(time.Now().UTC()) {
		target = target.Add(24 * time.Hour)
	}
	for {
		wait := time.Until(target)
		log.Printf("admin digest: next send in %s (at %s UTC)", wait, target.Format(time.RFC3339))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		// Discard return — the function already logs + audits any error.
		// The loop must continue to the next day regardless.
		_, _ = a.sendAdminDigest(ctx)
		target = target.Add(24 * time.Hour)
	}
}

// sendAdminDigest does one pass — gather counts, format SMS, send. Returns
// the stats so tests can assert without poking the provider.
func (a *App) sendAdminDigest(ctx context.Context) (db.AdminDigestStats, error) {
	stats, err := a.DB.AdminDigestStats(ctx)
	if err != nil {
		log.Printf("admin digest: stats: %v", err)
		return stats, err
	}
	body := formatAdminDigestBody(stats)
	phone := a.Cfg.SMS.AdminLoginAlertPhone
	if err := a.SMS.Send(ctx, phone, body); err != nil {
		log.Printf("admin digest sms %s: %v", phone, err)
		a.DB.Audit(ctx, "system", "admin_digest_failed", "", "phone="+phone+" err="+err.Error())
		return stats, err
	}
	a.DB.Audit(ctx, "system", "admin_digest_sent", "",
		"phone="+phone+" revenue="+strconv.Itoa(stats.YesterdayRevenueCents)+
			" paid="+strconv.Itoa(stats.YesterdayPaidOrders)+
			" failed="+strconv.Itoa(stats.FailedOrdersToday)+
			" expiring="+strconv.Itoa(stats.ExpiringWithin3Days))
	return stats, nil
}

// formatAdminDigestBody is a pure helper so tests can assert without
// running the loop.
func formatAdminDigestBody(s db.AdminDigestStats) string {
	yuan := s.YesterdayRevenueCents / 100
	cents := s.YesterdayRevenueCents % 100
	body := "【router-billing 日报】昨日营收 ¥" +
		strconv.Itoa(yuan) + "." + leftPad2(cents) +
		"（" + strconv.Itoa(s.YesterdayPaidOrders) + " 单）"
	if s.ExpiringWithin3Days > 0 {
		body += " · 未来 3 天 " + strconv.Itoa(s.ExpiringWithin3Days) + " 个 MAC 到期"
	}
	if s.FailedOrdersToday > 0 {
		body += " · 今日 " + strconv.Itoa(s.FailedOrdersToday) + " 单失败"
	}
	return body
}

// POST /admin/sms-log/digest
//
// Manual trigger for the daily-digest SMS. Same code path as the scheduled
// loop, so manual sends use the same body shape + audit entry. Useful for
// admins to verify the digest works before relying on the daily cron.
func (a *App) handleAdminDigestTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/sms-log", http.StatusSeeOther)
		return
	}
	if a.SMS == nil || !a.SMS.Available() {
		http.Redirect(w, r, "/admin/sms-log?err=sms_disabled", http.StatusSeeOther)
		return
	}
	if a.Cfg.SMS.AdminLoginAlertPhone == "" {
		http.Redirect(w, r, "/admin/sms-log?err=digest_no_phone", http.StatusSeeOther)
		return
	}
	if _, err := a.sendAdminDigest(r.Context()); err != nil {
		http.Redirect(w, r, "/admin/sms-log?err=sms_failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/sms-log?ok=digest_sent", http.StatusSeeOther)
}

func leftPad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}
