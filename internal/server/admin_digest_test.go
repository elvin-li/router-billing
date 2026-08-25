package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"router-billing/internal/db"
	"router-billing/internal/models"
	"router-billing/internal/sms"
)

func TestAdminDigestStatsAggregates(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	now := time.Now().UTC()
	yesterday := now.AddDate(0, 0, -1)
	twoDaysAgo := now.AddDate(0, 0, -2)

	// Yesterday's paid order — should count.
	seedOrderWithCreated(t, app, "DIGEST-YES", "AA:BB:CC:00:00:01", models.OrderPaid, yesterday)
	// Patch paid_at to land in the yesterday window.
	if _, err := app.DB.Exec(ctx, `UPDATE orders SET paid_at = ? WHERE order_no = 'DIGEST-YES'`, yesterday); err != nil {
		t.Fatal(err)
	}
	// Two days ago — should NOT count in "yesterday" window.
	seedOrderWithCreated(t, app, "DIGEST-OLD", "AA:BB:CC:00:00:02", models.OrderPaid, twoDaysAgo)
	_, _ = app.DB.Exec(ctx, `UPDATE orders SET paid_at = ? WHERE order_no = 'DIGEST-OLD'`, twoDaysAgo)

	// Today's failed order.
	seedOrderWithCreated(t, app, "DIGEST-FAIL", "AA:BB:CC:00:00:03", models.OrderFailed, now)

	// MAC expiring tomorrow — should be in 3-day window.
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:00:04", "soon", 1, nil); err != nil {
		t.Fatal(err)
	}

	s, err := app.DB.AdminDigestStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.YesterdayPaidOrders != 1 {
		t.Errorf("YesterdayPaidOrders = %d; want 1", s.YesterdayPaidOrders)
	}
	if s.YesterdayRevenueCents != 100 {
		t.Errorf("YesterdayRevenueCents = %d; want 100", s.YesterdayRevenueCents)
	}
	if s.FailedOrdersToday != 1 {
		t.Errorf("FailedOrdersToday = %d; want 1", s.FailedOrdersToday)
	}
	if s.ExpiringWithin3Days != 1 {
		t.Errorf("ExpiringWithin3Days = %d; want 1", s.ExpiringWithin3Days)
	}
}

func TestSendAdminDigestEndToEnd(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	app.Cfg.SMS.AdminLoginAlertPhone = "13800160000"

	_, err := app.sendAdminDigest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recs := console.Recent()
	if len(recs) != 1 {
		t.Fatalf("expected 1 SMS; got %d", len(recs))
	}
	if recs[0].Phone != "13800160000" {
		t.Errorf("phone: %s", recs[0].Phone)
	}
	if !strings.Contains(recs[0].Message, "日报") {
		t.Errorf("body should mention 日报; got %q", recs[0].Message)
	}

	// Audit entry written.
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "admin_digest_sent" {
			found = true
		}
	}
	if !found {
		t.Error("admin_digest_sent audit entry missing")
	}
}

func TestAdminDigestAuditSurvivesContextCancel(t *testing.T) {
	// The ctx dies the moment the SMS is delivered (admin closed the
	// manual-trigger page, or shutdown began). The audit row is how
	// operators confirm the daily schedule fired — it must land anyway.
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.Cfg.SMS.AdminLoginAlertPhone = "13800160001"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.SMS = &sms.Sender{P: &cancelingProvider{inner: console, cancel: cancel}}

	if _, err := app.sendAdminDigest(ctx); err != nil {
		t.Fatalf("sendAdminDigest: %v", err)
	}
	if n := len(console.Recent()); n != 1 {
		t.Fatalf("expected 1 SMS; got %d", n)
	}
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "admin_digest_sent" {
			found = true
		}
	}
	if !found {
		t.Error("admin_digest_sent audit row was lost to the canceled context")
	}
}

func TestFormatAdminDigestBody(t *testing.T) {
	cases := []struct {
		s    db.AdminDigestStats
		want string // substring to find
	}{
		{db.AdminDigestStats{YesterdayRevenueCents: 12345, YesterdayPaidOrders: 5},
			"昨日营收 ¥123.45（5 单）"},
		{db.AdminDigestStats{YesterdayRevenueCents: 100, YesterdayPaidOrders: 1, ExpiringWithin3Days: 7},
			"未来 3 天 7 个 MAC 到期"},
		{db.AdminDigestStats{FailedOrdersToday: 3},
			"今日 3 单失败"},
		{db.AdminDigestStats{YesterdayRevenueCents: 50},
			"¥0.50"},
	}
	for _, c := range cases {
		got := formatAdminDigestBody(c.s)
		if !strings.Contains(got, c.want) {
			t.Errorf("formatAdminDigestBody(%+v) = %q; missing %q", c.s, got, c.want)
		}
	}
}

func TestNextDigestAtFiresAtConfiguredHour(t *testing.T) {
	utc := func(y int, m time.Month, d, h, min int) time.Time {
		return time.Date(y, m, d, h, min, 0, 0, time.UTC)
	}
	cases := []struct {
		name string
		now  time.Time
		hour int
		want time.Time
	}{
		// Documented semantics: fire AT the configured UTC hour. The old
		// code used hour-1 and fired one hour early.
		{"before-hour-same-day", utc(2026, 3, 10, 6, 30), 9, utc(2026, 3, 10, 9, 0)},
		{"after-hour-next-day", utc(2026, 3, 10, 9, 30), 9, utc(2026, 3, 11, 9, 0)},
		{"exactly-at-hour-rolls-to-next-day", utc(2026, 3, 10, 9, 0), 9, utc(2026, 3, 11, 9, 0)},
		{"hour-24-means-midnight", utc(2026, 3, 10, 6, 0), 24, utc(2026, 3, 11, 0, 0)},
		{"hour-1-is-one-am", utc(2026, 3, 10, 0, 30), 1, utc(2026, 3, 10, 1, 0)},
	}
	for _, c := range cases {
		if got := nextDigestAt(c.now, c.hour); !got.Equal(c.want) {
			t.Errorf("%s: nextDigestAt(%s, %d) = %s; want %s",
				c.name, c.now, c.hour, got, c.want)
		}
	}
}

func TestNextDigestAtAbsorbsClockJumps(t *testing.T) {
	// After a multi-day suspend / clock step, recomputing from the current
	// wall clock must yield exactly ONE next send — not one per missed day
	// (the old target.Add(24h) catch-up sent a burst of digest SMSes).
	lastFired := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	nowAfterJump := lastFired.Add(5*24*time.Hour + 3*time.Hour) // 2026-03-15 12:00
	next := nextDigestAt(nowAfterJump, 9)
	want := time.Date(2026, 3, 16, 9, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("next after clock jump = %s; want %s", next, want)
	}
	if !next.After(nowAfterJump) {
		t.Error("next send must be strictly in the future — otherwise the loop fires immediately in a burst")
	}
}

func TestAdminDigestLoopShortCircuitsWhenDisabled(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	app.Cfg.SMS.AdminLoginAlertPhone = "13800160000"
	// AdminDigestHour = 0 → loop should return immediately.

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		app.adminDigestLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("loop didn't honor admin_digest_hour=0")
	}
}

func TestAdminDigestTriggerSendsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	// Set the digest phone AFTER login so the login-alert SMS path doesn't
	// fire (it reads the same config field). The digest button reads the
	// field at request-time, so this still works.
	app.Cfg.SMS.AdminLoginAlertPhone = "13800160100"

	type kv = map[string][]string
	res, _ := do(t, h, "POST", "/admin/sms-log/digest",
		kv{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=digest_sent") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}
	recs := console.Recent()
	if len(recs) != 1 {
		t.Errorf("expected 1 SMS (the digest); got %d", len(recs))
	}
	if !strings.Contains(recs[0].Message, "日报") {
		t.Errorf("last SMS should be the digest body; got %q", recs[0].Message)
	}
}

func TestAdminDigestTriggerNoSMSReturnsErr(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	type kv = map[string][]string
	res, _ := do(t, h, "POST", "/admin/sms-log/digest",
		kv{"_csrf": {csrf}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "sms_disabled") {
		t.Errorf("expected sms_disabled; got %s", res.Header.Get("Location"))
	}
}

func TestAdminDigestTriggerNoPhoneReturnsErr(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	// app.Cfg.SMS.AdminLoginAlertPhone left empty.
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	type kv = map[string][]string
	res, _ := do(t, h, "POST", "/admin/sms-log/digest",
		kv{"_csrf": {csrf}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "digest_no_phone") {
		t.Errorf("expected digest_no_phone; got %s", res.Header.Get("Location"))
	}
}

func TestAdminDigestLoopShortCircuitsWhenSMSNotConfigured(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.SMS.AdminDigestHour = 3
	app.Cfg.SMS.AdminLoginAlertPhone = "13800160000"
	// app.SMS is the no-op Sender from setupTestApp.

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		app.adminDigestLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("loop didn't honor no-SMS-provider")
	}
}
