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
