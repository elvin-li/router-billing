package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"router-billing/internal/sms"
)

// seedUserAndMACExpiring inserts a user + a MAC with the given expiry and
// links them. Returns the MAC's actual stored expires_at (the function may
// round to seconds depending on driver).
func seedUserAndMACExpiring(t *testing.T, app *App, phone, mac string, daysOut int) {
	t.Helper()
	ctx := context.Background()
	u, err := app.DB.CreateUser(ctx, phone, "h")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.UpsertMAC(ctx, mac, "test", daysOut, &u.ID); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryReminderSendsForEligibleMACs(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}

	// 2-day MAC (within the 3-day window) → eligible
	seedUserAndMACExpiring(t, app, "13800143001", "AA:BB:CC:DD:E1:01", 2)
	// 10-day MAC (outside window) → NOT eligible
	seedUserAndMACExpiring(t, app, "13800143002", "AA:BB:CC:DD:E1:02", 10)

	sent, _, errored := app.sendExpiryReminders(context.Background())
	if sent != 1 {
		t.Errorf("sent = %d, want 1", sent)
	}
	if errored != 0 {
		t.Errorf("errored = %d, want 0", errored)
	}

	recs := console.Recent()
	if len(recs) != 1 {
		t.Fatalf("expected 1 SMS; got %d", len(recs))
	}
	if recs[0].Phone != "13800143001" {
		t.Errorf("wrong phone: %s", recs[0].Phone)
	}
	if !strings.Contains(recs[0].Message, "套餐") {
		t.Errorf("body should mention 套餐; got %q", recs[0].Message)
	}
}

func TestExpiryReminderDeduplicatesWithin22Hours(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}

	seedUserAndMACExpiring(t, app, "13800143003", "AA:BB:CC:DD:E1:03", 2)

	// First pass — sends.
	sent1, _, _ := app.sendExpiryReminders(context.Background())
	if sent1 != 1 {
		t.Fatalf("first pass: sent = %d", sent1)
	}
	// Second pass — must NOT re-send (audit row blocks it).
	sent2, _, _ := app.sendExpiryReminders(context.Background())
	if sent2 != 0 {
		t.Errorf("second pass should de-dup; sent = %d", sent2)
	}
	if n := len(console.Recent()); n != 1 {
		t.Errorf("expected 1 total SMS; got %d", n)
	}
}

// cancelingProvider delivers via the wrapped Console but cancels the
// given CancelFunc as a side effect of the send — simulating a request
// context that dies between "SMS delivered" and "de-dup audit written"
// (admin closed the trigger page, or the server started shutting down).
type cancelingProvider struct {
	inner  *sms.Console
	cancel context.CancelFunc
}

func (c *cancelingProvider) Name() string { return "canceling" }
func (c *cancelingProvider) Send(ctx context.Context, phone, message string) error {
	err := c.inner.Send(ctx, phone, message)
	c.cancel()
	return err
}

func TestExpiryReminderDedupSurvivesContextCancelMidPass(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)

	seedUserAndMACExpiring(t, app, "13800143020", "AA:BB:CC:DD:E1:20", 2)

	// First pass: the context is canceled the moment the SMS goes out.
	// The de-dup audit row must still land — otherwise every later pass
	// re-texts the same user (real-world SMS spam until the MAC expires).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.SMS = &sms.Sender{P: &cancelingProvider{inner: console, cancel: cancel}}
	sent1, _, _ := app.sendExpiryReminders(ctx)
	if sent1 != 1 {
		t.Fatalf("first pass: sent = %d, want 1", sent1)
	}

	// Second pass with a healthy context — must de-dup.
	app.SMS = &sms.Sender{P: console}
	sent2, _, _ := app.sendExpiryReminders(context.Background())
	if sent2 != 0 {
		t.Errorf("second pass re-sent %d reminders — de-dup audit row was lost to the canceled context", sent2)
	}
	if n := len(console.Recent()); n != 1 {
		t.Errorf("expected exactly 1 SMS total; got %d", n)
	}
}

func TestExpiryReminderPassStopsOnCanceledContext(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)

	// Two eligible MACs. The context dies as a side effect of the FIRST
	// send — the pass must stop instead of grinding through the rest
	// (each remaining MAC would fail its send on the dead ctx and write
	// an expiry_reminder_failed audit row: restart-time noise).
	seedUserAndMACExpiring(t, app, "13800143030", "AA:BB:CC:DD:E1:30", 2)
	seedUserAndMACExpiring(t, app, "13800143031", "AA:BB:CC:DD:E1:31", 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.SMS = &sms.Sender{P: &cancelingProvider{inner: console, cancel: cancel}}
	sent, _, errored := app.sendExpiryReminders(ctx)
	if sent != 1 {
		t.Errorf("sent = %d, want 1 (the in-flight MAC completes)", sent)
	}
	if errored != 0 {
		t.Errorf("errored = %d, want 0 — remaining MACs should be deferred, not failed", errored)
	}
	if n := len(console.Recent()); n != 1 {
		t.Errorf("expected 1 SMS before the cancel stopped the pass; got %d", n)
	}
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	for _, e := range entries {
		if e.Action == "expiry_reminder_failed" {
			t.Errorf("canceled pass wrote a failure audit row: %+v", e)
		}
	}

	// A later healthy pass picks up the deferred MAC (and only that one —
	// the first is de-duped by its audit row).
	app.SMS = &sms.Sender{P: console}
	sent2, _, _ := app.sendExpiryReminders(context.Background())
	if sent2 != 1 {
		t.Errorf("follow-up pass sent = %d, want 1 (the deferred MAC)", sent2)
	}
}

func TestExpiryReminderSkipsSuspendedUsers(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800143004", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:E1:04", "", 2, &u.ID)
	_ = app.DB.SuspendUser(ctx, u.ID, true)

	sent, skipped, _ := app.sendExpiryReminders(ctx)
	if sent != 0 {
		t.Errorf("suspended user should not be sent; got %d", sent)
	}
	if skipped != 1 {
		t.Errorf("suspended user should be skipped; got skipped=%d", skipped)
	}
}

func TestExpiryReminderSkipsAlreadyExpired(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800143005", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:E1:05", "", 30, &u.ID)
	// Patch expires_at into the past.
	if _, err := app.DB.Exec(ctx, `UPDATE macs SET expires_at = ? WHERE mac = 'AA:BB:CC:DD:E1:05'`,
		time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	sent, _, _ := app.sendExpiryReminders(ctx)
	if sent != 0 {
		t.Errorf("already-expired MAC should not get reminder; sent=%d", sent)
	}
}

func TestExpiryReminderSkipsMACWithoutOwner(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	ctx := context.Background()

	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:E1:06", "", 2, nil); err != nil {
		t.Fatal(err)
	}
	sent, _, _ := app.sendExpiryReminders(ctx)
	if sent != 0 {
		t.Errorf("ownerless MAC should not get reminder; sent=%d", sent)
	}
}

func TestExpiryReminderNoSMSProviderShortCircuits(t *testing.T) {
	// Smoke test for the loop's early return — no panic, no DB queries
	// when SMS is missing.
	app := setupTestApp(t)
	// app.SMS is the no-op Sender from setupTestApp.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// expiryReminderLoop should return immediately.
	done := make(chan struct{})
	go func() {
		app.expiryReminderLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expiryReminderLoop didn't return when SMS disabled")
	}
}

func TestExpiryReminderWindowDaysHonored(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	// Bump the window to 14 days so a 10-day MAC becomes eligible.
	app.Cfg.SMS.ExpiryReminderDays = 14

	seedUserAndMACExpiring(t, app, "13800143010", "AA:BB:CC:DD:E1:10", 10)
	sent, _, _ := app.sendExpiryReminders(context.Background())
	if sent != 1 {
		t.Errorf("with 14-day window, 10-day MAC should be eligible; sent=%d", sent)
	}
}

func TestExpiryReminderDisableShortCircuitsLoop(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	app.Cfg.SMS.ExpiryReminderDisable = true

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		app.expiryReminderLoop(ctx)
		close(done)
	}()
	select {
	case <-done:
		// good — loop returned immediately
	case <-time.After(500 * time.Millisecond):
		t.Fatal("loop didn't honor expiry_reminder_disable")
	}
}

func TestAdminExpiryReminderTriggerSendsAndAudits(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	seedUserAndMACExpiring(t, app, "13800143011", "AA:BB:CC:DD:E1:11", 2)

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/sms-log/expiry-reminders",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=reminders") {
		t.Errorf("redirect: %s", loc)
	}
	if !strings.Contains(loc, "sent=1") {
		t.Errorf("redirect should include sent=1; got %s", loc)
	}

	if n := len(console.Recent()); n != 1 {
		t.Errorf("expected 1 SMS; got %d", n)
	}
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "expiry_reminder_pass" {
			found = true
		}
	}
	if !found {
		t.Error("expected expiry_reminder_pass audit entry")
	}
}

func TestAdminExpiryReminderTriggerNoSMSReturnsErr(t *testing.T) {
	app := setupTestApp(t) // app.SMS = no-op
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/sms-log/expiry-reminders",
		url.Values{"_csrf": {csrf}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "sms_disabled") {
		t.Errorf("expected sms_disabled; got %s", res.Header.Get("Location"))
	}
}

func TestFormatExpiryReminderBody(t *testing.T) {
	exp := time.Now().Add(48 * time.Hour)
	body := formatExpiryReminderBody("AA:BB:CC:11:22:33", "kitchen tv", exp)
	for _, want := range []string{"kitchen tv", "AA:BB:CC:11:22:33", "套餐", "续费"} {
		if !strings.Contains(body, want) {
			t.Errorf("body should contain %q; got %s", want, body)
		}
	}
	// Without a label.
	body2 := formatExpiryReminderBody("AA:BB:CC:11:22:33", "", exp)
	if strings.Contains(body2, "()") {
		t.Errorf("label-less body should not have empty parens; got %s", body2)
	}
}

func TestFormatExpiryReminderBodyDayCountRoundsUp(t *testing.T) {
	cases := []struct {
		until time.Duration
		want  string
	}{
		// 71h out spans into the 3rd day — the old truncation said "2 天".
		{71 * time.Hour, "还有 3 天"},
		{47 * time.Hour, "还有 2 天"},
		{20 * time.Hour, "还有 1 天"},
		// Already past (still status=active until the sweep): clamp to 1.
		{-2 * time.Hour, "还有 1 天"},
	}
	for _, c := range cases {
		body := formatExpiryReminderBody("AA:BB:CC:11:22:33", "", time.Now().Add(c.until))
		if !strings.Contains(body, c.want) {
			t.Errorf("until=%s: body %q should contain %q", c.until, body, c.want)
		}
	}
}
