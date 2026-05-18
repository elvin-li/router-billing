package server

import (
	"context"
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
