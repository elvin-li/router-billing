package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"router-billing/internal/sms"
)

// gatedSMSProvider freezes the FIRST send at its entrance (before the
// wrapped provider records anything) until release is closed. Later sends
// proceed once the first one has been released — sync.Once blocks
// concurrent callers until the gated function returns, which is exactly
// the overlap window this test needs.
type gatedSMSProvider struct {
	inner   sms.Provider
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedSMSProvider) Name() string { return g.inner.Name() }

func (g *gatedSMSProvider) Send(ctx context.Context, phone, message string) error {
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})
	return g.inner.Send(ctx, phone, message)
}

// The hourly reminder loop and the manual /admin/sms-log/expiry-reminders
// trigger can run at the same time. Their shared 22h de-dup marker (the
// expiry_reminder audit row) is only written AFTER each SMS goes out, so
// two overlapping passes used to both list the same eligible MACs and
// double-text every listed user. sendExpiryReminders is now serialized:
// the second pass must observe the first pass's audit rows and send
// nothing.
func TestExpiryReminderConcurrentPassesDoNotDoubleText(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	gate := &gatedSMSProvider{
		inner:   console,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	app.SMS = &sms.Sender{P: gate}

	seedUserAndMACExpiring(t, app, "13800143050", "AA:BB:CC:DD:E1:50", 2)

	pass1 := make(chan int, 1)
	go func() {
		sent, _, _ := app.sendExpiryReminders(context.Background())
		pass1 <- sent
	}()
	<-gate.entered // pass 1 listed the MAC and is mid-SMS; no de-dup row yet

	pass2 := make(chan int, 1)
	go func() {
		sent, _, _ := app.sendExpiryReminders(context.Background())
		pass2 <- sent
	}()

	// Without serialization pass 2 would list the same MAC right here
	// (the audit row only lands after the send) and queue a second SMS.
	time.Sleep(150 * time.Millisecond)
	close(gate.release)

	sent1, sent2 := <-pass1, <-pass2
	if total := sent1 + sent2; total != 1 {
		t.Errorf("overlapping passes sent %d reminders total, want exactly 1 (pass1=%d pass2=%d)",
			total, sent1, sent2)
	}
	if n := len(console.Recent()); n != 1 {
		t.Errorf("expected exactly 1 SMS delivered; got %d", n)
	}
}
