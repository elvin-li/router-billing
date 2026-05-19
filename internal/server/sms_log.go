package server

// Persistent SMS logging — every send through App.SendSMS lands one row
// in sms_log regardless of outcome. Survives restarts (unlike the console
// provider's in-memory ring buffer) and is provider-agnostic.
//
// Callers should prefer this wrapper over a.SMS.Send so that delivery
// state is uniformly captured. The legacy ring buffer for the console
// provider stays alive because some tests + the test-send button rely
// on `Recent()` for immediate visibility without a DB round-trip.

import (
	"context"
	"log"
)

// SendSMS delivers `message` to `phone` through whatever provider is
// wired and records the outcome in sms_log. Returns the provider's error
// (nil on success). Always logs to DB even on failure — that's the whole
// point: failures are what operators most want to see later.
//
// Failure to record to DB is swallowed (warns on stderr) so it can't
// reverse the real-world delivery state. Operators who want bullet-proof
// logging should also monitor the stderr stream.
func (a *App) SendSMS(ctx context.Context, phone, message string) error {
	provider := "none"
	if a.SMS != nil {
		provider = a.SMS.Name()
	}
	err := a.SMS.Send(ctx, phone, message)
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	if logErr := a.DB.LogSMS(ctx, provider, phone, message, err == nil, errMsg); logErr != nil {
		log.Printf("sms_log write failed: %v (real send result was: %v)", logErr, err)
	}
	return err
}
