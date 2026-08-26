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
//
// Messages that carry a live credential (password-reset codes, temp
// passwords) MUST go through SendSMSSensitive instead: sms_log rows are
// exposed to /admin/sms-log AND to GET /api/admin/sms/log, which
// deliberately accepts READ-ONLY API tokens on the assumption that the
// table holds delivery state, not auth material.
func (a *App) SendSMS(ctx context.Context, phone, message string) error {
	return a.sendSMSLogged(ctx, phone, message, message)
}

// SendSMSSensitive delivers `message` but persists `logged` (a redacted
// stand-in) to sms_log. Pre-v0.119 the forgot-password and admin
// reset-password flows stored the full body — i.e. the live 6-digit
// reset code / the plaintext temp password — in the DB. Anyone holding a
// read-only monitoring token could then POST /user/forgot-password for a
// victim's phone (public endpoint), read the code from
// GET /api/admin/sms/log within its 10-minute TTL, and take over the
// account — despite the read-only tier existing precisely so such tokens
// can never affect accounts.
func (a *App) SendSMSSensitive(ctx context.Context, phone, message, logged string) error {
	return a.sendSMSLogged(ctx, phone, message, logged)
}

func (a *App) sendSMSLogged(ctx context.Context, phone, message, logged string) error {
	provider := "none"
	if a.SMS != nil {
		provider = a.SMS.Name()
	}
	err := a.SMS.Send(ctx, phone, message)
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	// The log write must survive ctx dying between "provider delivered"
	// and "row inserted" (client disconnect, shutdown): the SMS is out in
	// the real world either way, and sms_log exists precisely to record
	// that.
	if logErr := a.DB.LogSMS(context.WithoutCancel(ctx), provider, phone, logged, err == nil, errMsg); logErr != nil {
		log.Printf("sms_log write failed: %v (real send result was: %v)", logErr, err)
	}
	return err
}
