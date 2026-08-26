package server

import (
	"crypto/sha256"
	"sync"
)

// TOTP one-time-use enforcement (RFC 6238 §5.2: "The verifier MUST NOT
// accept the second attempt of the OTP after the successful validation").
//
// Without this, a 6-digit code stays valid for its whole ±1-step window
// (up to ~90 s) — an attacker who observes a code the victim just typed
// (shoulder-surf, phishing relay) could immediately reuse it to open a
// second session or to pass the 2FA-disable check.
//
// We track the highest accepted timestep per secret, in memory — same
// trade-off as the twoFAAttempts maps: a restart forgets, but a restart
// also takes longer than the 30 s code period, so nothing is replayable
// across it. Keyed by a hash of the secret (not user ID / username) so
// the guard follows re-enrollments automatically and never stores the
// raw secret in yet another place.
var totpUsedSteps = struct {
	sync.Mutex
	m map[[32]byte]int64
}{m: map[[32]byte]int64{}}

// totpConsumeStep records that `step` was accepted for `secret` and
// returns true. Returns false — without recording anything — when a step
// at or before the last accepted one is presented again (a replay).
func totpConsumeStep(secret string, step int64) bool {
	key := sha256.Sum256([]byte(secret))
	totpUsedSteps.Lock()
	defer totpUsedSteps.Unlock()
	if last, ok := totpUsedSteps.m[key]; ok && step <= last {
		return false
	}
	totpUsedSteps.m[key] = step
	return true
}
