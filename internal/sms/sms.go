// Package sms is a thin abstraction over SMS providers (Aliyun, Tencent
// Cloud, Twilio, etc.). Used for password-reset codes and pay/grant
// notifications when admin opts in via config.
//
// The real providers need merchant credentials we don't have a clean way
// to test against; the Console provider prints to the server log so dev
// flows still work end-to-end.
package sms

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

// Provider is what every concrete SMS backend implements.
type Provider interface {
	// Send queues + delivers a message. ctx carries deadlines; non-nil err
	// means delivery failed (the caller decides whether to retry).
	Send(ctx context.Context, phone, message string) error

	// Name is a stable identifier for logging / audit ("console", "aliyun",
	// "tencent", "twilio", ...).
	Name() string
}

// ErrNotConfigured is returned by Sender when no provider has been wired.
var ErrNotConfigured = errors.New("sms: provider not configured")

// Sender wraps a (possibly-nil) Provider so callers can do `s.Send(...)`
// unconditionally and just inspect the error.
type Sender struct {
	P Provider
}

// Send returns ErrNotConfigured when P is nil. Otherwise delegates.
func (s *Sender) Send(ctx context.Context, phone, message string) error {
	if s == nil || s.P == nil {
		return ErrNotConfigured
	}
	return s.P.Send(ctx, phone, message)
}

// Available reports whether a provider is wired up.
func (s *Sender) Available() bool {
	return s != nil && s.P != nil
}

// Name returns the provider name or "none".
func (s *Sender) Name() string {
	if s == nil || s.P == nil {
		return "none"
	}
	return s.P.Name()
}

// --- Console provider --------------------------------------------------------

// Console is a development provider: every Send writes one log line. The
// recorded messages are also kept in a small ring buffer (last 50) for tests
// + an admin debug page.
type Console struct {
	mu  sync.Mutex
	log []Record
	cap int
}

// Record is one in-memory log entry.
type Record struct {
	At      time.Time
	Phone   string
	Message string
}

// NewConsole returns a console provider ready to use. cap is the ring-buffer
// size (default 50 when ≤0).
func NewConsole(cap int) *Console {
	if cap <= 0 {
		cap = 50
	}
	return &Console{cap: cap}
}

func (c *Console) Name() string { return "console" }

func (c *Console) Send(_ context.Context, phone, message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, Record{At: time.Now().UTC(), Phone: phone, Message: message})
	if len(c.log) > c.cap {
		c.log = c.log[len(c.log)-c.cap:]
	}
	log.Printf("sms(console) → %s: %s", phone, message)
	return nil
}

// Recent returns a copy of the most-recent entries (newest last).
// Useful for /admin/sms-log debug pages or test assertions.
func (c *Console) Recent() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Record, len(c.log))
	copy(out, c.log)
	return out
}
