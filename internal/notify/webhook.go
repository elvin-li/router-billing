// Package notify pushes events to an admin-configured webhook URL.
// Useful for: payment notifications to shopkeeper's own dashboard,
// monitoring (anomaly alerts), Slack/Lark/钉钉 bots, etc.
//
// Delivery model:
//   - Best-effort, fire-and-forget queue with 64-deep buffer
//   - Single worker goroutine — events are serialized (preserves order)
//   - HMAC-SHA256 signature in `X-Router-Billing-Signature` header
//   - Drops on full queue, logs to standard logger
//   - Exponential backoff retries — by default 2s, 30s, 5m; tests inject
//     a tighter schedule via BackoffSchedule.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// DefaultBackoffSchedule is the wait between successive retries. The
// initial delivery is attempt 0; failure schedules attempt 1 after
// DefaultBackoffSchedule[0], and so on. After len(schedule) failures the
// event is dropped with a log entry.
var DefaultBackoffSchedule = []time.Duration{
	2 * time.Second,
	30 * time.Second,
	5 * time.Minute,
}

type Event struct {
	Type    string    `json:"type"` // "pay" / "redeem" / "grant" / "revoke" / "user_login" / ...
	At      time.Time `json:"at"`
	Actor   string    `json:"actor,omitempty"`
	MAC     string    `json:"mac,omitempty"`
	UserID  int64     `json:"user_id,omitempty"`
	Amount  int       `json:"amount_cents,omitempty"`
	Days    int       `json:"days,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	OrderNo string    `json:"order_no,omitempty"`
	Voucher string    `json:"voucher,omitempty"`
}

type Notifier struct {
	URL    string
	Secret string

	// RetryDelay is the LEGACY single-shot delay. When set and
	// BackoffSchedule is nil, the worker uses [RetryDelay] as a 1-element
	// schedule for back-compat with the original 2s-one-retry behavior.
	// New code should set BackoffSchedule directly.
	RetryDelay time.Duration

	// BackoffSchedule controls the retry timing. Empty / nil falls back to
	// DefaultBackoffSchedule. Length 0 = no retries (initial attempt only).
	BackoffSchedule []time.Duration

	HTTPClient *http.Client
	queue      chan Event
}

func New(url, secret string) *Notifier {
	if url == "" {
		return &Notifier{} // no-op
	}
	return &Notifier{
		URL:             url,
		Secret:          secret,
		BackoffSchedule: DefaultBackoffSchedule,
		HTTPClient:      &http.Client{Timeout: 8 * time.Second},
		queue:           make(chan Event, 64),
	}
}

// schedule returns the effective retry-delay slice. Semantics:
//   - nil BackoffSchedule  → use DefaultBackoffSchedule (3 retries).
//   - empty BackoffSchedule → caller opted out of retries entirely.
//   - non-empty BackoffSchedule → use as-is.
//
// Legacy RetryDelay > 0 (with nil BackoffSchedule) yields the original
// one-shot behavior for callers that haven't migrated.
func (n *Notifier) schedule() []time.Duration {
	if n.BackoffSchedule != nil {
		return n.BackoffSchedule
	}
	if n.RetryDelay > 0 {
		return []time.Duration{n.RetryDelay}
	}
	return DefaultBackoffSchedule
}

// Run blocks until ctx is canceled. Spawn it in a goroutine from main.
func (n *Notifier) Run(ctx context.Context) {
	if n.URL == "" {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-n.queue:
			n.deliver(ctx, ev, 0)
		}
	}
}

// Send enqueues an event. Non-blocking; drops on a full queue.
func (n *Notifier) Send(ev Event) {
	if n == nil || n.URL == "" {
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	select {
	case n.queue <- ev:
	default:
		log.Printf("notify: queue full, dropping %s/%s", ev.Type, ev.MAC)
	}
}

func (n *Notifier) deliver(ctx context.Context, ev Event, attempt int) {
	body, _ := json.Marshal(ev)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		log.Printf("notify: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "router-billing/1 notify")
	if n.Secret != "" {
		mac := hmac.New(sha256.New, []byte(n.Secret))
		mac.Write(body)
		req.Header.Set("X-Router-Billing-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := n.HTTPClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			return
		}
		err = fmt.Errorf("http %d", resp.StatusCode)
	}
	sched := n.schedule()
	if attempt < len(sched) {
		delay := sched[attempt]
		log.Printf("notify: %s/%s attempt %d failed (%v); retrying in %s",
			ev.Type, ev.MAC, attempt+1, err, delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		n.deliver(ctx, ev, attempt+1)
		return
	}
	log.Printf("notify: drop %s/%s after %d attempts: %v", ev.Type, ev.MAC, attempt+1, err)
}
