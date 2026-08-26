// Package notify pushes events to an admin-configured webhook URL.
// Useful for: payment notifications to shopkeeper's own dashboard,
// monitoring (anomaly alerts), Slack/Lark/钉钉 bots, etc.
//
// Delivery model:
//   - Best-effort, fire-and-forget queue with 64-deep buffer
//   - Single worker goroutine — fresh events are delivered in order
//   - HMAC-SHA256 signature in `X-Router-Billing-Signature` header
//   - Drops on full queue, logs to standard logger
//   - Exponential backoff retries — by default 2s, 30s, 5m; tests inject
//     a tighter schedule via BackoffSchedule. Retries are scheduled with
//     a timer and re-enqueued, so a failing endpoint never blocks the
//     worker: fresh events keep flowing while a retry waits its turn.
//     (Retried events may therefore land out of order relative to newer
//     events — receivers should key on Event.At / OrderNo, not arrival.)
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

// defaultAttemptTimeout bounds one delivery attempt (DNS + connect + TLS +
// request + response) when Notifier.AttemptTimeout is unset. Generous
// compared to the 8s default HTTPClient timeout — it is a backstop, not
// the primary limit.
const defaultAttemptTimeout = 30 * time.Second

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

	// AttemptTimeout is the hard per-attempt ceiling enforced with a
	// context deadline, independent of HTTPClient.Timeout. Zero/negative
	// falls back to defaultAttemptTimeout. This exists because the worker
	// is a SINGLE goroutine: if a caller swaps in an HTTPClient without a
	// Timeout (http.DefaultClient has none), one endpoint that accepts the
	// TCP connection and then never responds would wedge the pipeline
	// forever — the same stall the v0.108 re-enqueue fix addressed, just
	// via a hung request instead of a backoff sleep.
	AttemptTimeout time.Duration

	HTTPClient *http.Client
	queue      chan queued

	// OnDelivery, if non-nil, is called once per delivery attempt (initial
	// + each retry) AFTER the HTTP response settles. Callback must not
	// block — it runs on the same goroutine as deliver(). Used by the
	// server package to persist a row in `webhook_deliveries` for the
	// /admin/webhook-log view.
	//
	// `statusCode` is 0 if the HTTP call never produced a response (DNS
	// failure, connection refused, etc.). `err` is the same value that
	// drives the retry decision.
	OnDelivery func(ev Event, attempt int, statusCode int, durationMs int64, err error)
}

// queued is one queue entry: the event plus which delivery attempt it is
// on (0 = initial). Retries re-enter the queue with attempt+1 instead of
// blocking the worker in a sleep.
type queued struct {
	ev      Event
	attempt int
}

func New(url, secret string) *Notifier {
	if url == "" {
		return &Notifier{} // no-op
	}
	// Leave BackoffSchedule nil so schedule() can pick the right fallback
	// at delivery time. If we eagerly populated it here, callers that set
	// the legacy RetryDelay field (or future BackoffSchedule) after New()
	// would silently lose their override.
	return &Notifier{
		URL:        url,
		Secret:     secret,
		HTTPClient: &http.Client{Timeout: 8 * time.Second},
		queue:      make(chan queued, 64),
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
		case q := <-n.queue:
			n.deliverSafe(ctx, q.ev, q.attempt)
		}
	}
}

// deliverSafe wraps deliver with a recover so a panic (e.g. inside the
// caller-supplied OnDelivery hook) drops one event instead of killing
// the whole process via an unrecovered panic in the worker goroutine.
func (n *Notifier) deliverSafe(ctx context.Context, ev Event, attempt int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("notify: panic delivering %s/%s (event dropped, worker continues): %v",
				ev.Type, ev.MAC, r)
		}
	}()
	n.deliver(ctx, ev, attempt)
}

// Send enqueues an event. Non-blocking; drops on a full queue.
func (n *Notifier) Send(ev Event) {
	if n == nil || n.URL == "" {
		return
	}
	if n.queue == nil {
		// A Notifier built as a struct literal with URL set (bypassing
		// New) has no queue: a send on a nil channel never proceeds, so
		// the select below fell through to `default` and logged a
		// misleading "queue full" for EVERY event. Name the real problem.
		log.Printf("notify: dropping %s/%s — Notifier not initialized via notify.New (no queue)", ev.Type, ev.MAC)
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	select {
	case n.queue <- queued{ev: ev}:
	default:
		log.Printf("notify: queue full, dropping %s/%s", ev.Type, ev.MAC)
	}
}

func (n *Notifier) deliver(ctx context.Context, ev Event, attempt int) {
	// Hard per-attempt deadline: the single worker must never wedge on
	// one request, no matter how the HTTPClient is configured. Kept
	// separate from the parent ctx — the retry decision below checks the
	// PARENT for shutdown, and a timed-out attempt must still retry.
	attemptTimeout := n.AttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = defaultAttemptTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()

	body, _ := json.Marshal(ev)

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, n.URL, bytes.NewReader(body))
	if err != nil {
		log.Printf("notify: build request: %v", err)
		if n.OnDelivery != nil {
			n.OnDelivery(ev, attempt, 0, 0, err)
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "router-billing/1 notify")
	if n.Secret != "" {
		mac := hmac.New(sha256.New, []byte(n.Secret))
		mac.Write(body)
		req.Header.Set("X-Router-Billing-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	// Default a nil client rather than dereferencing it: a Notifier whose
	// HTTPClient was cleared (or replaced with nil after New) used to
	// nil-panic in deliverSafe on EVERY event — recovered, but each event
	// silently dropped. Read into a local; never mutate the shared struct
	// (Send/deliver run concurrently with retry timers).
	httpClient := n.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 8 * time.Second}
	}

	start := time.Now()
	resp, err := httpClient.Do(req)
	statusCode := 0
	if err == nil {
		statusCode = resp.StatusCode
		// Drain a bounded slice of the body before closing so the
		// keep-alive connection can be reused for the next delivery.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			if n.OnDelivery != nil {
				n.OnDelivery(ev, attempt, statusCode, time.Since(start).Milliseconds(), nil)
			}
			return
		}
		err = fmt.Errorf("http %d", resp.StatusCode)
	}
	if n.OnDelivery != nil {
		n.OnDelivery(ev, attempt, statusCode, time.Since(start).Milliseconds(), err)
	}
	sched := n.schedule()
	if attempt < len(sched) {
		if ctx.Err() != nil {
			return // shutting down — don't schedule work nobody will run
		}
		delay := sched[attempt]
		log.Printf("notify: %s/%s attempt %d failed (%v); retrying in %s",
			ev.Type, ev.MAC, attempt+1, err, delay)
		// Schedule the retry via re-enqueue rather than sleeping here:
		// the pre-v0.108 in-place `time.After(delay)` held the single
		// worker for the whole backoff (up to ~5.5min per event on the
		// default schedule), so one dead endpoint stalled the pipeline
		// until the 64-slot queue overflowed and payment/grant events
		// were silently dropped.
		next := queued{ev: ev, attempt: attempt + 1}
		time.AfterFunc(delay, func() {
			select {
			case n.queue <- next:
			default:
				log.Printf("notify: queue full, dropping retry %s/%s", ev.Type, ev.MAC)
			}
		})
		return
	}
	log.Printf("notify: drop %s/%s after %d attempts: %v", ev.Type, ev.MAC, attempt+1, err)
}
