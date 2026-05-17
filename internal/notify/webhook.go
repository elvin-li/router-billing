// Package notify pushes events to an admin-configured webhook URL.
// Useful for: payment notifications to shopkeeper's own dashboard,
// monitoring (anomaly alerts), Slack/Lark/钉钉 bots, etc.
//
// Delivery model:
//   - Best-effort, fire-and-forget queue with 64-deep buffer
//   - Single worker goroutine — events are serialized (preserves order)
//   - HMAC-SHA256 signature in `X-Router-Billing-Signature` header
//   - Drops on full queue, logs to standard logger
//   - One retry after 2 seconds; further failures are dropped (with log)
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
	URL        string
	Secret     string
	RetryDelay time.Duration // 0 = default 2s; tests inject short values

	HTTPClient *http.Client
	queue      chan Event
}

func New(url, secret string) *Notifier {
	if url == "" {
		return &Notifier{} // no-op
	}
	return &Notifier{
		URL:        url,
		Secret:     secret,
		RetryDelay: 2 * time.Second,
		HTTPClient: &http.Client{Timeout: 8 * time.Second},
		queue:      make(chan Event, 64),
	}
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
	if attempt < 1 {
		// One retry, default 2s. Tests set RetryDelay to ~10ms.
		delay := n.RetryDelay
		if delay <= 0 {
			delay = 2 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		n.deliver(ctx, ev, attempt+1)
		return
	}
	log.Printf("notify: drop %s/%s after retries: %v", ev.Type, ev.MAC, err)
}
