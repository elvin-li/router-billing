package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// captureSrv records every request body + signature header and returns the
// status code dictated by `respondWith` (callable: each call may return a new code).
type captureSrv struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
	respFn  func(call int) int
	calls   int32
}

func newCaptureSrv(t *testing.T, respFn func(int) int) *captureSrv {
	t.Helper()
	c := &captureSrv{respFn: respFn}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		c.headers = append(c.headers, r.Header.Clone())
		call := int(atomic.AddInt32(&c.calls, 1))
		c.mu.Unlock()
		code := 200
		if c.respFn != nil {
			code = c.respFn(call)
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *captureSrv) snapshot() ([][]byte, []http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := make([][]byte, len(c.bodies))
	copy(b, c.bodies)
	h := make([]http.Header, len(c.headers))
	copy(h, c.headers)
	return b, h
}

func TestNilNotifierIsNoOp(t *testing.T) {
	var n *Notifier // explicitly nil
	n.Send(Event{Type: "pay"})
	// Empty Notifier (no URL) too:
	n2 := New("", "")
	n2.Send(Event{Type: "pay"})
}

func TestDeliversWithCorrectSignature(t *testing.T) {
	const secret = "shared-secret-xyz"
	srv := newCaptureSrv(t, nil) // always 200

	n := New(srv.srv.URL, secret)
	n.RetryDelay = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	n.Send(Event{Type: "pay", At: now, MAC: "AA:BB:CC:DD:EE:FF", Amount: 100})

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&srv.calls) < 1 {
		select {
		case <-deadline:
			t.Fatal("webhook never received")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	bodies, headers := srv.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("got %d calls; want 1", len(bodies))
	}

	// Verify signature header is hex HMAC-SHA256 of body
	gotSig := headers[0].Get("X-Router-Billing-Signature")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(bodies[0])
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotSig), []byte(wantSig)) {
		t.Errorf("bad signature\n got  %s\n want %s", gotSig, wantSig)
	}

	// Body should be the event we sent.
	var ev Event
	if err := json.Unmarshal(bodies[0], &ev); err != nil {
		t.Fatalf("body: %v", err)
	}
	if ev.Type != "pay" || ev.MAC != "AA:BB:CC:DD:EE:FF" || ev.Amount != 100 {
		t.Errorf("body mismatch: %+v", ev)
	}

	// Content-Type set
	if ct := headers[0].Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type %q", ct)
	}
}

func TestNoSignatureWhenSecretEmpty(t *testing.T) {
	srv := newCaptureSrv(t, nil)
	n := New(srv.srv.URL, "") // no secret
	n.RetryDelay = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Send(Event{Type: "ping"})

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&srv.calls) < 1 {
		select {
		case <-deadline:
			t.Fatal("never received")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	_, headers := srv.snapshot()
	if got := headers[0].Get("X-Router-Billing-Signature"); got != "" {
		t.Errorf("expected no signature; got %q", got)
	}
}

func TestRetriesOnceOn5xx(t *testing.T) {
	srv := newCaptureSrv(t, func(call int) int {
		if call == 1 {
			return 500
		}
		return 200
	})
	n := New(srv.srv.URL, "")
	n.RetryDelay = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Send(Event{Type: "pay"})

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&srv.calls) < 2 {
		select {
		case <-deadline:
			t.Fatalf("only %d calls; want 2", atomic.LoadInt32(&srv.calls))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	// Give it a moment to ensure no third call.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&srv.calls); got != 2 {
		t.Errorf("expected exactly 2 calls (1 fail + 1 retry); got %d", got)
	}
}

func TestExponentialBackoffRetriesUntilSchedule(t *testing.T) {
	// Server fails the first 2 attempts, succeeds on the 3rd. With a
	// 3-step schedule the worker should make exactly 3 calls.
	srv := newCaptureSrv(t, func(call int) int {
		if call <= 2 {
			return 503
		}
		return 200
	})
	n := New(srv.srv.URL, "")
	n.BackoffSchedule = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond, 5 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Send(Event{Type: "pay"})

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&srv.calls) < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d calls; want 3", atomic.LoadInt32(&srv.calls))
		default:
			time.Sleep(2 * time.Millisecond)
		}
	}
	// Give it a moment to confirm no 4th call.
	time.Sleep(40 * time.Millisecond)
	if got := atomic.LoadInt32(&srv.calls); got != 3 {
		t.Errorf("expected exactly 3 calls; got %d", got)
	}
}

func TestPersistentFailureDropsAfterFullSchedule(t *testing.T) {
	srv := newCaptureSrv(t, func(int) int { return 500 })
	n := New(srv.srv.URL, "")
	n.BackoffSchedule = []time.Duration{2 * time.Millisecond, 2 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Send(Event{Type: "pay"})

	// 1 initial + 2 retries = 3 total. Wait for all, then confirm no 4th.
	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&srv.calls) < 3 {
		select {
		case <-deadline:
			t.Fatalf("only %d calls; want 3", atomic.LoadInt32(&srv.calls))
		default:
			time.Sleep(1 * time.Millisecond)
		}
	}
	time.Sleep(30 * time.Millisecond)
	if got := atomic.LoadInt32(&srv.calls); got != 3 {
		t.Errorf("expected exactly 3 calls (drop after full schedule); got %d", got)
	}
}

func TestLegacyRetryDelayBehavesAsOneShot(t *testing.T) {
	// Old code-paths set RetryDelay and expect "one retry then drop".
	// Confirm that still works when BackoffSchedule is nil.
	srv := newCaptureSrv(t, func(int) int { return 500 })
	n := New(srv.srv.URL, "")
	n.RetryDelay = 5 * time.Millisecond
	n.BackoffSchedule = nil // legacy path

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Send(Event{Type: "pay"})

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&srv.calls) < 2 {
		select {
		case <-deadline:
			t.Fatalf("only %d calls; want 2", atomic.LoadInt32(&srv.calls))
		default:
			time.Sleep(1 * time.Millisecond)
		}
	}
	time.Sleep(30 * time.Millisecond)
	if got := atomic.LoadInt32(&srv.calls); got != 2 {
		t.Errorf("legacy RetryDelay should mean 1 retry only; got %d calls", got)
	}
}

func TestEmptyScheduleMeansNoRetry(t *testing.T) {
	// Explicit empty slice = opt out of retries entirely (differs from nil
	// which falls back to DefaultBackoffSchedule).
	srv := newCaptureSrv(t, func(int) int { return 500 })
	n := New(srv.srv.URL, "")
	n.BackoffSchedule = []time.Duration{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Send(Event{Type: "pay"})

	// Wait long enough that a retry would have fired if one were scheduled.
	time.Sleep(80 * time.Millisecond)
	if got := atomic.LoadInt32(&srv.calls); got != 1 {
		t.Errorf("empty schedule should mean exactly 1 attempt; got %d", got)
	}
}

func TestQueueDropsWhenFull(t *testing.T) {
	// Slow receiver — first request blocks; queue fills.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n := New(srv.URL, "")
	n.RetryDelay = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	// 1 in flight + 64 in queue. The 66th should be dropped.
	for i := 0; i < 70; i++ {
		n.Send(Event{Type: "spam"})
	}
	// Currently we have no public "drop count" — just assert Send doesn't block.
	// (If it did, this test would hang.)
	close(block)
}

func TestRetryBackoffDoesNotBlockFreshEvents(t *testing.T) {
	// A failing event with a long backoff must not stall the worker:
	// fresh events sent AFTER the failure should be delivered while the
	// failed one is still waiting for its retry slot. Pre-v0.108 the
	// worker slept through the backoff in-place, so the fresh event
	// would not arrive until the retry schedule was exhausted.
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev Event
		_ = json.Unmarshal(body, &ev)
		mu.Lock()
		seen = append(seen, ev.Type)
		mu.Unlock()
		if ev.Type == "poison" {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	n := New(srv.URL, "")
	// One retry after a long-ish delay. The fresh event must land well
	// before this delay elapses.
	n.BackoffSchedule = []time.Duration{600 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	n.Send(Event{Type: "poison"})
	n.Send(Event{Type: "fresh"})

	freshBy := time.Now().Add(400 * time.Millisecond) // well inside the 600ms backoff
	for {
		mu.Lock()
		gotFresh := false
		for _, s := range seen {
			if s == "fresh" {
				gotFresh = true
			}
		}
		mu.Unlock()
		if gotFresh {
			break
		}
		if time.Now().After(freshBy) {
			t.Fatal("fresh event was blocked behind the failing event's backoff")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// And the poison event's retry should still happen (2 total attempts).
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		poison := 0
		for _, s := range seen {
			if s == "poison" {
				poison++
			}
		}
		mu.Unlock()
		if poison >= 2 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("poison retry never fired; deliveries: %v", seen)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestPanicInOnDeliveryDoesNotKillWorker(t *testing.T) {
	// The server package wires OnDelivery to a DB write. If that hook
	// panics, the worker must survive and keep delivering later events —
	// an unrecovered panic in the worker goroutine kills the whole
	// process.
	srv := newCaptureSrv(t, nil) // always 200
	n := New(srv.srv.URL, "")
	n.BackoffSchedule = []time.Duration{}
	first := true
	n.OnDelivery = func(ev Event, attempt, status int, durationMs int64, err error) {
		if first {
			first = false
			panic("boom in delivery log hook")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	n.Send(Event{Type: "one"})
	n.Send(Event{Type: "two"})

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&srv.calls) < 2 {
		select {
		case <-deadline:
			t.Fatalf("worker died after OnDelivery panic; only %d deliveries", atomic.LoadInt32(&srv.calls))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestAtIsSetIfZero(t *testing.T) {
	srv := newCaptureSrv(t, nil)
	n := New(srv.srv.URL, "")
	n.RetryDelay = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	n.Send(Event{Type: "pay"}) // At intentionally zero

	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&srv.calls) < 1 {
		select {
		case <-deadline:
			t.Fatal("never received")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	bodies, _ := srv.snapshot()
	var ev Event
	_ = json.Unmarshal(bodies[0], &ev)
	if ev.At.IsZero() {
		t.Error("At should be populated server-side when sent zero")
	}
	if time.Since(ev.At) > time.Minute {
		t.Errorf("At should be ~now; got %s", ev.At)
	}
}
