package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeExpirer struct {
	calls atomic.Int32
	err   error
}

func (f *fakeExpirer) ExpireDue(_ context.Context) (int, error) {
	f.calls.Add(1)
	return 0, f.err
}

func TestRunCallsInitialAndOnTick(t *testing.T) {
	e := &fakeExpirer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, e, 30*time.Millisecond); close(done) }()

	// Let at least 3 ticks fire + the initial one.
	time.Sleep(120 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
	got := e.calls.Load()
	if got < 3 {
		t.Errorf("expected ≥3 ExpireDue calls; got %d", got)
	}
}

func TestRunHonorsCtxCancelEvenIfTickPending(t *testing.T) {
	e := &fakeExpirer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, e, 30*time.Second); close(done) }()
	// Cancel before the second tick can land.
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("did not exit")
	}
	// Only the initial call should have happened.
	if got := e.calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 (initial) call; got %d", got)
	}
}

func TestRunSurvivesExpirerError(t *testing.T) {
	e := &fakeExpirer{err: errors.New("boom")}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, e, 20*time.Millisecond); close(done) }()
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done
	// Errors must NOT stop the cron.
	if got := e.calls.Load(); got < 3 {
		t.Errorf("expected ≥3 calls even with errors; got %d", got)
	}
}

func TestRunDefaultsIntervalWhenZero(t *testing.T) {
	// If interval ≤ 0, scheduler should default to 1 hour. We can't wait
	// an hour, so verify by canceling fast and noting only the initial fired.
	e := &fakeExpirer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, e, 0); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if got := e.calls.Load(); got != 1 {
		t.Errorf("expected default 1h interval to give us only the initial call; got %d", got)
	}
}
