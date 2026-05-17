package sms

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSenderNilReturnsErrNotConfigured(t *testing.T) {
	var s *Sender
	if err := s.Send(context.Background(), "13800138000", "x"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("nil sender: %v, want ErrNotConfigured", err)
	}
	if (&Sender{}).Available() {
		t.Error("zero Sender should not be Available")
	}
	if (&Sender{}).Name() != "none" {
		t.Errorf("Name() = %q", (&Sender{}).Name())
	}
}

func TestConsoleProviderSendAndRecent(t *testing.T) {
	c := NewConsole(3)
	s := &Sender{P: c}

	if !s.Available() {
		t.Error("wired sender should be Available")
	}
	if s.Name() != "console" {
		t.Errorf("Name = %q", s.Name())
	}

	for i := 0; i < 5; i++ {
		if err := s.Send(context.Background(), "13800138000", "msg-"+string(rune('A'+i))); err != nil {
			t.Fatal(err)
		}
	}

	// Cap=3 → only the last 3 survive.
	rec := c.Recent()
	if len(rec) != 3 {
		t.Fatalf("len = %d, want 3 (ring buffer capped)", len(rec))
	}
	if !strings.HasSuffix(rec[0].Message, "C") || !strings.HasSuffix(rec[2].Message, "E") {
		t.Errorf("oldest-first sweep wrong: %+v", rec)
	}
	for _, r := range rec {
		if r.Phone != "13800138000" {
			t.Errorf("phone = %q", r.Phone)
		}
		if r.At.IsZero() {
			t.Error("At not set")
		}
	}
}

func TestConsoleDefaultCap(t *testing.T) {
	c := NewConsole(0)
	if c.cap != 50 {
		t.Errorf("default cap = %d, want 50", c.cap)
	}
}
