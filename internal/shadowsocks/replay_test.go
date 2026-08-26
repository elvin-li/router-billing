package shadowsocks

import (
	"testing"
	"time"
)

func TestReplayFilterRejectsReuse(t *testing.T) {
	f := newReplayFilter(time.Minute, 0)
	salt := []byte("0123456789abcdef0123456789abcdef")
	if err := f.check(salt); err != nil {
		t.Fatalf("first use should pass: %v", err)
	}
	if err := f.check(salt); err == nil {
		t.Fatal("second use of same salt should be rejected")
	}
}

func TestReplayFilterDistinctSaltsPass(t *testing.T) {
	f := newReplayFilter(time.Minute, 0)
	for i := 0; i < 100; i++ {
		salt := make([]byte, 32)
		salt[0] = byte(i)
		salt[7] = byte(i >> 8)
		salt[15] = byte(i * 7)
		if err := f.check(salt); err != nil {
			t.Fatalf("distinct salt %d rejected: %v", i, err)
		}
	}
}

func TestReplayFilterWindowExpiry(t *testing.T) {
	f := newReplayFilter(time.Minute, 0)
	now := time.Unix(1_700_000_000, 0)
	f.now = func() time.Time { return now }

	salt := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := f.check(salt); err != nil {
		t.Fatal(err)
	}
	// Advance past the window — the salt should be accepted again.
	now = now.Add(2 * time.Minute)
	if err := f.check(salt); err != nil {
		t.Fatalf("salt should be fresh after window expiry: %v", err)
	}
}

func TestReplayFilterDisabled(t *testing.T) {
	f := newReplayFilter(0, 0)
	salt := []byte("same-salt-every-time-0123456789xy")
	if err := f.check(salt); err != nil {
		t.Fatal(err)
	}
	if err := f.check(salt); err != nil {
		t.Fatal("disabled filter must always accept")
	}
}

func TestReplayFilterNilSafe(t *testing.T) {
	var f *replayFilter
	if err := f.check([]byte("x")); err != nil {
		t.Fatalf("nil filter should accept: %v", err)
	}
}

func TestReplayFilterBounded(t *testing.T) {
	f := newReplayFilter(time.Hour, 128)
	now := time.Unix(1_700_000_000, 0)
	f.now = func() time.Time { return now }
	for i := 0; i < 10_000; i++ {
		salt := make([]byte, 32)
		salt[0] = byte(i)
		salt[1] = byte(i >> 8)
		salt[2] = byte(i >> 16)
		_ = f.check(salt)
	}
	if f.size() > 128 {
		t.Fatalf("filter exceeded cap: size=%d", f.size())
	}
}
