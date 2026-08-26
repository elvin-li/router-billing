package server

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateRunesASCII(t *testing.T) {
	if got := truncateRunes("hello", 10); got != "hello" {
		t.Errorf("under-limit string changed: %q", got)
	}
	if got := truncateRunes("hello", 5); got != "hello" {
		t.Errorf("exact-limit string changed: %q", got)
	}
	if got := truncateRunes("hello world", 5); got != "hello" {
		t.Errorf("ascii truncation = %q", got)
	}
	if got := truncateRunes("x", 0); got != "" {
		t.Errorf("max=0 should return empty, got %q", got)
	}
}

func TestTruncateRunesNeverSplitsUTF8(t *testing.T) {
	// 每个汉字 3 字节 — cutting "你好世界" at any byte budget must yield
	// valid UTF-8 that is a prefix of the original.
	s := "你好世界ab测试"
	for max := 0; max <= len(s)+2; max++ {
		got := truncateRunes(s, max)
		if !utf8.ValidString(got) {
			t.Fatalf("max=%d produced invalid UTF-8: %q", max, got)
		}
		if len(got) > max {
			t.Fatalf("max=%d produced %d bytes", max, len(got))
		}
		if got != s[:len(got)] {
			t.Fatalf("max=%d not a prefix: %q", max, got)
		}
	}
	// Spot-check: a 4-byte budget over 3-byte runes keeps exactly one rune.
	if got := truncateRunes("你好", 4); got != "你" {
		t.Errorf("4-byte budget over 3-byte runes = %q, want 你", got)
	}
}

func TestHandlerTruncationSitesUseValidUTF8(t *testing.T) {
	// The regression the helper exists for: a 1000-byte cap over a Chinese
	// note used to slice mid-rune. Simulate the exact old failure input.
	note := ""
	for len(note) <= 1000 {
		note += "长备注内容"
	}
	got := truncateRunes(note, 1000)
	if !utf8.ValidString(got) {
		t.Fatal("1000-byte cap over Chinese text produced invalid UTF-8")
	}
	if len(got) > 1000 {
		t.Fatalf("cap exceeded: %d bytes", len(got))
	}
}
