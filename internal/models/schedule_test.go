package models

import (
	"testing"
	"time"
)

func TestScheduleActive(t *testing.T) {
	// Mon-Fri 18:00-22:00
	weekday := MacSchedule{Days: []int{1, 2, 3, 4, 5}, StartMin: 18 * 60, EndMin: 22 * 60}
	// At Tue 19:00 — allowed
	if !weekday.Active(time.Date(2026, 5, 19, 19, 0, 0, 0, time.UTC)) {
		t.Error("Tue 19:00 should be allowed")
	}
	// Sat 19:00 — denied
	if weekday.Active(time.Date(2026, 5, 23, 19, 0, 0, 0, time.UTC)) {
		t.Error("Sat 19:00 should be denied (weekday only)")
	}
	// Tue 17:59 — denied
	if weekday.Active(time.Date(2026, 5, 19, 17, 59, 0, 0, time.UTC)) {
		t.Error("Tue 17:59 should be denied (before start)")
	}
	// Tue 22:00 — denied (exclusive end)
	if weekday.Active(time.Date(2026, 5, 19, 22, 0, 0, 0, time.UTC)) {
		t.Error("Tue 22:00 should be denied (exclusive end)")
	}
}

func TestScheduleMidnightWrap(t *testing.T) {
	night := MacSchedule{Days: []int{1, 2, 3, 4, 5, 6, 7}, StartMin: 22 * 60, EndMin: 6 * 60}
	if !night.Active(time.Date(2026, 5, 19, 23, 0, 0, 0, time.UTC)) {
		t.Error("23:00 should be allowed")
	}
	if !night.Active(time.Date(2026, 5, 19, 2, 0, 0, 0, time.UTC)) {
		t.Error("02:00 should be allowed (wrap)")
	}
	if night.Active(time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)) {
		t.Error("10:00 should be denied")
	}
}

func TestScheduleEmpty(t *testing.T) {
	zero := MacSchedule{}
	for hr := 0; hr < 24; hr++ {
		if !zero.Active(time.Date(2026, 5, 19, hr, 0, 0, 0, time.UTC)) {
			t.Errorf("empty schedule should always allow; failed at %d", hr)
		}
	}
}

func TestScheduleSunday(t *testing.T) {
	s := MacSchedule{Days: []int{7}, StartMin: 0, EndMin: 1440}
	// 2026-05-17 is a Sunday
	if !s.Active(time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)) {
		t.Error("Sun should match days=[7]")
	}
}

func TestParseAndJSON(t *testing.T) {
	s := MacSchedule{Days: []int{1, 5}, StartMin: 60, EndMin: 120}
	j := s.JSON()
	parsed, err := ParseSchedule(j)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Days) != 2 || parsed.StartMin != 60 || parsed.EndMin != 120 {
		t.Errorf("round-trip failed: %+v", parsed)
	}
	if z, _ := ParseSchedule(""); !z.IsEmpty() {
		t.Error("empty string should parse to empty")
	}
	if _, err := ParseSchedule("not json"); err == nil {
		t.Error("bad json should error")
	}
	if _, err := ParseSchedule(`{"days":[8],"start_min":0,"end_min":1}`); err == nil {
		t.Error("invalid day should error")
	}
}
