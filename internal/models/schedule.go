package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MacSchedule restricts when a MAC is allowed online.
// Days are ISO weekday numbers: 1=Mon, 7=Sun.
// StartMin/EndMin are minutes-from-midnight (0..1440). If EndMin <= StartMin
// the window wraps midnight (e.g. 22:00-06:00).
//
// An empty Days slice OR StartMin == EndMin means "no schedule" — MAC is
// always allowed (within its expires_at).
type MacSchedule struct {
	Days     []int `json:"days"`
	StartMin int   `json:"start_min"`
	EndMin   int   `json:"end_min"`
}

// Active returns true when the MAC should be online at time t.
// A zero-value MacSchedule (no Days) is interpreted as "always".
func (s MacSchedule) Active(t time.Time) bool {
	if len(s.Days) == 0 || s.StartMin == s.EndMin {
		return true
	}
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7 // Go: Sunday=0; we use ISO Sun=7
	}
	dayOK := false
	for _, d := range s.Days {
		if d == wd {
			dayOK = true
			break
		}
	}
	if !dayOK {
		return false
	}
	nowMin := t.Hour()*60 + t.Minute()
	if s.StartMin < s.EndMin {
		return nowMin >= s.StartMin && nowMin < s.EndMin
	}
	// wraps midnight
	return nowMin >= s.StartMin || nowMin < s.EndMin
}

// IsEmpty reports whether the schedule is the "always allow" no-op value.
func (s MacSchedule) IsEmpty() bool {
	return len(s.Days) == 0 || s.StartMin == s.EndMin
}

// String returns a human-readable description, e.g. "Mon-Fri 18:00-22:00"
// or "周一二三四五 18:00-22:00".
func (s MacSchedule) String() string {
	if s.IsEmpty() {
		return ""
	}
	names := []string{"", "一", "二", "三", "四", "五", "六", "日"}
	var ds []string
	for _, d := range s.Days {
		if d >= 1 && d <= 7 {
			ds = append(ds, names[d])
		}
	}
	return fmt.Sprintf("周%s %02d:%02d-%02d:%02d",
		strings.Join(ds, ""),
		s.StartMin/60, s.StartMin%60,
		s.EndMin/60, s.EndMin%60)
}

// ParseSchedule decodes the JSON column stored in macs.schedule_json.
// Empty string returns the zero value (always allow), no error.
func ParseSchedule(j string) (MacSchedule, error) {
	if strings.TrimSpace(j) == "" {
		return MacSchedule{}, nil
	}
	var s MacSchedule
	if err := json.Unmarshal([]byte(j), &s); err != nil {
		return s, err
	}
	if s.StartMin < 0 || s.StartMin > 1439 || s.EndMin < 0 || s.EndMin > 1439 {
		return s, fmt.Errorf("schedule minutes out of range")
	}
	for _, d := range s.Days {
		if d < 1 || d > 7 {
			return s, fmt.Errorf("invalid weekday: %d", d)
		}
	}
	return s, nil
}

// JSON encodes the schedule for storage. Returns "" for the no-op value.
func (s MacSchedule) JSON() string {
	if s.IsEmpty() {
		return ""
	}
	b, _ := json.Marshal(s)
	return string(b)
}
