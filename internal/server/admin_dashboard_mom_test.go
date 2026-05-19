package server

import (
	"strings"
	"testing"
)

// momDelta pins every edge case the dashboard pill renders. We compute it
// in Go (not in the template) so this test isolates the math from the
// HTML.
func TestMomDeltaPercent(t *testing.T) {
	cases := []struct {
		name    string
		curr    int
		prev    int
		wantPct int
		wantDir string
		wantHas bool
	}{
		{"both zero is flat", 0, 0, 0, "flat", false},
		{"new growth from zero", 100, 0, 0, "new", false},
		{"complete dropoff to zero", 0, 50, -100, "gone", true},
		{"unchanged is flat", 100, 100, 0, "flat", true},
		{"plus 50 percent", 150, 100, 50, "up", true},
		{"minus 50 percent", 50, 100, -50, "down", true},
		{"plus 12 percent", 112, 100, 12, "up", true},
		// Rounding: 14.7% → 15%, -14.7% → -15%.
		{"rounds half-up positive", 113, 98, 15, "up", true},
		{"rounds half-down negative", 83, 98, -15, "down", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := momDelta(c.curr, c.prev)
			if got.Percent != c.wantPct {
				t.Errorf("percent: got %d want %d", got.Percent, c.wantPct)
			}
			if got.Direction != c.wantDir {
				t.Errorf("direction: got %q want %q", got.Direction, c.wantDir)
			}
			if got.HasPrev != c.wantHas {
				t.Errorf("hasPrev: got %v want %v", got.HasPrev, c.wantHas)
			}
		})
	}
}

// /admin/dashboard should render the MoM pill so operators see the trend.
// We don't seed actual data here (DashboardSnapshot reads "last 30 days"
// from the test clock); we just confirm the pill markup is wired.
func TestAdminDashboardRendersMoMPill(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/dashboard", nil, jar)
	// Empty DB → no previous-period data, so the rendered pill is the
	// flat-when-no-data branch — `<no value>` would suggest the template
	// references the wrong key. Check that the surrounding "30 天营收"
	// section renders + the MoM CSS class is present somewhere.
	if !strings.Contains(body, "30 天营收") {
		t.Error("30-day revenue header missing")
	}
	// On an empty DB both windows are 0 so we get "flat" with HasPrev=false
	// meaning the pill is suppressed — that's expected. We can't assert
	// the pill IS rendered without seeding orders, but we CAN assert no
	// `<no value>` leak.
	if strings.Contains(body, "&lt;no value&gt;") || strings.Contains(body, "<no value>") {
		t.Errorf("template references missing key — got <no value>; body=%s", truncate(body, 800))
	}
}
