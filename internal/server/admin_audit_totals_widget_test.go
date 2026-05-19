package server

import (
	"context"
	"strings"
	"testing"
)

// /admin/audit should show the v0.86 action-frequency chips for actions
// present in the filter window.
func TestAdminAuditPageShowsActionFrequencyChips(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin", "grant", "M1", "")
	app.DB.Audit(ctx, "admin", "grant", "M2", "")
	app.DB.Audit(ctx, "admin", "revoke", "M3", "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/audit", nil, jar)

	if !strings.Contains(body, "动作频次") {
		t.Error("page should show the 动作频次 (action frequency) heading")
	}
	// Each action should appear in the chip row.
	for _, action := range []string{"grant", "revoke"} {
		if !strings.Contains(body, ">"+action+"</code>") {
			t.Errorf("chip for action %q missing", action)
		}
	}
}

// Date range filter on the chip section. Note: loginAdmin() writes an
// admin-login audit row, so the audit table is NEVER truly empty in
// these tests. We assert on the SPECIFIC chip HTML pattern instead of
// the heading-string to avoid coupling to "first-load-no-rows" state.
func TestAdminAuditChipsHonorDateFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin", "uniq-event-Z", "M1", "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	// Future since → the chip row should NOT contain a chip for uniq-event-Z
	// (the chip-specific pattern is `<code...>uniq-event-Z</code>` and only
	// appears in the chip render, not in the filter dropdown's <option>).
	_, body := do(t, h, "GET", "/admin/audit?since=2099-01-01", nil, jar)
	if strings.Contains(body, ">uniq-event-Z</code>") {
		t.Error("future since should hide the action chip for uniq-event-Z")
	}
}
