package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/db"
)

// SearchAudit with Q must filter on the detail column. Each test seeds
// three rows then asserts only the matching one comes back.
func TestSearchAuditByDetailSubstring(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "system", "expiry_reminder_failed", "AA:BB:CC:00:13:01", "phone=13800300001 err=upstream timeout")
	app.DB.Audit(ctx, "system", "expiry_reminder_failed", "AA:BB:CC:00:13:02", "phone=13800300002 err=upstream timeout")
	app.DB.Audit(ctx, "admin", "grant", "AA:BB:CC:00:13:03", "days=30 via=ui ip=10.0.0.1")

	got, err := app.DB.SearchAudit(ctx, db.AuditFilter{Q: "via=ui"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 via=ui row; got %d", len(got))
	}
	if got[0].Action != "grant" {
		t.Errorf("expected grant row; got %s", got[0].Action)
	}

	// Substring match: "13800300001" appears in only one row.
	got, _ = app.DB.SearchAudit(ctx, db.AuditFilter{Q: "13800300001"})
	if len(got) != 1 || !strings.Contains(got[0].Detail, "13800300001") {
		t.Errorf("phone substring should match exactly 1; got %d %+v", len(got), got)
	}
}

// Q composes with other filters: action=grant AND q=ip=10.0.0 should
// intersect.
func TestSearchAuditQComposesWithAction(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin", "grant", "X", "ip=10.0.0.1")
	app.DB.Audit(ctx, "admin", "grant", "Y", "ip=192.168.1.1")
	app.DB.Audit(ctx, "admin", "revoke", "Z", "ip=10.0.0.1")

	got, _ := app.DB.SearchAudit(ctx, db.AuditFilter{Action: "grant", Q: "10.0.0"})
	if len(got) != 1 {
		t.Errorf("compose filter should give 1; got %d", len(got))
	}
	if len(got) > 0 && got[0].Target != "X" {
		t.Errorf("expected target X; got %s", got[0].Target)
	}
}

// /api/admin/audit?q=... should route through.
func TestAPIAuditListWithQFilter(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	app.DB.Audit(ctx, "admin", "grant", "M", "days=30 via=api")
	app.DB.Audit(ctx, "admin", "grant", "N", "days=30 via=ui")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/audit?q=via=api", "rb_w", "")
	var resp struct {
		Entries []struct {
			Target string `json:"target"`
		} `json:"entries"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Entries) != 1 || resp.Entries[0].Target != "M" {
		t.Errorf("api q filter should give M only; got %+v", resp.Entries)
	}
}

// /admin/audit page should render the new q input.
func TestAdminAuditPageShowsQInput(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/audit", nil, jar)
	if !strings.Contains(body, `name="q"`) {
		t.Error("audit page should expose the q input")
	}
	if !strings.Contains(body, "详情关键字") {
		t.Error("audit page should label the q input")
	}
}
