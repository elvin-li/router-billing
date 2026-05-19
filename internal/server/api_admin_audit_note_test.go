package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIAuditNoteHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/audit/note", "rb_w",
		`{"note":"Refund issued via gateway dashboard","target":"ORD-12345"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}

	entries, _ := app.DB.ListAudit(context.Background(), 5)
	found := false
	for _, e := range entries {
		if e.Action == "manual_note" && e.Target == "ORD-12345" {
			found = true
			if !strings.Contains(e.Detail, "Refund issued via gateway dashboard") {
				t.Errorf("note text missing from audit detail: %q", e.Detail)
			}
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit should mark via=api; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("audit row not created")
	}
}

func TestAPIAuditNoteCustomAction(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/audit/note", "rb_w",
		`{"note":"v1.2.3 rolled out","action":"deploy","target":"prod"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	entries, _ := app.DB.ListAudit(context.Background(), 5)
	found := false
	for _, e := range entries {
		if e.Action == "deploy" && e.Target == "prod" {
			found = true
		}
	}
	if !found {
		t.Error("custom-action audit row not created")
	}
}

func TestAPIAuditNoteEmptyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/audit/note", "rb_w", `{"note":"   "}`)
	if rr.Code != 400 {
		t.Errorf("empty note should be 400; got %d", rr.Code)
	}
}

func TestAPIAuditNoteBadActionRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	// Action with a slash should be rejected by planKeyOK.
	rr := apiReq(t, h, "POST", "/api/admin/audit/note", "rb_w",
		`{"note":"x","action":"has/slash"}`)
	if rr.Code != 400 {
		t.Errorf("bad action should be 400; got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"field":"action"`) {
		t.Errorf("400 should include field=action hint; got %s", rr.Body.String())
	}
}

func TestAPIAuditNoteLongNoteTruncated(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	long := strings.Repeat("A", 2000)
	rr := apiReq(t, h, "POST", "/api/admin/audit/note", "rb_w",
		`{"note":"`+long+`"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	entries, _ := app.DB.ListAudit(context.Background(), 5)
	for _, e := range entries {
		if e.Action == "manual_note" {
			// Detail should be truncated to ≤1000 chars of note +
			// roughly 30 chars of via=api ip=... suffix.
			if len(e.Detail) > 1100 {
				t.Errorf("audit detail not truncated; got %d chars", len(e.Detail))
			}
		}
	}
}

func TestAPIAuditNoteReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/audit/note", "rb_ro",
		`{"note":"trying"}`)
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}
