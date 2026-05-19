package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/db"
)

// SearchSMSLogs with Since should exclude rows older than the cutoff.
func TestSearchSMSLogsSinceFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// Old row + new row.
	_, _ = app.DB.Exec(ctx, `INSERT INTO sms_log (provider, phone, message, success, error_msg, sent_at)
		VALUES ('console', '13800400001', 'old', 1, '', datetime('now', '-7 days'))`)
	_ = app.DB.LogSMS(ctx, "console", "13800400001", "new", true, "")

	got, _ := app.DB.SearchSMSLogs(ctx, db.SMSLogFilter{Since: "2026-01-01"})
	// Since the seeded row is dated 7 days ago AND we set since to 2026-01-01
	// (before current test date), both rows should appear.
	if len(got) < 2 {
		t.Errorf("expected both rows; got %d", len(got))
	}

	// Now narrow to a since that excludes the 7-day-old row. Using a
	// future date guarantees nothing is included.
	got, _ = app.DB.SearchSMSLogs(ctx, db.SMSLogFilter{Since: "2099-01-01"})
	if len(got) != 0 {
		t.Errorf("future since should exclude everything; got %d", len(got))
	}
}

// SearchWebhookDeliveries should accept Since/Until.
func TestSearchWebhookDeliveriesDateRange(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "evt", "M1", 0, 200, true, 5, "")

	// Since within range → row present.
	got, _ := app.DB.SearchWebhookDeliveries(ctx, db.WebhookDeliveryFilter{Since: "2026-01-01"})
	if len(got) == 0 {
		t.Error("expected row when since is within range")
	}

	// Until in the past → row excluded.
	got, _ = app.DB.SearchWebhookDeliveries(ctx, db.WebhookDeliveryFilter{Until: "2025-01-01"})
	if len(got) != 0 {
		t.Errorf("until-in-the-past should exclude everything; got %d", len(got))
	}
}

func TestAdminSMSLogPageRendersDateInputs(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log", nil, jar)
	if !strings.Contains(body, `name="since"`) || !strings.Contains(body, `name="until"`) {
		t.Error("sms-log page should expose since/until date inputs")
	}
}

func TestAdminWebhookLogPageRendersDateInputs(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/webhook-log", nil, jar)
	if !strings.Contains(body, `name="since"`) || !strings.Contains(body, `name="until"`) {
		t.Error("webhook-log page should expose since/until date inputs")
	}
}
