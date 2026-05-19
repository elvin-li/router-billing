package server

import (
	"context"
	"strings"
	"testing"
)

func TestAdminExportSMSLogReturnsCSV(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogSMS(ctx, "console", "13800410001", "csv-export-test", true, "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/export/sms-log.csv", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if res.Header.Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Errorf("Content-Type wrong: %q", res.Header.Get("Content-Type"))
	}
	// Header row + the seeded message.
	if !strings.Contains(body, "id,sent_at,provider,phone,message,success,error_msg") {
		t.Error("CSV header missing")
	}
	if !strings.Contains(body, "csv-export-test") {
		t.Error("CSV row missing seeded message")
	}
	if !strings.Contains(body, "13800410001") {
		t.Error("CSV row missing phone")
	}
}

func TestAdminExportSMSLogFilteredFilename(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	// No filter → plain filename.
	res, _ := do(t, h, "GET", "/admin/export/sms-log.csv", nil, jar)
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, `"sms-log.csv"`) {
		t.Errorf("unfiltered should be sms-log.csv; got %q", cd)
	}
	// Filtered → -filtered suffix.
	res, _ = do(t, h, "GET", "/admin/export/sms-log.csv?only_failed=1", nil, jar)
	if cd := res.Header.Get("Content-Disposition"); !strings.Contains(cd, "sms-log-filtered.csv") {
		t.Errorf("filtered should be sms-log-filtered.csv; got %q", cd)
	}
}

func TestAdminExportWebhookLogReturnsCSV(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "redeem", "AA:BB:CC:00:23:01", 0, 200, true, 12, "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/export/webhook-log.csv", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "id,sent_at,event_type,mac,attempt,status_code,success,duration_ms,error_msg") {
		t.Error("CSV header missing")
	}
	if !strings.Contains(body, "AA:BB:CC:00:23:01") {
		t.Error("CSV row missing MAC")
	}
	if !strings.Contains(body, "redeem") {
		t.Error("CSV row missing event_type")
	}
}

func TestAdminExportWebhookLogHonorsFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "wanted-event", "M1", 0, 200, true, 5, "")
	_ = app.DB.LogWebhookDelivery(ctx, "other-event", "M1", 0, 200, true, 5, "")
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/webhook-log.csv?event_type=wanted-event", nil, jar)
	if !strings.Contains(body, "wanted-event") {
		t.Error("filter should include matching row")
	}
	if strings.Contains(body, "other-event") {
		t.Error("filter should exclude non-matching row")
	}
}

func TestAdminSMSLogPageHasExportButton(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/sms-log", nil, jar)
	if !strings.Contains(body, "/admin/export/sms-log.csv") {
		t.Error("sms-log page should expose the export-csv link")
	}
}

func TestAdminWebhookLogPageHasExportButton(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/webhook-log", nil, jar)
	if !strings.Contains(body, "/admin/export/webhook-log.csv") {
		t.Error("webhook-log page should expose the export-csv link")
	}
}
