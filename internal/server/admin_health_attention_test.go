package server

import (
	"context"
	"encoding/json"
	"testing"

	"router-billing/internal/config"
)

// /api/admin/health (and /admin/health via the same handler) should now
// expose the same attention counters the dashboard renders.
func TestAPIHealthIncludesAttentionCounters(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	// Seed a SMS failure so SMSFailures24h is nonzero.
	_ = app.DB.LogSMS(ctx, "console", "13800270001", "fail", false, "boom")
	// Seed a webhook failure too.
	_ = app.DB.LogWebhookDelivery(ctx, "evt", "AA:BB:CC:00:19:01", 0, 500, false, 5, "http 500")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/health", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var resp struct {
		Attention struct {
			ExpiringSoon       int `json:"expiring_soon"`
			StalePending       int `json:"stale_pending"`
			SuspendedUsers     int `json:"suspended_users"`
			FailedToday        int `json:"failed_today"`
			SMSFailures24h     int `json:"sms_failures_24h"`
			WebhookFailures24h int `json:"webhook_failures_24h"`
		} `json:"attention"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Attention.SMSFailures24h == 0 {
		t.Errorf("sms_failures_24h should be 1; got %d", resp.Attention.SMSFailures24h)
	}
	if resp.Attention.WebhookFailures24h == 0 {
		t.Errorf("webhook_failures_24h should be 1; got %d", resp.Attention.WebhookFailures24h)
	}
}

// Anti-regression: pre-v0.61 health fields must still be present so
// existing monitoring scripts don't break.
func TestAPIHealthBackwardCompatFields(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/health", "rb_w", "")
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"version", "uptime_seconds", "db_path", "db_size_bytes",
		"mac_total", "mac_active", "mac_expired", "user_count",
		"revenue_cents", "firewall_set_count", "firewall_set_status",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("legacy field %q missing from health payload", key)
		}
	}
}
