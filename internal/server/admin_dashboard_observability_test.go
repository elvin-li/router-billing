package server

import (
	"context"
	"strings"
	"testing"
)

// Dashboard's new v0.59 "过去 24 小时投递失败" attention panel should
// appear when sms_log or webhook_deliveries have recent failures, and
// stay hidden when both are clean.
func TestDashboardShowsObservabilityFailureAttention(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogSMS(ctx, "console", "13800260001", "test", false, "boom")
	_ = app.DB.LogWebhookDelivery(ctx, "evt", "AA:BB:CC:00:17:01", 0, 500, false, 12, "http 500")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/dashboard", nil, jar)
	if !strings.Contains(body, "过去 24 小时投递失败") {
		t.Error("dashboard should show the new failure-window attention panel")
	}
	if !strings.Contains(body, "1") || !strings.Contains(body, "条 SMS 发送失败") {
		t.Error("dashboard should show SMS failure count")
	}
	if !strings.Contains(body, "次 Webhook 投递失败") {
		t.Error("dashboard should show webhook failure count")
	}
}

func TestDashboardHidesObservabilityFailureAttentionWhenClean(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// Seed only SUCCESS rows — panel should remain hidden.
	_ = app.DB.LogSMS(ctx, "console", "13800260010", "ok", true, "")
	_ = app.DB.LogWebhookDelivery(ctx, "evt", "", 0, 200, true, 5, "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/dashboard", nil, jar)
	if strings.Contains(body, "过去 24 小时投递失败") {
		t.Error("dashboard should NOT show the panel when only success rows exist")
	}
}

// Attention() should report only failures in the last 24 hours. Insert a
// failure with sent_at=2 days ago and confirm the counter stays zero.
func TestAttentionSMSFailuresWindowIs24h(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.Exec(ctx, `INSERT INTO sms_log (provider, phone, message, success, error_msg, sent_at)
		VALUES ('console', '13800260020', 'old', 0, 'old fail', datetime('now', '-2 days'))`)
	att, _ := app.DB.Attention(ctx)
	if att.SMSFailures24h != 0 {
		t.Errorf("2-day-old failure should NOT count; got SMSFailures24h=%d", att.SMSFailures24h)
	}
}

func TestAttentionTotalExcludesObservabilityCounters(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// Only seed observability failures — the navbar Total() should
	// still be zero.
	_ = app.DB.LogSMS(ctx, "console", "13800260030", "fail", false, "x")
	_ = app.DB.LogWebhookDelivery(ctx, "evt", "", 0, 500, false, 1, "x")

	att, _ := app.DB.Attention(ctx)
	if att.SMSFailures24h == 0 || att.WebhookFailures24h == 0 {
		t.Fatal("observability counters should be populated")
	}
	if att.Total() != 0 {
		t.Errorf("Total() should NOT include observability counters; got %d", att.Total())
	}
}
