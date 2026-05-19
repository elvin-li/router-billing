package server

import (
	"context"
	"encoding/json"
	"testing"

	"router-billing/internal/config"
)

func TestAPIWebhookLogReturnsRecent(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	for i, mac := range []string{"AA:BB:CC:00:10:01", "AA:BB:CC:00:10:02", "AA:BB:CC:00:10:03"} {
		_ = app.DB.LogWebhookDelivery(ctx, "redeem", mac, 0, 200, true, int64(5+i), "")
	}

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/webhook/log", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Logs []struct {
			EventType  string `json:"event_type"`
			MAC        string `json:"mac"`
			StatusCode int    `json:"status_code"`
			Success    bool   `json:"success"`
		} `json:"logs"`
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count != 3 {
		t.Errorf("expected 3 rows; got count=%d len=%d", resp.Count, len(resp.Logs))
	}
	// Newest first.
	if resp.Logs[0].MAC != "AA:BB:CC:00:10:03" {
		t.Errorf("newest-first: expected MAC 03; got %q", resp.Logs[0].MAC)
	}
}

func TestAPIWebhookLogOnlyFailedFilter(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "ok-evt", "", 0, 200, true, 1, "")
	_ = app.DB.LogWebhookDelivery(ctx, "bad-evt", "", 0, 500, false, 1, "http 500")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/webhook/log?only_failed=1", "rb_w", "")
	var resp struct {
		Logs []struct {
			EventType string `json:"event_type"`
			Success   bool   `json:"success"`
		} `json:"logs"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Logs) != 1 {
		t.Errorf("expected only the FAIL; got %d", len(resp.Logs))
	}
	if resp.Logs[0].EventType != "bad-evt" || resp.Logs[0].Success {
		t.Errorf("filter let wrong row through: %+v", resp.Logs[0])
	}
}

func TestAPIWebhookLogLimitRespected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		_ = app.DB.LogWebhookDelivery(ctx, "spam", "", 0, 200, true, 1, "")
	}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/webhook/log?limit=7", "rb_w", "")
	var resp struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count != 7 {
		t.Errorf("limit=7 should yield 7; got %d", resp.Count)
	}
}

func TestAPIWebhookLogReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/webhook/log", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly GET should be 200; got %d", rr.Code)
	}
}

func TestAPIWebhookLogPostRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/webhook/log", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("POST should be 405; got %d", rr.Code)
	}
}
