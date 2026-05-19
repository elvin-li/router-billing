package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-billing/internal/config"
	"router-billing/internal/notify"
)

func TestAPIWebhookTestEnqueuesEvent(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = r.Body.Close()
	}))
	defer srv.Close()

	app.Cfg.Webhook.URL = srv.URL
	app.Notifier = notify.New(srv.URL, "")
	go app.Notifier.Run(context.Background())

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/webhook/test", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
		URL    string `json:"url"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Status != "enqueued" || resp.URL != srv.URL {
		t.Errorf("unexpected response: %+v", resp)
	}

	// Wait briefly for the queue worker to deliver.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&hits) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Error("webhook test event never reached the upstream")
	}
}

func TestAPIWebhookTestNoURL503(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.Cfg.Webhook.URL = "" // not configured
	app.Notifier = notify.New("", "")
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/webhook/test", "rb_w", "")
	if rr.Code != 503 {
		t.Errorf("expected 503; got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not configured") {
		t.Errorf("error message should mention 'not configured'; got %s", rr.Body.String())
	}
}

func TestAPIWebhookTestReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/webhook/test", "rb_ro", "")
	if rr.Code != 403 {
		t.Errorf("readonly should be 403; got %d", rr.Code)
	}
}

// Audit row should record via=api so a reviewer can distinguish UI test
// clicks from automation / CI integration tests.
func TestAPIWebhookTestAuditViaAPI(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.Cfg.Webhook.URL = "https://example.invalid/hook"
	app.Notifier = notify.New("https://example.invalid/hook", "")
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/webhook/test", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	entries, _ := app.DB.ListAudit(context.Background(), 5)
	found := false
	for _, e := range entries {
		if e.Action == "webhook_test" {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit should mark via=api; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("webhook_test audit row missing")
	}
}
