package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"router-billing/internal/notify"
)

func TestAdminTestWebhookEnqueuesEvent(t *testing.T) {
	app := setupTestApp(t)

	// Spin up a capture server.
	var hits int32
	var bodyMu sync.Mutex
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the FULL body (a single Read may return a partial chunk) and
		// store it BEFORE bumping hits — the waiter below treats hits≥1 as
		// "lastBody is ready", so the old order was a checked-then-empty race.
		b, _ := io.ReadAll(r.Body)
		bodyMu.Lock()
		lastBody = string(b)
		bodyMu.Unlock()
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Wire a real Notifier so Send actually delivers.
	app.Cfg.Webhook.URL = srv.URL
	app.Notifier = notify.New(srv.URL, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.Notifier.Run(ctx)

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/maintenance/test-webhook",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "ok=webhook_test") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}

	// Wait briefly for async delivery.
	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(&hits) < 1 {
		select {
		case <-deadline:
			t.Fatal("webhook server never received the test event")
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
	bodyMu.Lock()
	body := lastBody
	bodyMu.Unlock()
	if !strings.Contains(body, `"type":"test"`) {
		t.Errorf("payload should be type=test; got %s", body)
	}

	// Audit entry.
	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "webhook_test" {
			found = true
		}
	}
	if !found {
		t.Error("webhook_test audit entry not written")
	}
}

func TestAdminTestWebhookNoURLReturnsErr(t *testing.T) {
	app := setupTestApp(t)
	// app.Cfg.Webhook.URL is empty in setupTestApp — leave it.
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]
	res, _ := do(t, h, "POST", "/admin/maintenance/test-webhook",
		url.Values{"_csrf": {csrf}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "webhook_not_configured") {
		t.Errorf("expected webhook_not_configured; got %s", res.Header.Get("Location"))
	}
}

func TestAdminMaintenancePageShowsWebhookSection(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Webhook.URL = "https://example.com/hook"
	app.Cfg.Webhook.Secret = "shh"
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/maintenance", nil, jar)
	if !strings.Contains(body, "Webhook") {
		t.Error("page should have a Webhook section")
	}
	if !strings.Contains(body, "https://example.com/hook") {
		t.Error("page should show the configured URL")
	}
	if !strings.Contains(body, "启用（HMAC-SHA256）") {
		t.Error("page should indicate signing is enabled")
	}
}

func TestAdminMaintenancePageEmptyWebhookShowsExample(t *testing.T) {
	app := setupTestApp(t)
	// no URL
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/maintenance", nil, jar)
	if !strings.Contains(body, "未配置") {
		t.Error("page should say 未配置 when no webhook URL")
	}
	if !strings.Contains(body, "router-billing-events") {
		t.Error("page should show the config example")
	}
}
