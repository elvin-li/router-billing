package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"router-billing/internal/notify"
)

// Wire the App.Notifier.OnDelivery callback and verify that a successful
// send produces exactly one DB row with status_code=200 and success=true.
func TestNotifierOnDeliveryRecordsSuccess(t *testing.T) {
	app := setupTestApp(t)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = r.Body.Close()
	}))
	defer srv.Close()

	app.Cfg.Webhook.URL = srv.URL
	app.Notifier = notify.New(srv.URL, "")
	app.Notifier.OnDelivery = func(ev notify.Event, attempt, status int, ms int64, err error) {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		_ = app.DB.LogWebhookDelivery(context.Background(),
			ev.Type, ev.MAC, attempt, status, err == nil, ms, errMsg)
	}
	go app.Notifier.Run(context.Background())

	app.Notifier.Send(notify.Event{Type: "test", MAC: "AA:BB:CC:00:0F:01"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&hits) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("webhook never received")
	}
	// Give the callback a moment to land its DB row.
	deadline = time.Now().Add(1 * time.Second)
	var logs []struct {
		EventType  string
		MAC        string
		StatusCode int
		Success    bool
	}
	for time.Now().Before(deadline) {
		entries, _ := app.DB.RecentWebhookDeliveries(context.Background(), 10, false)
		if len(entries) > 0 {
			for _, e := range entries {
				logs = append(logs, struct {
					EventType  string
					MAC        string
					StatusCode int
					Success    bool
				}{e.EventType, e.MAC, e.StatusCode, e.Success})
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(logs) == 0 {
		t.Fatal("no webhook_deliveries row written")
	}
	if logs[0].EventType != "test" || logs[0].MAC != "AA:BB:CC:00:0F:01" {
		t.Errorf("row missing event/mac: %+v", logs[0])
	}
	if logs[0].StatusCode != 200 || !logs[0].Success {
		t.Errorf("expected 200+success; got status=%d success=%v", logs[0].StatusCode, logs[0].Success)
	}
}

// 500-responding upstream → success=false, error_msg captures the failure.
func TestNotifierOnDeliveryRecordsFailure(t *testing.T) {
	app := setupTestApp(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	app.Cfg.Webhook.URL = srv.URL
	app.Notifier = notify.New(srv.URL, "")
	app.Notifier.BackoffSchedule = []time.Duration{} // no retries — keep test fast
	app.Notifier.OnDelivery = func(ev notify.Event, attempt, status int, ms int64, err error) {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		_ = app.DB.LogWebhookDelivery(context.Background(),
			ev.Type, ev.MAC, attempt, status, err == nil, ms, errMsg)
	}
	go app.Notifier.Run(context.Background())

	app.Notifier.Send(notify.Event{Type: "test", MAC: "AA:BB:CC:00:0F:02"})
	// Wait for the row.
	deadline := time.Now().Add(2 * time.Second)
	var got []notify.Event
	for time.Now().Before(deadline) {
		entries, _ := app.DB.RecentWebhookDeliveries(context.Background(), 10, true)
		if len(entries) > 0 {
			for _, e := range entries {
				got = append(got, notify.Event{Type: e.EventType, MAC: e.MAC})
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(got) == 0 {
		t.Fatal("no failure row recorded")
	}
	if got[0].Type != "test" || got[0].MAC != "AA:BB:CC:00:0F:02" {
		t.Errorf("row mismatch: %+v", got[0])
	}
}

func TestRecentWebhookDeliveriesOnlyFailed(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "ok", "", 0, 200, true, 5, "")
	_ = app.DB.LogWebhookDelivery(ctx, "fail", "AA:BB:CC:DD:EE:FF", 0, 500, false, 5, "http 500")

	all, _ := app.DB.RecentWebhookDeliveries(ctx, 100, false)
	if len(all) != 2 {
		t.Errorf("expected both rows; got %d", len(all))
	}
	failed, _ := app.DB.RecentWebhookDeliveries(ctx, 100, true)
	if len(failed) != 1 || failed[0].EventType != "fail" {
		t.Errorf("only_failed should isolate the FAIL row; got %+v", failed)
	}
}

func TestPurgeWebhookDeliveriesRespectsCap(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		_ = app.DB.LogWebhookDelivery(ctx, "spam", "", 0, 200, true, 1, "")
	}
	if err := app.DB.PurgeWebhookDeliveries(ctx, 5); err != nil {
		t.Fatal(err)
	}
	all, _ := app.DB.RecentWebhookDeliveries(ctx, 100, false)
	if len(all) != 5 {
		t.Errorf("expected 5 after purge; got %d", len(all))
	}
}

func TestAdminWebhookLogPageRenders(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "redeem", "AA:BB:CC:DD:EE:42", 0, 200, true, 12, "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/webhook-log", nil, jar)
	for _, want := range []string{
		"Webhook 投递日志",
		"AA:BB:CC:DD:EE:42",
		"redeem",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestAdminWebhookLogOnlyFailedFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "ok-evt", "", 0, 200, true, 5, "")
	_ = app.DB.LogWebhookDelivery(ctx, "bad-evt", "", 0, 500, false, 5, "boom")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/webhook-log?only_failed=1", nil, jar)
	if !strings.Contains(body, "bad-evt") {
		t.Error("failed-only filter should show the FAIL row")
	}
	if strings.Contains(body, "ok-evt") {
		t.Error("failed-only filter should exclude the OK row")
	}
}
