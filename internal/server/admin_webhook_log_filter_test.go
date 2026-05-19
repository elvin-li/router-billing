package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/db"
)

func TestSearchWebhookDeliveriesByEventType(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "order_paid", "AA:BB:CC:00:1C:01", 0, 200, true, 5, "")
	_ = app.DB.LogWebhookDelivery(ctx, "redeem", "AA:BB:CC:00:1C:02", 0, 200, true, 5, "")

	got, _ := app.DB.SearchWebhookDeliveries(ctx, db.WebhookDeliveryFilter{EventType: "order_paid"})
	if len(got) != 1 || got[0].EventType != "order_paid" {
		t.Errorf("event_type filter wrong; got %+v", got)
	}
}

func TestSearchWebhookDeliveriesByMAC(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "redeem", "AA:BB:CC:00:1C:10", 0, 200, true, 5, "")
	_ = app.DB.LogWebhookDelivery(ctx, "redeem", "AA:BB:CC:00:1C:11", 0, 200, true, 5, "")

	got, _ := app.DB.SearchWebhookDeliveries(ctx, db.WebhookDeliveryFilter{MAC: "AA:BB:CC:00:1C:10"})
	if len(got) != 1 || got[0].MAC != "AA:BB:CC:00:1C:10" {
		t.Errorf("mac filter wrong; got %+v", got)
	}
}

// Compose: event_type + only_failed
func TestSearchWebhookDeliveriesCompose(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "redeem", "M1", 0, 200, true, 5, "")       // ok
	_ = app.DB.LogWebhookDelivery(ctx, "redeem", "M1", 1, 500, false, 5, "5xx")   // fail
	_ = app.DB.LogWebhookDelivery(ctx, "order_paid", "M1", 0, 500, false, 5, "x") // wrong event

	got, _ := app.DB.SearchWebhookDeliveries(ctx, db.WebhookDeliveryFilter{
		EventType: "redeem", OnlyFailed: true,
	})
	if len(got) != 1 || got[0].EventType != "redeem" || got[0].Success {
		t.Errorf("compose filter wrong; got %+v", got)
	}
}

// /admin/webhook-log should render the new filter form.
func TestAdminWebhookLogPageRendersFilterForm(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/webhook-log", nil, jar)
	for _, want := range []string{
		`name="event_type"`, `name="mac"`, `name="only_failed"`,
		"event_type (如 order_paid)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

// /admin/webhook-log?event_type=X should show only matching rows.
func TestAdminWebhookLogPageHonorsEventTypeFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_ = app.DB.LogWebhookDelivery(ctx, "uniq-event-A", "AA:BB:CC:00:1C:30", 0, 200, true, 5, "")
	_ = app.DB.LogWebhookDelivery(ctx, "uniq-event-B", "AA:BB:CC:00:1C:31", 0, 200, true, 5, "")
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/webhook-log?event_type=uniq-event-A", nil, jar)
	if !strings.Contains(body, "uniq-event-A") {
		t.Error("filtered event should appear")
	}
	if strings.Contains(body, "uniq-event-B") {
		t.Error("non-matching event leaked")
	}
}
