package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPISightingsReturnsRecent(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen)
		VALUES ('AA:BB:CC:00:20:01', '192.168.5.10', 'recent-host', ?, ?)`, now.Add(-2*time.Hour), now)
	_, _ = app.DB.Exec(ctx, `INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen)
		VALUES ('AA:BB:CC:00:20:02', '192.168.5.11', 'old-host', ?, ?)`, now.Add(-90*24*time.Hour), now.Add(-72*time.Hour))

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sightings?since_hours=24", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Sightings []struct {
			Mac      string `json:"mac"`
			Hostname string `json:"hostname"`
		} `json:"sightings"`
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	// Within 24h → only the recent one.
	if resp.Count != 1 || resp.Sightings[0].Mac != "AA:BB:CC:00:20:01" {
		t.Errorf("unexpected: %+v", resp)
	}
}

func TestAPISightingsWiderWindow(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen)
		VALUES ('AA:BB:CC:00:20:03', '192.168.5.12', 'middle', ?, ?)`, now.Add(-7*24*time.Hour), now.Add(-3*24*time.Hour))

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sightings?since_hours=168", "rb_w", "") // 7 days
	var resp struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count == 0 {
		t.Error("7-day window should include a 3-day-old sighting")
	}
}

func TestAPISightingsReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sightings", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly should be 200; got %d", rr.Code)
	}
}

func TestAPISightingsRejectsPOST(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/sightings", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("POST should be 405; got %d", rr.Code)
	}
}
