package server

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"router-billing/internal/config"
)

// API MAC list filters: confirm user_id / status / q each isolate
// correctly.
func TestAPIMACListByUserID(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u1, _ := app.DB.CreateUser(ctx, "13800160001", "h")
	u2, _ := app.DB.CreateUser(ctx, "13800160002", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:03:01", "phone", 30, &u1.ID)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:03:02", "tablet", 30, &u1.ID)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:03:03", "phone", 30, &u2.ID)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:03:04", "orphan", 30, nil)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs?user_id="+strconv.FormatInt(u1.ID, 10), "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var resp struct {
		MACs []struct {
			Mac string `json:"mac"`
		} `json:"macs"`
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count != 2 || len(resp.MACs) != 2 {
		t.Errorf("expected 2 MACs for u1; got count=%d len=%d", resp.Count, len(resp.MACs))
	}
}

func TestAPIMACListByStatus(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:04:01", "phone", 30, nil)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:04:02", "phone", 30, nil)
	_ = app.DB.SetMACStatus(ctx, "AA:BB:CC:00:04:02", "blocked")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs?status=blocked", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var resp struct {
		MACs []struct {
			Mac    string `json:"mac"`
			Status string `json:"status"`
		} `json:"macs"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, m := range resp.MACs {
		if m.Status != "blocked" {
			t.Errorf("filter leaked non-blocked: %+v", m)
		}
	}
	// Exactly one blocked.
	if len(resp.MACs) != 1 {
		t.Errorf("expected 1 blocked MAC; got %d", len(resp.MACs))
	}
}

func TestAPIMACListLimitRespected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		mac := "AA:BB:CC:00:05:" + macHex(i)
		_, _ = app.DB.UpsertMAC(ctx, mac, "phone", 30, nil)
	}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs?limit=10", "rb_w", "")
	var resp struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count != 10 {
		t.Errorf("limit not applied; got count=%d (want 10)", resp.Count)
	}
}

func TestAPIMACListBadUserIDIs400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs?user_id=notanumber", "rb_w", "")
	if rr.Code != 400 {
		t.Errorf("bad user_id should be 400; got %d", rr.Code)
	}
}

func TestAPIMACListUserIDComposesWithStatus(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800160003", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:06:01", "phone", 30, &u.ID)
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:06:02", "phone", 30, &u.ID)
	_ = app.DB.SetMACStatus(ctx, "AA:BB:CC:00:06:02", "blocked")

	h := app.Routes()
	rr := apiReq(t, h, "GET",
		"/api/admin/macs?user_id="+strconv.FormatInt(u.ID, 10)+"&status=blocked",
		"rb_w", "")
	var resp struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count != 1 {
		t.Errorf("user+status compose should give 1; got %d", resp.Count)
	}
}

// macHex converts 0..255 to a 2-digit upper-case hex string for MAC
// suffixes. Avoids importing fmt in the test path.
func macHex(i int) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{hex[(i>>4)&0xF], hex[i&0xF]})
}
