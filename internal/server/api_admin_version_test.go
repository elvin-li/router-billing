package server

import (
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIVersionReturnsSnapshot(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.Version = "v0.81-test"
	h := app.Routes()

	rr := apiReq(t, h, "GET", "/api/admin/version", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Version       string `json:"version"`
		UptimeSeconds int    `json:"uptime_seconds"`
		WechatEnabled bool   `json:"wechat_enabled"`
		AlipayEnabled bool   `json:"alipay_enabled"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Version != "v0.81-test" {
		t.Errorf("version not echoed: %q", resp.Version)
	}
	if resp.UptimeSeconds < 0 {
		t.Errorf("uptime should be >= 0; got %d", resp.UptimeSeconds)
	}
}

func TestAPIVersionReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/version", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly should be 200; got %d", rr.Code)
	}
}

func TestAPIVersionRejectsPOST(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/version", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("POST should be 405; got %d", rr.Code)
	}
}

// Anti-leak: response should NOT contain any user / MAC / order data.
// It's deliberately a minimal payload.
func TestAPIVersionMinimal(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/version", "rb_w", "")
	body := rr.Body.String()
	for _, banned := range []string{"mac_total", "user_count", "revenue", "db_path", "password"} {
		if strings.Contains(body, banned) {
			t.Errorf("version payload includes operational detail %q: %s", banned, body)
		}
	}
}
