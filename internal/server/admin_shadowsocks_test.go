package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/db"
	"router-billing/internal/shadowsocks"
)

func enableSS(app *App) {
	app.Cfg.Shadowsocks = config.Shadowsocks{
		Enabled:  true,
		Listen:   "192.168.5.1:8388",
		Method:   "chacha20-ietf-poly1305",
		Password: "test-shadowsocks-password",
		Tag:      "test-router",
	}
	app.Cfg.PortalHost = "192.168.5.1"
}

func TestAdminShadowsocksDisabled(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/shadowsocks", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "未启用") {
		t.Error("disabled page should say 未启用")
	}
	if strings.Contains(body, "ss://") {
		t.Error("disabled page must not contain an ss:// link")
	}
}

func TestAdminShadowsocksEnabledMasksURI(t *testing.T) {
	app := setupTestApp(t)
	enableSS(app)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/shadowsocks", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "已启用") {
		t.Error("enabled page should say 已启用")
	}
	// Without ?reveal=1 the password/URI must NOT be present.
	if strings.Contains(body, "ss://") {
		t.Error("masked page leaked the ss:// URI")
	}
	if strings.Contains(body, "test-shadowsocks-password") {
		t.Error("masked page leaked the password")
	}
	if !strings.Contains(body, "显示分享链接") {
		t.Error("masked page should offer a reveal button")
	}
}

func TestAdminShadowsocksRevealShowsURIAndAudits(t *testing.T) {
	app := setupTestApp(t)
	enableSS(app)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/shadowsocks?reveal=1", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "ss://") {
		t.Error("reveal page should contain the ss:// URI")
	}
	// The QR is served from a separate endpoint (no secret in the img URL).
	if !strings.Contains(body, "/admin/shadowsocks/qr") {
		t.Error("reveal page should embed the QR endpoint")
	}
	// An audit row must have been written for the reveal.
	rows, _ := app.DB.SearchAudit(context.Background(), db.AuditFilter{Action: "shadowsocks_uri_view"})
	if len(rows) == 0 {
		t.Error("reveal should write a shadowsocks_uri_view audit row")
	}
}

func TestAdminShadowsocksQR(t *testing.T) {
	app := setupTestApp(t)
	enableSS(app)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/shadowsocks/qr", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("qr status = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("qr content-type = %q", ct)
	}
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("qr Cache-Control = %q, want no-store", cc)
	}
}

func TestAdminShadowsocksQRDisabled404(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/shadowsocks/qr", nil, jar)
	if res.StatusCode != 404 {
		t.Errorf("qr when disabled = %d, want 404", res.StatusCode)
	}
}

func TestAdminShadowsocksRequiresAuth(t *testing.T) {
	app := setupTestApp(t)
	enableSS(app)
	h := app.Routes()
	res, _ := do(t, h, "GET", "/admin/shadowsocks", nil, nil)
	if res.StatusCode != 303 {
		t.Errorf("unauth = %d, want 303 redirect", res.StatusCode)
	}
}

func TestMetricsShadowsocksGauges(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	// Disabled: enabled gauge should be 0 and present.
	_, body := do(t, h, "GET", "/metrics", nil, nil)
	if !strings.Contains(body, "router_billing_shadowsocks_enabled 0") {
		t.Errorf("expected shadowsocks_enabled 0 when disabled:\n%s", body)
	}

	// Enabled: attach metrics and confirm counters are exposed.
	m := &shadowsocks.Metrics{}
	app.SSMetrics = m
	_, body = do(t, h, "GET", "/metrics", nil, nil)
	if !strings.Contains(body, "router_billing_shadowsocks_enabled 1") {
		t.Errorf("expected shadowsocks_enabled 1 when SSMetrics set:\n%s", body)
	}
	for _, want := range []string{
		"router_billing_shadowsocks_connections_total",
		"router_billing_shadowsocks_bytes_in_total",
		"router_billing_shadowsocks_bytes_out_total",
		"router_billing_shadowsocks_replay_rejected_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}
