package server

import (
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAdminAPITokensPageRenders(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_dashboard_xyz123", Label: "grafana", ReadOnly: true, RateLimitPerMin: 30},
		{Token: "rb_writer_abc789", Label: "ci"},
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/api-tokens", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	for _, want := range []string{"grafana", "ci", "rb_d…", "rb_w…", "只读", "读写", "30/分钟", "无限制"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestAdminAPITokensPageHidesFullToken(t *testing.T) {
	// Regression guard: the actual token string must NEVER appear in the
	// rendered HTML (only the 4-char prefix). A compromised admin browser
	// shouldn't be able to extract tokens via the UI.
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_DO_NOT_LEAK_xyz789super_secret", Label: "ops"},
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/api-tokens", nil, jar)
	if strings.Contains(body, "DO_NOT_LEAK_xyz789super_secret") {
		t.Error("UI leaks the full token value")
	}
	if !strings.Contains(body, "rb_D…") {
		t.Error("UI should show the 4-char prefix")
	}
}

func TestAdminAPITokensPageEmptyState(t *testing.T) {
	app := setupTestApp(t)
	// app.Cfg.APITokens left empty
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/api-tokens", nil, jar)
	if !strings.Contains(body, "没有配置 API token") {
		t.Error("empty-state message should appear when no tokens configured")
	}
}

func TestAdminAPITokensPageFlagsEmptyTokenValue(t *testing.T) {
	// Config typo: token field forgotten or empty.
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "", Label: "broken-config"},
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/api-tokens", nil, jar)
	if !strings.Contains(body, "空 token") {
		t.Error("empty-token row should be flagged with 空 token warning")
	}
}

func TestAdminAPITokensInSidebar(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	// Sidebar appears on any admin page — pick one we know works.
	_, body := do(t, h, "GET", "/admin/macs", nil, jar)
	if !strings.Contains(body, `href="/admin/api-tokens"`) {
		t.Error("sidebar should link to /admin/api-tokens")
	}
}
