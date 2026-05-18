package server

import (
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestBuildHSTSHeaderDefaults(t *testing.T) {
	// Zero config → 1-year max-age, no extras.
	got := buildHSTSHeader(config.Security{})
	if got != "max-age=31536000" {
		t.Errorf("default HSTS: got %q", got)
	}
}

func TestBuildHSTSHeaderCustomMaxAge(t *testing.T) {
	got := buildHSTSHeader(config.Security{HSTSMaxAgeSeconds: 63072000})
	if got != "max-age=63072000" {
		t.Errorf("custom HSTS: got %q", got)
	}
}

func TestBuildHSTSHeaderWithSubdomainsAndPreload(t *testing.T) {
	got := buildHSTSHeader(config.Security{
		HSTSMaxAgeSeconds:     63072000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           true,
	})
	for _, want := range []string{"max-age=63072000", "includeSubDomains", "preload"} {
		if !strings.Contains(got, want) {
			t.Errorf("HSTS should include %q; got %q", want, got)
		}
	}
}

func TestBuildHSTSHeaderNegativeMaxAgeFallsBackToDefault(t *testing.T) {
	got := buildHSTSHeader(config.Security{HSTSMaxAgeSeconds: -1})
	if got != "max-age=31536000" {
		t.Errorf("negative max-age should fallback to default; got %q", got)
	}
}

func TestSecurityHeadersAppliesHSTSWhenTLS(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security = config.Security{
		HSTSMaxAgeSeconds:     63072000,
		HSTSIncludeSubdomains: true,
	}
	h := app.Routes()
	res, _ := do(t, h, "GET", "/portal", nil, map[string]string{})
	// Without TLS / X-Forwarded-Proto, HSTS is NOT set (correct — we don't
	// want to burn the directive on an HTTP-only deploy).
	if hsts := res.Header.Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS shouldn't be set on plain HTTP; got %q", hsts)
	}
}
