package server

import (
	"net/http/httptest"
	"testing"

	"router-billing/internal/config"
)

// mustProxyNets is a test helper turning CIDR strings into the parsed form
// the App carries.
func appWithProxies(t *testing.T, proxies ...string) *App {
	t.Helper()
	sec := config.Security{TrustedProxies: proxies}
	nets, err := sec.TrustedProxyNets()
	if err != nil {
		t.Fatalf("parse proxies %v: %v", proxies, err)
	}
	return &App{trustedProxies: nets}
}

// Without trusted_proxies configured, X-Forwarded-For must be IGNORED —
// otherwise any client can spoof it to rotate around per-IP rate limits.
func TestClientIPIgnoresXFFByDefault(t *testing.T) {
	a := &App{}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("X-Forwarded-For", "10.9.9.9")
	if got := a.clientIP(r); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want peer 203.0.113.7 (XFF must be ignored)", got)
	}
}

func TestClientIPTrustsXFFFromTrustedProxy(t *testing.T) {
	a := appWithProxies(t, "192.0.2.0/24")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.42")
	if got := a.clientIP(r); got != "198.51.100.42" {
		t.Errorf("clientIP = %q, want forwarded 198.51.100.42", got)
	}
}

// Rightmost-untrusted rule: a client that prepends junk to XFF can't spoof
// its identity — the proxy appends the true peer last, and trusted-proxy
// hops are skipped from the right.
func TestClientIPRightmostUntrusted(t *testing.T) {
	a := appWithProxies(t, "192.0.2.0/24", "10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	// client-spoofed junk, real client, internal proxy hop
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.42, 10.0.0.5")
	if got := a.clientIP(r); got != "198.51.100.42" {
		t.Errorf("clientIP = %q, want 198.51.100.42 (rightmost untrusted)", got)
	}
}

func TestClientIPUntrustedPeerWithXFF(t *testing.T) {
	a := appWithProxies(t, "10.0.0.0/8")
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:5555" // NOT a trusted proxy
	r.Header.Set("X-Forwarded-For", "198.51.100.42")
	if got := a.clientIP(r); got != "203.0.113.7" {
		t.Errorf("clientIP = %q, want peer (untrusted peer's XFF ignored)", got)
	}
}

func TestTrustedProxyNetsRejectsGarbage(t *testing.T) {
	sec := config.Security{TrustedProxies: []string{"not-an-ip"}}
	if _, err := sec.TrustedProxyNets(); err == nil {
		t.Fatal("expected error for invalid trusted_proxies entry")
	}
	sec = config.Security{TrustedProxies: []string{"127.0.0.1", "10.0.0.0/8", "::1"}}
	nets, err := sec.TrustedProxyNets()
	if err != nil {
		t.Fatalf("valid entries rejected: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("want 3 nets, got %d", len(nets))
	}
}
