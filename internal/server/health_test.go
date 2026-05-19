package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicHealthReturnsOKWithVersion(t *testing.T) {
	app := setupTestApp(t)
	app.Version = "v0.30-test"
	h := app.Routes()

	for _, path := range []string{"/health", "/healthz"} {
		t.Run(path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", path, nil)
			h.ServeHTTP(rr, req)
			if rr.Code != 200 {
				t.Fatalf("expected 200; got %d body=%s", rr.Code, rr.Body.String())
			}
			var resp struct {
				Status        string `json:"status"`
				Version       string `json:"version"`
				UptimeSeconds int    `json:"uptime_seconds"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Status != "ok" {
				t.Errorf("status: got %q want %q", resp.Status, "ok")
			}
			if resp.Version != "v0.30-test" {
				t.Errorf("version not echoed: got %q", resp.Version)
			}
			if resp.UptimeSeconds < 0 {
				t.Errorf("uptime should be non-negative; got %d", resp.UptimeSeconds)
			}
		})
	}
}

// /health is public — no Authorization header, no admin cookie. The handler
// must not require auth or return a redirect to /admin/login.
func TestPublicHealthIsUnauthenticated(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	// Deliberately no Authorization, no cookies.
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("public health should not require auth; got %d", rr.Code)
	}
}

func TestPublicHealthRejectsPOST(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/health", strings.NewReader(""))
	h.ServeHTTP(rr, req)
	if rr.Code != 405 {
		t.Errorf("POST /health should be 405; got %d", rr.Code)
	}
}

// Anti-leak red-line: /health must NOT carry operational detail that
// /admin/health does. No row counts, no revenue, no provider names —
// those go behind auth.
func TestPublicHealthDoesNotLeakOperationalDetail(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	for _, banned := range []string{
		"mac_total", "mac_active", "user_count", "revenue_cents",
		"wechat_enabled", "alipay_enabled", "db_path", "firewall",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("public /health leaks %q: %s", banned, body)
		}
	}
}
