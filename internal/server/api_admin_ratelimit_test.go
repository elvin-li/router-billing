package server

import (
	"testing"

	"router-billing/internal/config"
)

func TestAPITokenRateLimitEnforced(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_throttle", Label: "ci", RateLimitPerMin: 3},
	}
	h := app.Routes()

	// First 3 requests within budget.
	for i := 0; i < 3; i++ {
		rr := apiReq(t, h, "GET", "/api/admin/health", "rb_throttle", "")
		if rr.Code != 200 {
			t.Fatalf("req %d should be 200; got %d", i+1, rr.Code)
		}
	}
	// 4th hits the cap.
	rr := apiReq(t, h, "GET", "/api/admin/health", "rb_throttle", "")
	if rr.Code != 429 {
		t.Errorf("4th request should be 429; got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAPITokenNoRateLimitWhenZero(t *testing.T) {
	// Default (RateLimitPerMin=0) → no limit. Confirm 20 requests all pass.
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_unlim", Label: "ops"}}
	h := app.Routes()
	for i := 0; i < 20; i++ {
		rr := apiReq(t, h, "GET", "/api/admin/health", "rb_unlim", "")
		if rr.Code != 200 {
			t.Fatalf("req %d hit unexpected limit: %d", i+1, rr.Code)
		}
	}
}

func TestAPITokenRateLimitIsPerToken(t *testing.T) {
	// Two tokens, one throttled, one not — confirm they don't share a
	// counter.
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_a", Label: "a", RateLimitPerMin: 2},
		{Token: "rb_b", Label: "b", RateLimitPerMin: 100},
	}
	h := app.Routes()

	// Burn token a's budget.
	apiReq(t, h, "GET", "/api/admin/health", "rb_a", "")
	apiReq(t, h, "GET", "/api/admin/health", "rb_a", "")
	rr := apiReq(t, h, "GET", "/api/admin/health", "rb_a", "")
	if rr.Code != 429 {
		t.Errorf("a 3rd: %d", rr.Code)
	}

	// Token b unaffected.
	rrB := apiReq(t, h, "GET", "/api/admin/health", "rb_b", "")
	if rrB.Code != 200 {
		t.Errorf("b should be unaffected; got %d", rrB.Code)
	}
}

func TestAPITokenRateLimitDoesNotBlockOtherEndpoints(t *testing.T) {
	// The limiter is per-token, not per-token-per-path. Confirm the
	// budget is shared across endpoints (so a script that hits health +
	// macs both counts against the same bucket).
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_shared", Label: "monitor", RateLimitPerMin: 2, ReadOnly: true},
	}
	h := app.Routes()
	apiReq(t, h, "GET", "/api/admin/health", "rb_shared", "")
	apiReq(t, h, "GET", "/api/admin/macs", "rb_shared", "")
	rr := apiReq(t, h, "GET", "/api/admin/health", "rb_shared", "")
	if rr.Code != 429 {
		t.Errorf("third call across endpoints should hit 429; got %d", rr.Code)
	}
}
