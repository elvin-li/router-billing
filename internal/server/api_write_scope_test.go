package server

import (
	"strings"
	"testing"

	"router-billing/internal/config"
)

// v0.130: requireAPITokenWrite rejects read-only tokens on EVERY method.
// The old carve-out only blocked non-GET, which today is equivalent
// (every write handler is POST-only and 405s a GET) — but it meant one
// future write-registered handler answering GET would silently open its
// payload/side effects to monitoring-grade tokens. The middleware now
// enforces the scope itself; a read-only GET on a write route is 403
// (scope error), never 405 (method hint from inside the handler).
func TestAPIWriteRoutesRejectReadonlyOnAnyMethod(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_ro", Label: "monitor", ReadOnly: true},
		{Token: "rb_w", Label: "ops"},
	}
	h := app.Routes()

	writeRoutes := []string{
		"/api/admin/macs/grant",
		"/api/admin/macs/revoke",
		"/api/admin/orders/refund",
		"/api/admin/vouchers/generate",
		"/api/admin/users/grant",
		"/api/admin/maintenance/expire-now",
		"/api/admin/plans/save",
	}
	for _, route := range writeRoutes {
		for _, method := range []string{"GET", "POST"} {
			rr := apiReq(t, h, method, route, "rb_ro", "")
			if rr.Code != 403 {
				t.Errorf("%s %s with readonly token: want 403, got %d (body=%s)",
					method, route, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "read-only") {
				t.Errorf("%s %s: error should name the read-only scope; got %s",
					method, route, rr.Body.String())
			}
		}
	}

	// Full-scope tokens keep the old behavior: GET on a write route is a
	// handler-level 405, POST proceeds into the handler (400 for the empty
	// body here — anything but 401/403 proves the middleware let it through).
	rr := apiReq(t, h, "GET", "/api/admin/macs/grant", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("full token GET on write route: want 405, got %d", rr.Code)
	}
	rr = apiReq(t, h, "POST", "/api/admin/macs/grant", "rb_w", "")
	if rr.Code == 401 || rr.Code == 403 {
		t.Errorf("full token POST must pass the middleware; got %d", rr.Code)
	}
}
