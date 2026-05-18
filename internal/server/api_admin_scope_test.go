package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"router-billing/internal/config"
)

// apiReq is a thin helper: build a request with a Bearer token, optional JSON
// body, fire it through the routes, return the recorder.
func apiReq(t *testing.T, h http.Handler, method, path, bearer, jsonBody string) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if jsonBody != "" {
		body = strings.NewReader(jsonBody)
	}
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, body)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestReadOnlyAPITokenCannotGrant(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_monitor_ro", Label: "monitor", ReadOnly: true},
	}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/macs/grant", "rb_monitor_ro",
		`{"mac":"aa:bb:cc:11:22:99","days":7}`)
	if rr.Code != 403 {
		t.Errorf("expected 403; got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "read-only") {
		t.Errorf("error should mention read-only; got %s", rr.Body.String())
	}

	// The MAC must NOT exist.
	if m, _ := app.DB.GetMAC(context.Background(), "AA:BB:CC:11:22:99"); m != nil {
		t.Error("MAC should not have been created by a read-only token")
	}
}

func TestReadOnlyAPITokenCannotRevoke(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_monitor_ro", Label: "monitor", ReadOnly: true},
	}
	// Seed a MAC.
	ctx := context.Background()
	_, _ = app.MACSvc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "seed", 30, nil)

	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/macs/revoke", "rb_monitor_ro",
		`{"mac":"aa:bb:cc:dd:ee:ff"}`)
	if rr.Code != 403 {
		t.Errorf("expected 403; got %d", rr.Code)
	}
	// MAC still there.
	if m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:FF"); m == nil {
		t.Error("MAC should not be deleted by a read-only token")
	}
}

func TestReadOnlyAPITokenCanListAndHealth(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_monitor_ro", Label: "monitor", ReadOnly: true},
	}
	h := app.Routes()

	rr := apiReq(t, h, "GET", "/api/admin/macs", "rb_monitor_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly GET /macs: %d body=%s", rr.Code, rr.Body.String())
	}
	rr2 := apiReq(t, h, "GET", "/api/admin/health", "rb_monitor_ro", "")
	if rr2.Code != 200 {
		t.Errorf("readonly GET /health: %d", rr2.Code)
	}
}

func TestWritableAPITokenStillGrantsAndRevokes(t *testing.T) {
	// Regression guard: adding the ReadOnly bit must not break legacy
	// full-access tokens (where readonly defaults to false).
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_full", Label: "ci"}, // ReadOnly defaults to false
	}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/macs/grant", "rb_full",
		`{"mac":"aa:bb:cc:dd:ee:11","days":7}`)
	if rr.Code != 200 {
		t.Fatalf("full grant: %d body=%s", rr.Code, rr.Body.String())
	}
	rr2 := apiReq(t, h, "POST", "/api/admin/macs/revoke", "rb_full",
		`{"mac":"aa:bb:cc:dd:ee:11"}`)
	if rr2.Code != 200 {
		t.Fatalf("full revoke: %d", rr2.Code)
	}
}

func TestMixedTokensEnforcedIndependently(t *testing.T) {
	// Two tokens, one each — verify they're matched + scoped independently.
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{
		{Token: "rb_full", Label: "writer"},
		{Token: "rb_ro", Label: "reader", ReadOnly: true},
	}
	h := app.Routes()

	rrW := apiReq(t, h, "POST", "/api/admin/macs/grant", "rb_full",
		`{"mac":"aa:bb:cc:dd:ee:22","days":7}`)
	if rrW.Code != 200 {
		t.Errorf("full grant: %d", rrW.Code)
	}
	rrR := apiReq(t, h, "POST", "/api/admin/macs/grant", "rb_ro",
		`{"mac":"aa:bb:cc:dd:ee:33","days":7}`)
	if rrR.Code != 403 {
		t.Errorf("readonly grant: %d (want 403)", rrR.Code)
	}
}

func TestMatchAPITokenFullReturnsNilOnMiss(t *testing.T) {
	c := &config.Config{
		APITokens: []config.APIToken{{Token: "yes", Label: "ok"}},
	}
	if got := c.MatchAPITokenFull(""); got != nil {
		t.Errorf("empty input should return nil; got %+v", got)
	}
	if got := c.MatchAPITokenFull("no"); got != nil {
		t.Errorf("wrong token should return nil; got %+v", got)
	}
	if got := c.MatchAPITokenFull("yes"); got == nil || got.Label != "ok" {
		t.Errorf("right token should return APIToken; got %+v", got)
	}
}

func TestMatchAPITokenBackwardCompat(t *testing.T) {
	// Old MatchAPIToken(string)string still works the way callers expect.
	c := &config.Config{
		APITokens: []config.APIToken{
			{Token: "yes", Label: "ok"},
			{Token: "yes2", Label: ""}, // empty label → "unnamed-token"
		},
	}
	if l := c.MatchAPIToken(""); l != "" {
		t.Errorf("empty input: got %q", l)
	}
	if l := c.MatchAPIToken("yes"); l != "ok" {
		t.Errorf("labeled token: got %q", l)
	}
	if l := c.MatchAPIToken("yes2"); l != "unnamed-token" {
		t.Errorf("unlabeled token: got %q", l)
	}
}
