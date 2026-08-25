package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func payCreateJSON(t *testing.T, app *App, body string) int {
	t.Helper()
	h := app.Routes()
	req := httptest.NewRequest("POST", "/api/pay/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func countOrders(t *testing.T, app *App) int {
	t.Helper()
	orders, err := app.DB.ListOrders(contextForTest(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return len(orders)
}

// Regression (v0.97): pay-create used to insert the pending order BEFORE
// validating the provider, so every "unknown provider" request left an
// orphaned pending row (polled for 30 min, inflating pending counters).
func TestPayCreateUnknownProviderLeavesNoOrder(t *testing.T) {
	app := setupTestApp(t)
	code := payCreateJSON(t, app, `{"mac":"aa:bb:cc:dd:ee:01","plan":"month","provider":"paypal"}`)
	if code != 400 {
		t.Errorf("unknown provider status = %d, want 400", code)
	}
	if n := countOrders(t, app); n != 0 {
		t.Errorf("unknown provider left %d orphaned order(s), want 0", n)
	}
}

// Same regression for a known-but-disabled provider (WeChat/Alipay not
// configured in the test app).
func TestPayCreateDisabledProviderLeavesNoOrder(t *testing.T) {
	app := setupTestApp(t)
	for _, provider := range []string{"wechat", "alipay"} {
		code := payCreateJSON(t, app,
			`{"mac":"aa:bb:cc:dd:ee:02","plan":"month","provider":"`+provider+`"}`)
		if code != 400 {
			t.Errorf("%s (disabled) status = %d, want 400", provider, code)
		}
	}
	if n := countOrders(t, app); n != 0 {
		t.Errorf("disabled providers left %d orphaned order(s), want 0", n)
	}
}

// Provider is validated after MAC/plan, so those errors keep priority.
func TestPayCreateBadMACStillRejected(t *testing.T) {
	app := setupTestApp(t)
	if code := payCreateJSON(t, app, `{"mac":"nope","plan":"month","provider":"wechat"}`); code != 400 {
		t.Errorf("bad mac status = %d, want 400", code)
	}
	if code := payCreateJSON(t, app, `{"mac":"aa:bb:cc:dd:ee:03","plan":"bogus","provider":"wechat"}`); code != 400 {
		t.Errorf("bad plan status = %d, want 400", code)
	}
	if n := countOrders(t, app); n != 0 {
		t.Errorf("validation failures left %d order(s), want 0", n)
	}
}
