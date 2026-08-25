package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// A pay-create with an unknown/disabled provider must NOT leave an orphan
// pending order behind — the fallback poller would otherwise keep
// re-selecting it for 30 minutes and the stale-pending attention counter
// would nag the admin about a request that never got a QR code.
func TestPayCreateUnknownProviderLeavesNoOrder(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	for _, provider := range []string{"paypal", "wechat", "alipay", ""} {
		body := `{"mac":"aa:bb:cc:dd:ee:01","plan":"month","provider":"` + provider + `"}`
		req := httptest.NewRequest("POST", "/api/pay/create", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		// wechat/alipay are disabled in the test config; paypal is unknown.
		if rr.Code != 400 {
			t.Errorf("provider %q: status = %d, want 400", provider, rr.Code)
		}
	}

	orders, err := app.DB.ListOrders(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 0 {
		t.Fatalf("orphan orders created: %+v", orders)
	}
}
