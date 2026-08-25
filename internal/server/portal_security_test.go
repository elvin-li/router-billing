package server

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
)

// ---------- /redeem rate limit vs X-Forwarded-For rotation ----------

// A client rotating X-Forwarded-For must NOT get a fresh rate-limit
// bucket per request. Pre-v0.107 the header was trusted unconditionally,
// so the /redeem limiter — the only defense against brute-forcing
// voucher codes — was fully bypassable with one spoofed header per POST.
// With the default empty security.trusted_proxies the header is ignored
// and all attempts share the RemoteAddr bucket.
func TestRedeemRateLimitNotBypassableViaXFF(t *testing.T) {
	app := setupTestApp(t)
	app.redeemLimiter = newRateLimiter(3, time.Hour)
	h := app.Routes()

	form := url.Values{"code": {"AAAAAAAAAA22"}, "mac": {"aa:bb:cc:dd:ee:ff"}}
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("POST", "/redeem", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Fresh spoofed source per attempt — the bypass vector.
		req.Header.Set("X-Forwarded-For", "10.9.9."+string(rune('1'+i)))
		req.RemoteAddr = "192.0.2.50:1234" // same real peer throughout
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		loc := strings.ToLower(rr.Header().Get("Location"))
		limited := strings.Contains(loc, "%e5%b0%9d%e8%af%95") // "尝试" (rate-limited message)
		if i < 3 && limited {
			t.Errorf("attempt %d should not be rate-limited yet: %s", i, loc)
		}
		if i == 3 && !limited {
			t.Errorf("attempt %d should be rate-limited despite rotating XFF: %s", i, loc)
		}
	}
}

// ---------- /pay/success receipt-order gating ----------

func TestPaySuccessReceiptOnlyForRecentPaidOrders(t *testing.T) {
	ctx := context.Background()
	app := setupTestApp(t)
	h := app.Routes()

	mkPaid := func(orderNo, mac string) {
		t.Helper()
		if err := app.DB.CreateOrder(ctx, &models.Order{
			OrderNo: orderNo, Mac: mac, Plan: "month", Days: 30,
			AmountCents: 100, Status: models.OrderPending, PaymentMethod: "wechat",
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := app.DB.MarkOrderPaid(ctx, orderNo, "TRADE-"+orderNo); err != nil {
			t.Fatal(err)
		}
	}

	// Fresh payment → receipt link offered.
	mkPaid("ORD-FRESH-1", "AA:BB:CC:00:11:22")
	res, body := do(t, h, "GET", "/pay/success?mac=AA:BB:CC:00:11:22", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if !strings.Contains(body, "ORD-FRESH-1") {
		t.Error("fresh paid order should offer the receipt link")
	}

	// Old payment (2h ago) → no receipt link: /pay/success?mac= must not
	// be usable as a MAC → order-history oracle by anyone who knows a
	// neighbor's MAC.
	mkPaid("ORD-OLD-1", "AA:BB:CC:00:33:44")
	if _, err := app.DB.Exec(ctx,
		`UPDATE orders SET paid_at = ? WHERE order_no = ?`,
		time.Now().UTC().Add(-2*time.Hour), "ORD-OLD-1"); err != nil {
		t.Fatal(err)
	}
	_, body = do(t, h, "GET", "/pay/success?mac=AA:BB:CC:00:33:44", nil, nil)
	if strings.Contains(body, "ORD-OLD-1") {
		t.Error("stale paid order must not be discoverable via /pay/success?mac=")
	}
	// The expiry row is gated the same way (mac isn't the requester's).
	if strings.Contains(body, "到期时间") {
		t.Error("expiry row must not render for a foreign MAC without a recent order")
	}

	// Malformed mac query param is dropped entirely (no reflection, no lookup).
	res, body = do(t, h, "GET", "/pay/success?mac="+url.QueryEscape(`"><svg onload=x>`), nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("garbage mac status = %d", res.StatusCode)
	}
	if strings.Contains(body, "svg onload") {
		t.Error("garbage mac must not be reflected")
	}
}

// ---------- SSE streams stop after session revocation ----------

// sseStreamClosesOnRevoke connects to an SSE endpoint with a live admin
// session, revokes the session mid-stream, and asserts the server closes
// the connection instead of streaming forever.
func sseStreamClosesOnRevoke(t *testing.T, path string) {
	t.Helper()
	app := setupTestApp(t)
	app.sseTick = 25 * time.Millisecond
	srv := httptest.NewServer(app.Routes())
	defer srv.Close()

	// Real login for a real session token. Don't follow the 303 —
	// the Set-Cookie lives on the redirect response itself.
	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirect.PostForm(srv.URL+"/admin/login",
		url.Values{"username": {"admin"}, "password": {"admin-pw"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var adminTok string
	for _, c := range resp.Cookies() {
		if c.Name == adminCookieName {
			adminTok = c.Value
		}
	}
	if adminTok == "" {
		t.Fatal("no admin session cookie")
	}

	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: adminTok})
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if stream.StatusCode != 200 {
		t.Fatalf("stream connect: %d", stream.StatusCode)
	}

	// First frame arrives while the session is alive.
	rd := bufio.NewReader(stream.Body)
	if _, err := rd.ReadString('\n'); err != nil {
		t.Fatalf("no initial frame: %v", err)
	}

	// Revoke the session (as /admin/sessions/revoke or panic would).
	if err := app.DB.DeleteSession(context.Background(), adminTok); err != nil {
		t.Fatal(err)
	}

	// The server must close the stream within a few ticks.
	done := make(chan struct{})
	go func() {
		for {
			if _, err := rd.ReadString('\n'); err != nil {
				close(done)
				return
			}
		}
	}()
	select {
	case <-done:
		// closed — good
	case <-time.After(3 * time.Second):
		t.Fatalf("%s kept streaming after session revocation", path)
	}
}

func TestDevicesStreamClosesOnSessionRevoke(t *testing.T) {
	sseStreamClosesOnRevoke(t, "/admin/devices/stream")
}

func TestStatsStreamClosesOnSessionRevoke(t *testing.T) {
	sseStreamClosesOnRevoke(t, "/admin/stats/stream")
}
