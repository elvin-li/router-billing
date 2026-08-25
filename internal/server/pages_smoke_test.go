package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"router-billing/internal/models"
)

// seedEverything populates every table a template can range over, so the
// smoke test below exercises the non-empty row paths of every page. With
// the buffered render() (v0.102) a typo'd struct field inside any of those
// ranges turns the page into a clean 500 — which this test then catches.
func seedEverything(t *testing.T, app *App) (userID int64, orderNo string) {
	t.Helper()
	ctx := context.Background()

	u, err := app.DB.CreateUser(ctx, "13800139900", "hash")
	if err != nil {
		t.Fatal(err)
	}
	userID = u.ID

	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:99:01", "smoke device", 30, &userID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:99:02", "50% promo", -5, nil); err != nil {
		t.Fatal(err)
	}

	orderNo = "ORD-SMOKE-1"
	for i, o := range []*models.Order{
		{OrderNo: orderNo, Mac: "AA:BB:CC:00:99:01", Plan: "month", Days: 30,
			AmountCents: 100, Status: models.OrderPending, PaymentMethod: "wechat", UserID: &userID},
		{OrderNo: "ORD-SMOKE-2", Mac: "AA:BB:CC:00:99:02", Plan: "month", Days: 30,
			AmountCents: 100, Status: models.OrderPending, PaymentMethod: "alipay"},
	} {
		if err := app.DB.CreateOrder(ctx, o); err != nil {
			t.Fatalf("order %d: %v", i, err)
		}
	}
	if _, _, err := app.DB.MarkOrderPaid(ctx, "ORD-SMOKE-2", "TRADE-1"); err != nil {
		t.Fatal(err)
	}

	if _, err := app.DB.CreateVoucher(ctx, "SMOKEAAA2345", 30, "smoke", "smoke-batch", nil); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().AddDate(0, 0, -1)
	if _, err := app.DB.CreateVoucher(ctx, "SMOKEBBB2345", 30, "", "smoke-batch", &past); err != nil {
		t.Fatal(err)
	}

	if _, err := app.DB.CreateTrustedDevice(ctx, userID, "trust-token-1", "smoke browser", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.CreateSession(ctx, "user-sess-1", "user", u.Phone, &userID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.UpsertSighting(ctx, "AA:BB:CC:00:99:03", "10.0.0.3", "smoke-host"); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.LogSMS(ctx, "smoke", u.Phone, "验证码 123456", true, ""); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.LogSMS(ctx, "smoke", u.Phone, "fail", false, "timeout"); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.LogWebhookDelivery(ctx, "pay", "AA:BB:CC:00:99:01", 1, 200, true, 12, ""); err != nil {
		t.Fatal(err)
	}
	app.DB.Audit(ctx, "admin", "grant", "AA:BB:CC:00:99:01", "days=30 ip=10.0.0.9")
	app.DB.Audit(ctx, "user:"+u.Phone, "login", "", "ip=10.0.0.9")
	app.DB.Audit(ctx, "webhook:wechat", "pay", "AA:BB:CC:00:99:02", "order=ORD-SMOKE-2 amount=100")
	return userID, orderNo
}

// Every HTML page in the app must render 200 with seeded rows in every
// table — and must never contain "<no value>" (the missing-map-key
// footprint) anywhere in the body.
func TestAllPagesRenderWithSeededData(t *testing.T) {
	app := setupTestApp(t)
	userID, orderNo := seedEverything(t, app)
	h := app.Routes()
	adminJar := loginAdmin(t, h)

	adminPages := []string{
		"/admin/dashboard",
		"/admin/macs",
		"/admin/macs?q=smoke&status=active",
		"/admin/macs/detail?mac=AA:BB:CC:00:99:01",
		"/admin/macs/schedule?mac=AA:BB:CC:00:99:01",
		"/admin/devices",
		"/admin/orders",
		"/admin/orders?status=paid",
		"/admin/orders/detail?order_no=" + orderNo,
		"/admin/orders/detail?order_no=ORD-SMOKE-2",
		fmt.Sprintf("/admin/users/detail?id=%d", userID),
		"/admin/users",
		"/admin/audit",
		"/admin/audit?actor=admin",
		"/admin/sessions",
		"/admin/health",
		"/admin/maintenance",
		"/admin/webhook-log",
		"/admin/sms-log",
		"/admin/api-tokens",
		"/admin/ssid-cards",
		"/admin/vouchers",
		"/admin/vouchers?batch=smoke-batch",
		"/admin/vouchers/print?batch=smoke-batch",
		"/admin/plans",
		"/admin/2fa",
	}
	for _, page := range adminPages {
		res, body := do(t, h, "GET", page, nil, adminJar)
		if res.StatusCode != 200 {
			t.Errorf("%s status = %d, want 200 (template error?)", page, res.StatusCode)
			continue
		}
		if strings.Contains(body, "<no value>") {
			t.Errorf("%s renders '<no value>'", page)
		}
	}

	// User-facing pages with a real logged-in session.
	userJar := map[string]string{userCookieName: "user-sess-1"}
	res, _ := do(t, h, "GET", "/user/me", nil, userJar)
	for k, v := range cookieJar(res) {
		userJar[k] = v
	}
	// /user/forgot-password is excluded: without an SMS provider (the test
	// app has none) it correctly 303s back to login instead of rendering.
	userPages := []string{
		"/user/me",
		"/user/2fa",
		"/user/login",
		"/user/register",
		"/redeem",
		"/portal",
	}
	for _, page := range userPages {
		res, body := do(t, h, "GET", page, nil, userJar)
		if res.StatusCode != 200 {
			t.Errorf("%s status = %d, want 200", page, res.StatusCode)
			continue
		}
		if strings.Contains(body, "<no value>") {
			t.Errorf("%s renders '<no value>'", page)
		}
	}
}
