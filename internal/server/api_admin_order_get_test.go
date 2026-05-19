package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPIOrderGetHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800220001", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:09:01", "phone", 30, &u.ID)
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('API-GET-1', 'AA:BB:CC:00:09:01', 'month', 30, 500, 'paid', 'wechat', ?, ?, ?)`,
		u.ID, now, now)
	app.DB.Audit(ctx, "wechat-notify", "order_paid", "API-GET-1", "trade=W123")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/orders/get?order_no=API-GET-1", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Order struct {
			OrderNo string `json:"order_no"`
		} `json:"order"`
		MAC struct {
			Mac string `json:"mac"`
		} `json:"mac"`
		Audit []struct {
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"audit"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Order.OrderNo != "API-GET-1" {
		t.Errorf("order_no not echoed: %q", resp.Order.OrderNo)
	}
	if resp.MAC.Mac != "AA:BB:CC:00:09:01" {
		t.Errorf("mac not included: %q", resp.MAC.Mac)
	}
	auditFound := false
	for _, a := range resp.Audit {
		if a.Action == "order_paid" && a.Target == "API-GET-1" {
			auditFound = true
		}
	}
	if !auditFound {
		t.Error("audit timeline missing the seeded row")
	}
}

func TestAPIOrderGetNotFound(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/orders/get?order_no=NOPE", "rb_w", "")
	if rr.Code != 404 {
		t.Errorf("missing order should 404; got %d", rr.Code)
	}
}

func TestAPIOrderGetMissingParam(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/orders/get", "rb_w", "")
	if rr.Code != 400 {
		t.Errorf("missing order_no should 400; got %d", rr.Code)
	}
}

func TestAPIOrderGetReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('RO-1', 'AA:BB:CC:00:09:02', 'month', 30, 100, 'paid', 'wechat', ?, ?)`, now, now)
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/orders/get?order_no=RO-1", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly should be 200; got %d", rr.Code)
	}
}

// MAC was deleted post-order — payload should still include the order
// and audit timeline, with mac=null.
func TestAPIOrderGetWithDeletedMAC(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `
		INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, paid_at, created_at)
		VALUES ('NOMAC-API', 'AA:BB:CC:DD:DE:AE', 'month', 30, 500, 'paid', 'wechat', ?, ?)`,
		now, now)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/orders/get?order_no=NOMAC-API", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"order_no":"NOMAC-API"`) {
		t.Error("order should still appear")
	}
	if !strings.Contains(body, `"mac":null`) {
		t.Errorf("expected mac:null when MAC missing; got %s", body)
	}
}

// Anti-leak: response must never include password_hash, totp_secret, etc.
func TestAPIOrderGetNoSensitiveFields(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800220009", "super-secret-hash")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:09:09", "phone", 30, &u.ID)
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('LEAK-CHECK', 'AA:BB:CC:00:09:09', 'month', 30, 100, 'paid', 'wechat', ?, ?, ?)`, u.ID, now, now)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/orders/get?order_no=LEAK-CHECK", "rb_w", "")
	body := rr.Body.String()
	for _, banned := range []string{"password_hash", "super-secret-hash", "totp_secret", "session_token"} {
		if strings.Contains(body, banned) {
			t.Errorf("response leaks %q: %s", banned, body)
		}
	}
}
