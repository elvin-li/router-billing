package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"router-billing/internal/db"
)

// SearchOrdersFiltered with UserID set must return only orders linked to
// that user — and orders with NULL user_id must NOT match. We seed three
// orders across two users so a wrong query couldn't accidentally pass.
func TestSearchOrdersFilteredByUserID(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	u1, _ := app.DB.CreateUser(ctx, "13800130001", "h")
	u2, _ := app.DB.CreateUser(ctx, "13800130002", "h")

	// 2 orders for u1, 1 for u2, 1 with no user_id.
	now := time.Now().UTC()
	for i, row := range []struct {
		orderNo string
		mac     string
		uid     *int64
	}{
		{"USR-1-A", "AA:BB:CC:DD:EE:01", &u1.ID},
		{"USR-1-B", "AA:BB:CC:DD:EE:02", &u1.ID},
		{"USR-2-A", "AA:BB:CC:DD:EE:03", &u2.ID},
		{"NOUSER", "AA:BB:CC:DD:EE:04", nil},
	} {
		_, _ = app.DB.Exec(ctx, `
			INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
			VALUES (?, ?, 'month', 30, 100, 'paid', 'wechat', ?, ?, ?)`,
			row.orderNo, row.mac, row.uid, now, now.Add(time.Duration(-i)*time.Second))
	}

	orders, err := app.DB.SearchOrdersFiltered(ctx, db.OrderFilter{UserID: u1.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 2 {
		t.Errorf("expected 2 orders for user %d; got %d", u1.ID, len(orders))
	}
	for _, o := range orders {
		if !strings.HasPrefix(o.OrderNo, "USR-1-") {
			t.Errorf("filter leaked order %s (user_id mismatch)", o.OrderNo)
		}
	}

	// u2 → exactly 1 order.
	orders, _ = app.DB.SearchOrdersFiltered(ctx, db.OrderFilter{UserID: u2.ID})
	if len(orders) != 1 || orders[0].OrderNo != "USR-2-A" {
		t.Errorf("expected only USR-2-A; got %+v", orders)
	}

	// UserID=0 means "no filter" — all 4 should come back (subject to limit).
	orders, _ = app.DB.SearchOrdersFiltered(ctx, db.OrderFilter{})
	if len(orders) < 4 {
		t.Errorf("UserID=0 should not filter; got %d (expected >= 4)", len(orders))
	}
}

// /admin/orders?user_id=N must accept the param and pass it to the filter.
// The orders without a user_id field must NOT appear in the rendered list.
func TestAdminOrdersPageUserIDFilter(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800130003", "h")
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('UI-USR-1', 'AA:BB:CC:DD:EE:05', 'month', 30, 100, 'paid', 'wechat', ?, ?, ?)`,
		u.ID, now, now)
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('OTHER-USER', 'AA:BB:CC:DD:EE:06', 'month', 30, 100, 'paid', 'wechat', NULL, ?, ?)`,
		now, now)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/orders?user_id=999999", nil, jar)
	if strings.Contains(body, "UI-USR-1") || strings.Contains(body, "OTHER-USER") {
		t.Error("user_id=999999 should match nothing")
	}

	// With the real user_id the orders should appear, but the unowned one
	// must not.
	uidPath := "/admin/orders?user_id=" + intToStr(u.ID)
	_, body = do(t, h, "GET", uidPath, nil, jar)
	if !strings.Contains(body, "UI-USR-1") {
		t.Error("user's order missing from filtered list")
	}
	if strings.Contains(body, "OTHER-USER") {
		t.Error("orphan order leaked into user_id-filtered list")
	}
	// The export link should carry the user_id through.
	if !strings.Contains(body, "user_id=") {
		t.Error("export link should include user_id param")
	}
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
