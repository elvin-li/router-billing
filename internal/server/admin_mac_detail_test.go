package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAdminMACDetailRendersFullProfile(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800230001", "h")
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:0A:01", "support-phone", 30, &u.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('MAC-D-ORD-1', 'AA:BB:CC:00:0A:01', 'month', 30, 500, 'paid', 'wechat', ?, ?, ?)`,
		u.ID, now, now)
	app.DB.Audit(ctx, "admin", "grant", "AA:BB:CC:00:0A:01", "days=30 via=ui")

	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/macs/detail?mac=AA:BB:CC:00:0A:01", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	for _, want := range []string{
		"AA:BB:CC:00:0A:01",
		"support-phone",  // label
		"MAC-D-ORD-1",    // order link
		"13800230001",    // owner phone
		"grant",          // audit action
		"days=30 via=ui", // audit detail
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q; body=%s", want, truncate(body, 1200))
		}
	}
}

func TestAdminMACDetailNormalizesInput(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:0A:02", "phone", 30, nil)

	h := app.Routes()
	jar := loginAdmin(t, h)

	// Lower-case dashed input should normalize and find the same MAC.
	res, body := do(t, h, "GET", "/admin/macs/detail?mac=aa-bb-cc-00-0a-02", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "AA:BB:CC:00:0A:02") {
		t.Error("page should render the canonical MAC")
	}
}

func TestAdminMACDetailMissingMACRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, _ := do(t, h, "GET", "/admin/macs/detail?mac=AA:BB:CC:DD:EE:00", nil, jar)
	if res.StatusCode != 303 {
		t.Errorf("missing MAC should 303; got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "err=not_found") {
		t.Errorf("redirect should signal not_found; got %s", res.Header.Get("Location"))
	}
}

func TestAdminMACDetailBadMACRedirects(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/macs/detail?mac=NOT-A-MAC-AT-ALL", nil, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=bad_mac") {
		t.Errorf("bad mac should give err=bad_mac; got %s", res.Header.Get("Location"))
	}
}

func TestAdminMACSListLinksToDetail(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:0A:05", "linked", 30, nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs", nil, jar)
	// First sanity: the MAC itself should at least render in the page.
	if !strings.Contains(body, "AA:BB:CC:00:0A:05") {
		t.Fatalf("MAC not rendered at all; body excerpt around 0A:05 area = %q",
			truncate(body, 500))
	}
	// html/template's URL-context escape encodes `:` as `%3a` (lower-case
	// per RFC 3986 §6.2.2.1 normalization) — accept either form.
	if !strings.Contains(body, "/admin/macs/detail?mac=AA:BB:CC:00:0A:05") &&
		!strings.Contains(body, "/admin/macs/detail?mac=AA%3aBB%3aCC%3a00%3a0A%3a05") &&
		!strings.Contains(body, "/admin/macs/detail?mac=AA%3ABB%3ACC%3A00%3A0A%3A05") {
		// Print substring around the MAC to see what's actually rendered.
		idx := strings.Index(body, "0A:05")
		start := idx - 200
		if start < 0 {
			start = 0
		}
		end := idx + 200
		if end > len(body) {
			end = len(body)
		}
		t.Errorf("macs list should link to detail page; nearby body=%q", body[start:end])
	}
}
