package db

import (
	"context"
	"testing"

	"router-billing/internal/models"
)

func TestEscapeLike(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"50%", `50\%`},
		{"a_b", `a\_b`},
		{`back\slash`, `back\\slash`},
		{`%_\`, `\%\_\\`},
	}
	for _, c := range cases {
		if got := escapeLike(c.in); got != c.want {
			t.Errorf("escapeLike(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Regression (v0.101): a search for a literal "%" or "_" used to act as a
// LIKE wildcard — "%" matched every row, "a_b" matched "axb" too.
func TestSearchMACsLiteralWildcards(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:01", "50% off promo", 30, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:02", "plain label", 30, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:03", "a_b", 30, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:04", "axb", 30, nil); err != nil {
		t.Fatal(err)
	}

	// Literal "%" matches only the label that contains one.
	got, err := d.SearchMACs(ctx, "50%", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Label != "50% off promo" {
		t.Errorf("q=50%% matched %d rows, want exactly the promo label", len(got))
	}

	// Bare "%" is a literal too — no label contains a lone stray "%"... but
	// "50% off promo" does contain the char, so exactly 1 row again.
	got, err = d.SearchMACs(ctx, "%", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("q=%% matched %d rows, want 1 (pre-v0.101 it matched all 4)", len(got))
	}

	// "_" is a literal single underscore, not any-char.
	got, err = d.SearchMACs(ctx, "a_b", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Label != "a_b" {
		t.Errorf("q=a_b matched %d rows, want only the literal a_b label", len(got))
	}
}

func TestSearchOrdersLiteralWildcards(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	for _, no := range []string{"ORD-AAA-1", "ORD-BBB-2"} {
		o := &models.Order{
			OrderNo:       no,
			Mac:           "AA:BB:CC:DD:EE:0" + no[len(no)-1:],
			Plan:          "month",
			Days:          30,
			AmountCents:   100,
			Status:        models.OrderPending,
			PaymentMethod: "wechat",
		}
		if err := d.CreateOrder(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	got, err := d.SearchOrders(ctx, "%", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("q=%% matched %d orders, want 0 (no order contains a literal %%)", len(got))
	}
}

func TestSearchUsersLiteralWildcards(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if _, err := d.CreateUser(ctx, "13800138001", "hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateUser(ctx, "13800138002", "hash"); err != nil {
		t.Fatal(err)
	}

	got, err := d.SearchUsers(ctx, "%", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("q=%% matched %d users, want 0 (pre-v0.101 it matched all)", len(got))
	}

	// Normal substring search still works.
	got, err = d.SearchUsers(ctx, "138001", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("substring search matched %d users, want 2", len(got))
	}
}

func TestSearchAuditLiteralWildcards(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	d.Audit(ctx, "admin", "grant", "AA:BB:CC:DD:EE:01", "detail one")
	d.Audit(ctx, "user:1", "redeem", "AA:BB:CC:DD:EE:02", "detail two")

	got, err := d.SearchAudit(ctx, AuditFilter{Actor: "%"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("actor=%% matched %d rows, want 0", len(got))
	}

	got, err = d.SearchAudit(ctx, AuditFilter{Q: "_"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("q=_ matched %d rows, want 0 (no detail contains a literal underscore)", len(got))
	}

	got, err = d.SearchAudit(ctx, AuditFilter{Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("actor=admin matched %d rows, want 1", len(got))
	}
}
