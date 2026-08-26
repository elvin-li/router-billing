package server

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"router-billing/internal/firewall"
)

// failingFW wraps the dry-run firewall but fails every Add/Sync — simulates
// nft being wedged (kernel module unloaded, table deleted by an fw3 reload…).
type failingFW struct {
	firewall.API
}

func (f *failingFW) Add(ctx context.Context, mac string) error {
	return errors.New("nft: broken pipe")
}
func (f *failingFW) Sync(ctx context.Context, macs []string) error {
	return errors.New("nft: broken pipe")
}

// Regression (v0.109): a firewall-only failure during redeem used to bubble
// up through MACSvc.Extend, so the handler reported "授权失败" and the voucher
// stayed consumed — even though the DB grant HAD landed. The DB is the source
// of truth (same reasoning as GrantFromOrder since v0.106): the redeem must
// succeed, days must be granted, and the voucher stays redeemed.
func TestRedeemSucceedsWhenFirewallAddFails(t *testing.T) {
	ctx := context.Background()
	app := setupTestApp(t)
	app.MACSvc.FW = &failingFW{API: app.MACSvc.FW}
	h := app.Routes()

	if _, err := app.DB.CreateVoucher(ctx, "FWFA23CDEE99", 7, "", "b1", nil); err != nil {
		t.Fatal(err)
	}
	res, _ := do(t, h, "POST", "/redeem",
		url.Values{"code": {"FWFA23CDEE99"}, "mac": {"aa:bb:cc:dd:ee:31"}}, nil)
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=1") {
		t.Fatalf("redeem with failing firewall should still succeed (DB is source of truth); loc=%s", loc)
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:31")
	if m == nil {
		t.Fatal("MAC not granted")
	}
	v, _ := app.DB.GetVoucher(ctx, "FWFA23CDEE99")
	if v.RedeemedAt == nil {
		t.Error("voucher should stay redeemed — the grant is durable")
	}
}

// Regression (v0.109, HIGH): when the DB grant itself failed after
// RedeemVoucher had already consumed the code, the voucher was burned with
// nothing granted and no compensation — the pay path got RevertOrderToPending
// for the identical hole, redeem didn't. A SQLite trigger on the macs table
// simulates the grant failing at the DB layer; the handler must un-redeem
// the voucher so the customer can retry, and the retry must work.
func TestRedeemUnredeemsVoucherWhenGrantFails(t *testing.T) {
	ctx := context.Background()
	app := setupTestApp(t)
	h := app.Routes()

	if _, err := app.DB.CreateVoucher(ctx, "BURNPR22F333", 7, "", "b2", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(ctx, `
		CREATE TRIGGER test_block_grant BEFORE INSERT ON macs
		BEGIN SELECT RAISE(ABORT, 'grant blocked by test'); END`); err != nil {
		t.Fatal(err)
	}

	res, _ := do(t, h, "POST", "/redeem",
		url.Values{"code": {"BURNPR22F333"}, "mac": {"aa:bb:cc:dd:ee:32"}}, nil)
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Fatalf("redeem should report failure while grant is blocked; loc=%s", loc)
	}
	v, _ := app.DB.GetVoucher(ctx, "BURNPR22F333")
	if v.RedeemedAt != nil {
		t.Fatal("voucher burned: grant failed but the code stayed consumed")
	}

	// Grant works again → the SAME code must now redeem successfully.
	if _, err := app.DB.Exec(ctx, `DROP TRIGGER test_block_grant`); err != nil {
		t.Fatal(err)
	}
	res, _ = do(t, h, "POST", "/redeem",
		url.Values{"code": {"BURNPR22F333"}, "mac": {"aa:bb:cc:dd:ee:32"}}, nil)
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "ok=1") {
		t.Fatalf("retry after transient grant failure should succeed; loc=%s", loc)
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:EE:32")
	if m == nil {
		t.Fatal("MAC not granted on retry")
	}
	v, _ = app.DB.GetVoucher(ctx, "BURNPR22F333")
	if v.RedeemedAt == nil {
		t.Error("voucher should be redeemed after the successful retry")
	}
}

// UnredeemVoucher may only undo the specific redemption the caller made:
// wrong-MAC or never-redeemed calls must error and leave the row alone.
func TestUnredeemVoucherGuards(t *testing.T) {
	ctx := context.Background()
	app := setupTestApp(t)

	if _, err := app.DB.CreateVoucher(ctx, "GUARDC23E456", 7, "", "b3", nil); err != nil {
		t.Fatal(err)
	}
	// Not redeemed yet → nothing to undo.
	if err := app.DB.UnredeemVoucher(ctx, "GUARDC23E456", "AA:BB:CC:DD:EE:33"); err == nil {
		t.Error("unredeem of an unused voucher should error")
	}
	if _, err := app.DB.RedeemVoucher(ctx, "GUARDC23E456", "AA:BB:CC:DD:EE:33", nil); err != nil {
		t.Fatal(err)
	}
	// Wrong MAC → must not clear someone else's redemption.
	if err := app.DB.UnredeemVoucher(ctx, "GUARDC23E456", "AA:BB:CC:DD:EE:99"); err == nil {
		t.Error("unredeem with mismatched MAC should error")
	}
	if v, _ := app.DB.GetVoucher(ctx, "GUARDC23E456"); v.RedeemedAt == nil {
		t.Fatal("mismatched unredeem cleared the redemption")
	}
	// Matching MAC → undo works, code is usable again.
	if err := app.DB.UnredeemVoucher(ctx, "GUARDC23E456", "AA:BB:CC:DD:EE:33"); err != nil {
		t.Fatal(err)
	}
	v, _ := app.DB.GetVoucher(ctx, "GUARDC23E456")
	if v.RedeemedAt != nil || v.RedeemedByMac != "" || v.RedeemedUserID != nil {
		t.Errorf("unredeem left residue: at=%v mac=%q uid=%v", v.RedeemedAt, v.RedeemedByMac, v.RedeemedUserID)
	}
	if _, err := app.DB.RedeemVoucher(ctx, "GUARDC23E456", "AA:BB:CC:DD:EE:34", nil); err != nil {
		t.Errorf("voucher should be redeemable again after unredeem: %v", err)
	}
}
