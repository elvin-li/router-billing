package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRedeemVoucherGrantHappyPath — one call consumes the voucher AND
// grants its days to the MAC, with the same "voucher:<batch>" label the
// old two-step flow wrote.
func TestRedeemVoucherGrantHappyPath(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if _, err := d.CreateVoucher(ctx, "GRANTOK00001", 30, "promo", "B1", nil); err != nil {
		t.Fatal(err)
	}
	u, err := d.CreateUser(ctx, "13800138000", "hash")
	if err != nil {
		t.Fatal(err)
	}

	v, m, err := d.RedeemVoucherGrant(ctx, "GRANTOK00001", "AA:BB:CC:DD:EE:01", &u.ID)
	if err != nil {
		t.Fatalf("RedeemVoucherGrant: %v", err)
	}
	if v.RedeemedAt == nil || v.RedeemedByMac != "AA:BB:CC:DD:EE:01" {
		t.Errorf("voucher not marked redeemed: %+v", v)
	}
	if m == nil {
		t.Fatal("expected MAC row back")
	}
	if m.Label != "voucher:B1" {
		t.Errorf("label = %q, want voucher:B1", m.Label)
	}
	if m.UserID == nil || *m.UserID != u.ID {
		t.Errorf("MAC owner = %v, want %d", m.UserID, u.ID)
	}
	want := time.Now().UTC().AddDate(0, 0, 30)
	if m.ExpiresAt.Before(want.Add(-time.Minute)) || m.ExpiresAt.After(want.Add(time.Minute)) {
		t.Errorf("expires_at = %s, want ~%s", m.ExpiresAt, want)
	}

	// Both writes are visible outside the tx.
	v2, _ := d.GetVoucher(ctx, "GRANTOK00001")
	if v2 == nil || v2.RedeemedAt == nil {
		t.Error("voucher row not persisted as redeemed")
	}
	m2, _ := d.GetMAC(ctx, "AA:BB:CC:DD:EE:01")
	if m2 == nil {
		t.Error("MAC row not persisted")
	}
}

// TestRedeemVoucherGrantExtendsExistingActive — redeeming onto an already-
// active MAC stacks the days on top of the current expiry (same semantics
// as UpsertMAC).
func TestRedeemVoucherGrantExtendsExistingActive(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:DD:EE:02", "existing", 10, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := d.GetMAC(ctx, "AA:BB:CC:DD:EE:02")

	if _, err := d.CreateVoucher(ctx, "GRANTSTACK01", 5, "", "B2", nil); err != nil {
		t.Fatal(err)
	}
	_, m, err := d.RedeemVoucherGrant(ctx, "GRANTSTACK01", "AA:BB:CC:DD:EE:02", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := before.ExpiresAt.AddDate(0, 0, 5)
	if !m.ExpiresAt.Equal(want) {
		t.Errorf("expires_at = %s, want stacked %s", m.ExpiresAt, want)
	}
}

// TestRedeemVoucherGrantValidationErrors — used/revoked/expired/missing
// vouchers return the typed errors AND leave the MAC completely untouched
// (the grant must never land when the redeem is rejected).
func TestRedeemVoucherGrantValidationErrors(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	// used
	if _, err := d.CreateVoucher(ctx, "GRANTUSED001", 30, "", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RedeemVoucher(ctx, "GRANTUSED001", "11:11:11:11:11:11", nil); err != nil {
		t.Fatal(err)
	}
	// revoked
	if _, err := d.CreateVoucher(ctx, "GRANTREVK001", 30, "", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeVoucher(ctx, "GRANTREVK001"); err != nil {
		t.Fatal(err)
	}
	// expired
	past := time.Now().UTC().Add(-time.Hour)
	if _, err := d.CreateVoucher(ctx, "GRANTEXPD001", 30, "", "", &past); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		code string
		want error
	}{
		{"GRANTUSED001", ErrVoucherUsed},
		{"GRANTREVK001", ErrVoucherRevoked},
		{"GRANTEXPD001", ErrVoucherExpired},
		{"NOSUCHCODE01", ErrVoucherNotFound},
	}
	for _, tc := range cases {
		_, _, err := d.RedeemVoucherGrant(ctx, tc.code, "AA:BB:CC:DD:EE:03", nil)
		if !errors.Is(err, tc.want) {
			t.Errorf("code %s: err = %v, want %v", tc.code, err, tc.want)
		}
	}
	// The target MAC must not exist — no grant may have leaked through.
	if m, _ := d.GetMAC(ctx, "AA:BB:CC:DD:EE:03"); m != nil {
		t.Errorf("rejected redeems must not create the MAC; got %+v", m)
	}
}
