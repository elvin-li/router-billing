package db

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"router-billing/internal/models"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	d, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestUpsertMACWithUserID(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	uid, err := d.CreateUser(ctx, "13800138000", "hash")
	if err != nil {
		t.Fatal(err)
	}
	uidPtr := uid.ID

	m, err := d.UpsertMAC(ctx, "AA:BB:CC:DD:EE:FF", "phone", 30, &uidPtr)
	if err != nil {
		t.Fatal(err)
	}
	if m.UserID == nil || *m.UserID != uid.ID {
		t.Errorf("UserID not set on insert")
	}
	if got := time.Until(m.ExpiresAt); got < 29*24*time.Hour || got > 31*24*time.Hour {
		t.Errorf("expiry off: %s", got)
	}

	// Extend without specifying UserID — owner should stay.
	m, err = d.UpsertMAC(ctx, "AA:BB:CC:DD:EE:FF", "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.UserID == nil || *m.UserID != uid.ID {
		t.Errorf("UserID dropped on extend")
	}
	if got := time.Until(m.ExpiresAt); got < 39*24*time.Hour {
		t.Errorf("expected ~40 days, got %s", got)
	}
}

func TestRedeemVoucherFlow(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if _, err := d.CreateVoucher(ctx, "TESTCODE1234", 30, "test", "batch1", nil); err != nil {
		t.Fatal(err)
	}

	v, err := d.RedeemVoucher(ctx, "TESTCODE1234", "AA:BB:CC:DD:EE:FF", nil)
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if v.RedeemedAt == nil {
		t.Error("RedeemedAt should be set")
	}

	// Second redemption must fail with ErrVoucherUsed.
	_, err = d.RedeemVoucher(ctx, "TESTCODE1234", "AA:BB:CC:DD:EE:FF", nil)
	if !errors.Is(err, ErrVoucherUsed) {
		t.Errorf("expected ErrVoucherUsed, got %v", err)
	}

	// Non-existent code.
	_, err = d.RedeemVoucher(ctx, "NOTACODE0000", "AA:BB:CC:DD:EE:FF", nil)
	if !errors.Is(err, ErrVoucherNotFound) {
		t.Errorf("expected ErrVoucherNotFound, got %v", err)
	}
}

func TestRedeemVoucherExpired(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	past := time.Now().Add(-1 * time.Hour)
	if _, err := d.CreateVoucher(ctx, "EXPIREDCODE1", 30, "t", "b", &past); err != nil {
		t.Fatal(err)
	}
	_, err := d.RedeemVoucher(ctx, "EXPIREDCODE1", "AA:BB:CC:DD:EE:FF", nil)
	if !errors.Is(err, ErrVoucherExpired) {
		t.Errorf("expected ErrVoucherExpired, got %v", err)
	}
}

func TestRedeemVoucherRevoked(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if _, err := d.CreateVoucher(ctx, "REVOKEDCODE1", 30, "t", "b", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeVoucher(ctx, "REVOKEDCODE1"); err != nil {
		t.Fatal(err)
	}
	_, err := d.RedeemVoucher(ctx, "REVOKEDCODE1", "AA:BB:CC:DD:EE:FF", nil)
	if !errors.Is(err, ErrVoucherRevoked) {
		t.Errorf("expected ErrVoucherRevoked, got %v", err)
	}
}

func TestReplaceMACTransferOwnership(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	u, _ := d.CreateUser(ctx, "13900139000", "hash")
	oldMac := "11:22:33:44:55:66"
	newMac := "AA:BB:CC:DD:EE:FF"

	if _, err := d.UpsertMAC(ctx, oldMac, "old-phone", 365, &u.ID); err != nil {
		t.Fatal(err)
	}

	got, err := d.ReplaceMAC(ctx, u.ID, oldMac, newMac, "new-phone")
	if err != nil {
		t.Fatal(err)
	}
	if got.Mac != newMac || got.Label != "new-phone" {
		t.Errorf("replace gave %+v", got)
	}
	if m, _ := d.GetMAC(ctx, oldMac); m != nil {
		t.Errorf("old MAC still present: %+v", m)
	}
	if m, _ := d.GetMAC(ctx, newMac); m == nil {
		t.Errorf("new MAC missing")
	}
}

func TestPlansOverlay(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	// Empty initially.
	plans, _ := d.ListPlans(ctx)
	if len(plans) != 0 {
		t.Errorf("expected 0 plans, got %d", len(plans))
	}

	// Upsert one
	p := models.Plan{Key: "vip", Label: "VIP", Days: 30, PriceCents: 5000, Enabled: true}
	if err := d.UpsertPlan(ctx, p); err != nil {
		t.Fatal(err)
	}
	plans, _ = d.ListPlans(ctx)
	if len(plans) != 1 || plans[0].Key != "vip" {
		t.Errorf("got %+v", plans)
	}

	// Update same key
	p.PriceCents = 6000
	if err := d.UpsertPlan(ctx, p); err != nil {
		t.Fatal(err)
	}
	plans, _ = d.ListPlans(ctx)
	if plans[0].PriceCents != 6000 {
		t.Errorf("update did not stick; got %d", plans[0].PriceCents)
	}

	// Delete
	if err := d.DeletePlan(ctx, "vip"); err != nil {
		t.Fatal(err)
	}
	plans, _ = d.ListPlans(ctx)
	if len(plans) != 0 {
		t.Errorf("expected 0 after delete, got %d", len(plans))
	}
}

func TestStatsSnapshotIdempotent(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if err := d.SnapshotToday(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.SnapshotToday(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ := d.ListStatsDaily(ctx, 30)
	if len(rows) != 1 {
		t.Errorf("expected 1 row (same day upsert), got %d", len(rows))
	}
}
