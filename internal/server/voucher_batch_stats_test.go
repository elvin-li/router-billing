package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"router-billing/internal/db"
)

func TestVoucherBatchStatsAggregates(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// batch-A: 3 vouchers — 1 unused, 1 redeemed, 1 revoked.
	_, _ = app.DB.CreateVoucher(ctx, "AAAA1111AAAA", 30, "", "batch-A", nil)
	_, _ = app.DB.CreateVoucher(ctx, "AAAA2222AAAA", 30, "", "batch-A", nil)
	_, _ = app.DB.CreateVoucher(ctx, "AAAA3333AAAA", 30, "", "batch-A", nil)
	if _, err := app.DB.RedeemVoucher(ctx, "AAAA2222AAAA", "AA:BB:CC:DD:EE:F0", nil); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.RevokeVoucher(ctx, "AAAA3333AAAA"); err != nil {
		t.Fatal(err)
	}

	// batch-B: 1 voucher, expired-via-expires_at.
	past := time.Now().UTC().Add(-time.Hour)
	if _, err := app.DB.CreateVoucher(ctx, "BBBB1111BBBB", 30, "", "batch-B", &past); err != nil {
		t.Fatal(err)
	}

	// no-batch voucher
	_, _ = app.DB.CreateVoucher(ctx, "NOBT1111NOBT", 30, "", "", nil)

	stats, err := app.DB.VoucherBatchStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]db.VoucherBatchStat{}
	for _, s := range stats {
		got[s.Batch] = s
	}
	if a := got["batch-A"]; a.Total != 3 || a.Unused != 1 || a.Redeemed != 1 || a.Revoked != 1 {
		t.Errorf("batch-A unexpected: %+v", a)
	}
	if b := got["batch-B"]; b.Total != 1 || b.Expired != 1 || b.Unused != 0 {
		t.Errorf("batch-B unexpected: %+v", b)
	}
	if n := got["(no batch)"]; n.Total != 1 {
		t.Errorf("(no batch) row missing or wrong: %+v", n)
	}
}

func TestAdminVouchersPageShowsBatchStatsSection(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.CreateVoucher(ctx, "AAAAXXXXAAAA", 30, "", "batch-render", nil)

	// Verify the DB query returns the seeded batch before rendering.
	stats, err := app.DB.VoucherBatchStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) == 0 {
		t.Fatal("VoucherBatchStats returned no rows; expected at least 1")
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/vouchers", nil, jar)
	if !strings.Contains(body, "按 batch 库存") {
		t.Errorf("page should show batch-stats section header; body=%s", truncate(body, 1500))
	}
	if !strings.Contains(body, "batch-render") {
		t.Error("page should list the batch by name")
	}
}

func TestAdminVouchersBatchStatsEmptyDB(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/vouchers", nil, jar)
	// Section should NOT appear when there are no batches (no vouchers at all).
	if strings.Contains(body, "按 batch 库存") {
		t.Error("batch-stats section should be hidden when DB is empty")
	}
}
