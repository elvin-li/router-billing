package server

import (
	"context"
	"strings"
	"testing"
)

// v0.126: the batch-revoke flash rendered ?batch= verbatim — free text in
// the trusted green banner. Only names of batches that actually exist may
// echo.
func TestVoucherBatchRevokeFlashOnlyEchoesKnownBatch(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	ctx := context.Background()

	if _, err := app.DB.CreateVoucher(ctx, "AAAABBBBCCCC", 30, "", "REAL-BATCH", nil); err != nil {
		t.Fatal(err)
	}

	const evil = "URGENT-wire-money-to-13800000000"
	res, body := do(t, h, "GET", "/admin/vouchers?ok=batch_revoke&revoked=3&batch="+evil, nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if strings.Contains(body, evil) {
		t.Error("attacker-controlled ?batch= text reflected into the trusted flash")
	}

	res, body = do(t, h, "GET", "/admin/vouchers?ok=batch_revoke&revoked=1&batch=REAL-BATCH", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "REAL-BATCH") {
		t.Error("legitimate batch name should still render in the flash")
	}
}

// Same reflected-text vector on the print page's title/header.
func TestVoucherPrintPageOnlyEchoesRealBatch(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	ctx := context.Background()

	if _, err := app.DB.CreateVoucher(ctx, "DDDDEEEEFFFF", 30, "", "PRINT-BATCH", nil); err != nil {
		t.Fatal(err)
	}

	const evil = "URGENT-wire-money-now"
	res, body := do(t, h, "GET", "/admin/vouchers/print?batch="+evil, nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if strings.Contains(body, evil) {
		t.Error("attacker-controlled ?batch= text reflected on the print page")
	}

	res, body = do(t, h, "GET", "/admin/vouchers/print?batch=PRINT-BATCH", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(body, "PRINT-BATCH") {
		t.Error("legitimate batch name should still render on the print page")
	}
}
