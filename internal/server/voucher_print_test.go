package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The print page must skip expired vouchers (redeem rejects them, so a
// printed card would be dead on arrival) and must query-escape codes in
// the QR path (imported codes are only length-checked, so '&' etc. would
// split the query string).

func TestAdminVouchersPrintSkipsExpired(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-24 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	if _, err := app.DB.CreateVoucher(ctx, "PRINTDEAD001", 30, "", "print-batch", &past); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.CreateVoucher(ctx, "PRINTLIVE001", 30, "", "print-batch", &future); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/vouchers/print?batch=print-batch", nil, jar)
	if strings.Contains(body, "PRINTDEAD001") {
		t.Error("expired voucher should not be printed")
	}
	if !strings.Contains(body, "PRINTLIVE001") {
		t.Error("unexpired voucher should be printed")
	}
}
