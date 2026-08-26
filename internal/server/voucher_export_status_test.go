package server

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Voucher CSV export ?status= filter pins each rendered status against
// its DB state so the derived-status mapping doesn't drift.
func TestVoucherExportFilterByStatus(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// 4 vouchers covering each status:
	_, _ = app.DB.CreateVoucher(ctx, "EXPORT111UNUS", 30, "", "exp-test", nil)
	_, _ = app.DB.CreateVoucher(ctx, "EXPORT222REDM", 30, "", "exp-test", nil)
	_, _ = app.DB.CreateVoucher(ctx, "EXPORT333REVO", 30, "", "exp-test", nil)
	past := time.Now().UTC().Add(-time.Hour)
	_, _ = app.DB.CreateVoucher(ctx, "EXPORT444EXPI", 30, "", "exp-test", &past)
	_, _ = app.DB.RedeemVoucher(ctx, "EXPORT222REDM", "AA:BB:CC:DD:EE:F2", nil)
	_ = app.DB.RevokeVoucher(ctx, "EXPORT333REVO")

	h := app.Routes()
	jar := loginAdmin(t, h)

	for _, c := range []struct {
		status      string
		wantCode    string
		wantNotCode []string
	}{
		{"unused", "EXPORT111UNUS", []string{"EXPORT222REDM", "EXPORT333REVO", "EXPORT444EXPI"}},
		{"redeemed", "EXPORT222REDM", []string{"EXPORT111UNUS", "EXPORT333REVO", "EXPORT444EXPI"}},
		{"revoked", "EXPORT333REVO", []string{"EXPORT111UNUS", "EXPORT222REDM", "EXPORT444EXPI"}},
		{"expired", "EXPORT444EXPI", []string{"EXPORT111UNUS", "EXPORT222REDM", "EXPORT333REVO"}},
	} {
		t.Run(c.status, func(t *testing.T) {
			_, body := do(t, h, "GET",
				"/admin/vouchers/export.csv?batch=exp-test&status="+c.status,
				nil, jar)
			if !strings.Contains(body, c.wantCode) {
				t.Errorf("status=%s should include %s; body=%s", c.status, c.wantCode, body)
			}
			for _, banned := range c.wantNotCode {
				if strings.Contains(body, banned) {
					t.Errorf("status=%s should NOT include %s; body=%s", c.status, banned, body)
				}
			}
		})
	}
}

// No status param → all 4 rows present (preserves the legacy semantics).
func TestVoucherExportNoStatusFilterReturnsAll(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	for _, c := range []string{"ALL11111ALLR", "ALL22222ALLR"} {
		_, _ = app.DB.CreateVoucher(ctx, c, 30, "", "all-test", nil)
	}
	_, _ = app.DB.RedeemVoucher(ctx, "ALL11111ALLR", "AA:BB:CC:DD:EE:F3", nil)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/vouchers/export.csv?batch=all-test", nil, jar)
	if !strings.Contains(body, "ALL11111ALLR") || !strings.Contains(body, "ALL22222ALLR") {
		t.Error("no-filter export should include all rows in the batch")
	}
}

// The Content-Disposition filename should embed the status when filtered
// so a downloaded export is self-describing.
func TestVoucherExportFilenameEncodesStatus(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.CreateVoucher(ctx, "FNAME1111FNAM", 30, "", "fname", nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, _ := do(t, h, "GET", "/admin/vouchers/export.csv?batch=fname&status=unused", nil, jar)
	cd := res.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "fname-unused") {
		t.Errorf("filename should embed status; got %q", cd)
	}
}

// Free-text batch names must not break out of the Content-Disposition
// quoted-string. net/http neutralizes CR/LF in header values, but a `"`
// passed through verbatim and let a batch named `x";evil=` smuggle extra
// header parameters (and produced RFC 6266 parse ambiguity across
// browsers). Every other export uses constant filenames; the voucher
// export keeps the batch for self-description, sanitized.
func TestVoucherExportFilenameSanitizesBatch(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	evil := `x";evil="1`
	_, _ = app.DB.CreateVoucher(ctx, "SANIT1111SANI", 30, "", evil, nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	res, body := do(t, h, "GET", "/admin/vouchers/export.csv?batch="+
		"x%22%3Bevil%3D%221", nil, jar)
	cd := res.Header.Get("Content-Disposition")
	if strings.Count(cd, `"`) != 2 {
		t.Errorf("filename quoting broken: %q", cd)
	}
	if strings.Contains(cd, ";evil=") {
		t.Errorf("batch text leaked into header params: %q", cd)
	}
	// The row itself still exports (filter matches the raw batch value).
	if !strings.Contains(body, "SANIT1111SANI") {
		t.Errorf("export body should still contain the batch's voucher")
	}
}

func TestFilenameSafe(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"batch-01", "batch-01"},
		{`x";evil="1`, "xevil1"},
		{"团购批次", ""},
		{"a b\tc", "abc"},
		{strings.Repeat("A", 100), strings.Repeat("A", 60)},
	} {
		if got := filenameSafe(c.in); got != c.want {
			t.Errorf("filenameSafe(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
