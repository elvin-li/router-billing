package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestAdminVoucherImportCSV(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	bulk := strings.Join([]string{
		"# comment row, skipped",
		"",
		"ABCD1111ABCD,30,promo,batch-A",
		"EFGH2222EFGH,365",
		"IJKL3333IJKL,90,monthly,batch-B,2026-12-31T23:59:59Z",
	}, "\n")
	res, _ := do(t, h, "POST", "/admin/vouchers/import",
		url.Values{"_csrf": {csrf}, "bulk": {bulk}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "added=3") {
		t.Errorf("expected added=3; got %s", loc)
	}
	if !strings.Contains(loc, "failed=0") {
		t.Errorf("expected failed=0; got %s", loc)
	}

	ctx := context.Background()
	for _, code := range []string{"ABCD1111ABCD", "EFGH2222EFGH", "IJKL3333IJKL"} {
		v, err := app.DB.GetVoucher(ctx, code)
		if err != nil || v == nil {
			t.Errorf("voucher %s not created (err=%v)", code, err)
		}
	}
}

func TestAdminVoucherImportRejectsDuplicates(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.CreateVoucher(ctx, "DUPDUPDUPDUP", 30, "", "", nil)

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/vouchers/import",
		url.Values{"_csrf": {csrf}, "bulk": {"DUPDUPDUPDUP,30\nNEWNEWNEWNEW,30"}}, jar)
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "added=1") {
		t.Errorf("expected added=1; got %s", loc)
	}
	if !strings.Contains(loc, "failed=1") {
		t.Errorf("expected failed=1 (dup); got %s", loc)
	}
}

func TestAdminVoucherImportNormalizesCodes(t *testing.T) {
	// User pastes a code with dashes / lowercase. voucher.Canon should
	// normalize to dash-less uppercase.
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/vouchers/import",
		url.Values{"_csrf": {csrf}, "bulk": {"abcd-1111-abcd,30,paste"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "added=1") {
		t.Errorf("normalized import failed: %s", res.Header.Get("Location"))
	}
	v, _ := app.DB.GetVoucher(context.Background(), "ABCD1111ABCD")
	if v == nil {
		t.Error("voucher should be stored as normalized uppercase dashless")
	}
}

func TestAdminVoucherImportSkipsTooShortCodes(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/vouchers/import",
		url.Values{"_csrf": {csrf}, "bulk": {"AB,30\nABCD1111ABCD,30"}}, jar)
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "added=1") || !strings.Contains(loc, "failed=1") {
		t.Errorf("short-code skip: %s", loc)
	}
}

func TestAdminVouchersPageShowsImportSection(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/vouchers", nil, jar)
	if !strings.Contains(body, "导入已有充值码") {
		t.Error("page should have voucher import section")
	}
	if !strings.Contains(body, `action="/admin/vouchers/import"`) {
		t.Error("page should have import form")
	}
}
