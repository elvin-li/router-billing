package server

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

// Regression tests for the maxGrantDays (3650) cap. Before the cap, a huge
// `days` value (typo or scripted client) flowed into AddDate(0,0,days),
// where extreme values overflow time.Time and can wrap expires_at into the
// past — turning a "grant" into a silent revoke. Every grant/voucher entry
// point must reject days > 3650.

func TestAPIUserGrantDaysTooLargeRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800130001", "h")
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:02:01", "phone", 30, &u.ID); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant", "rb_w",
		`{"user_id":`+strconv.FormatInt(u.ID, 10)+`,"days":100000}`)
	if rr.Code != 400 {
		t.Errorf("over-cap days should 400; got %d body=%s", rr.Code, rr.Body.String())
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:02:01")
	if m == nil || m.ExpiresAt.After(time.Now().AddDate(0, 0, 31)) {
		t.Error("MAC expiry should be untouched by rejected grant")
	}
}

func TestAPIUserGrantByPhoneDaysTooLargeRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	if _, err := app.DB.CreateUser(ctx, "13800130002", "h"); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/users/grant-by-phone", "rb_w",
		`{"phone":"13800130002","days":100000}`)
	if rr.Code != 400 {
		t.Errorf("over-cap days should 400; got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAPIVoucherGenerateDaysTooLargeRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/vouchers/generate", "rb_w",
		`{"count":1,"days":100000}`)
	if rr.Code != 400 {
		t.Errorf("over-cap days should 400; got %d body=%s", rr.Code, rr.Body.String())
	}
	rr = apiReq(t, h, "POST", "/api/admin/vouchers/generate", "rb_w",
		`{"count":1,"days":30,"expires_days":100000}`)
	if rr.Code != 400 {
		t.Errorf("over-cap expires_days should 400; got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminMACAddDaysTooLargeRejected(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/macs/add",
		url.Values{"_csrf": {csrf}, "mac": {"AA:BB:CC:00:03:01"}, "days": {"100000"}}, jar)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "err=invalid_days") {
		t.Errorf("expected redirect with err=invalid_days; got %d -> %s",
			res.StatusCode, res.Header.Get("Location"))
	}
	if m, _ := app.DB.GetMAC(context.Background(), "AA:BB:CC:00:03:01"); m != nil {
		t.Error("over-cap add should not create the MAC")
	}
}

func TestAdminMACExtendDaysTooLargeRejected(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:03:02", "x", 30, nil); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/macs/extend",
		url.Values{"_csrf": {csrf}, "mac": {"AA:BB:CC:00:03:02"}, "days": {"100000"}}, jar)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "err=invalid_days") {
		t.Errorf("expected redirect with err=invalid_days; got %d -> %s",
			res.StatusCode, res.Header.Get("Location"))
	}
	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:03:02")
	if m == nil || m.ExpiresAt.After(time.Now().AddDate(0, 0, 31)) {
		t.Error("MAC expiry should be untouched by rejected extend")
	}
}

func TestAdminMACBulkExtendDaysTooLargeRejected(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:03:03", "x", 30, nil); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/macs/bulk",
		url.Values{"_csrf": {csrf}, "action": {"extend"},
			"mac": {"AA:BB:CC:00:03:03"}, "days": {"100000"}}, jar)
	if res.StatusCode != 303 || !strings.Contains(res.Header.Get("Location"), "err=invalid_days") {
		t.Errorf("expected redirect with err=invalid_days; got %d -> %s",
			res.StatusCode, res.Header.Get("Location"))
	}
}

func TestAdminMACImportDaysTooLargeRowFails(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	// default_days over the cap → whole request rejected.
	res, _ := do(t, h, "POST", "/admin/macs/import",
		url.Values{"_csrf": {csrf}, "default_days": {"100000"},
			"bulk": {"AA:BB:CC:00:03:04"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=invalid_days") {
		t.Errorf("over-cap default_days should redirect with err=invalid_days; got %s",
			res.Header.Get("Location"))
	}

	// Per-row over-cap days → that row fails, valid row still imports.
	do(t, h, "POST", "/admin/macs/import",
		url.Values{"_csrf": {csrf},
			"bulk": {"AA:BB:CC:00:03:05,100000\nAA:BB:CC:00:03:06,30"}}, jar)
	ctx := context.Background()
	if m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:03:05"); m != nil {
		t.Error("over-cap row should not create a MAC")
	}
	if m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:00:03:06"); m == nil {
		t.Error("valid row should still be created")
	}
}

func TestAdminVouchersGenerateDaysTooLargeRejected(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/vouchers/generate",
		url.Values{"_csrf": {csrf}, "count": {"1"}, "days": {"100000"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=invalid_days") {
		t.Errorf("over-cap days should redirect with err=invalid_days; got %s",
			res.Header.Get("Location"))
	}
}

func TestAdminVouchersImportDaysTooLargeRowFails(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	do(t, h, "POST", "/admin/vouchers/import",
		url.Values{"_csrf": {csrf},
			"bulk": {"CAPTEST123456,100000\nCAPTEST654321,30"}}, jar)
	ctx := context.Background()
	if v, _ := app.DB.GetVoucher(ctx, "CAPTEST123456"); v != nil {
		t.Error("over-cap voucher row should not be created")
	}
	if v, _ := app.DB.GetVoucher(ctx, "CAPTEST654321"); v == nil {
		t.Error("valid voucher row should still be created")
	}
}
