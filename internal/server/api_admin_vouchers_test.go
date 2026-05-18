package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIVoucherListReturnsVouchers(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_voucher_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()

	_, _ = app.DB.CreateVoucher(ctx, "BATCHA1A1A1A1", 30, "promo", "batch-A", nil)
	_, _ = app.DB.CreateVoucher(ctx, "BATCHB2B2B2B2", 365, "yearly", "batch-B", nil)

	rr := apiReq(t, h, "GET", "/api/admin/vouchers", "rb_voucher_ro", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Vouchers []apiVoucher `json:"vouchers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Vouchers) != 2 {
		t.Errorf("expected 2 vouchers; got %d", len(resp.Vouchers))
	}
	// Codes are truncated to 4-char prefix + ellipsis.
	for _, v := range resp.Vouchers {
		if len(v.CodePrefix) != len("BATC"+"…") {
			t.Errorf("CodePrefix should be 4 chars + …; got %q", v.CodePrefix)
		}
		if !strings.HasSuffix(v.CodePrefix, "…") {
			t.Errorf("CodePrefix should end with ellipsis; got %q", v.CodePrefix)
		}
	}
}

func TestAPIVoucherListBatchFilter(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_voucher_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()
	_, _ = app.DB.CreateVoucher(ctx, "AAAA1111AAAA", 30, "x", "batch-A", nil)
	_, _ = app.DB.CreateVoucher(ctx, "BBBB2222BBBB", 30, "x", "batch-B", nil)
	_, _ = app.DB.CreateVoucher(ctx, "CCCC3333CCCC", 30, "x", "batch-A", nil)

	rr := apiReq(t, h, "GET", "/api/admin/vouchers?batch=batch-A", "rb_voucher_ro", "")
	var resp struct {
		Vouchers []apiVoucher `json:"vouchers"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Vouchers) != 2 {
		t.Errorf("batch=batch-A should return 2; got %d", len(resp.Vouchers))
	}
}

func TestAPIVoucherListNeverLeaksFullCode(t *testing.T) {
	// Critical regression guard: a leaked monitoring token must NOT be able
	// to scrape unredeemed voucher codes (which would equal free MAC time).
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_voucher_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()
	const fullCode = "SECRETCODE99X"
	_, _ = app.DB.CreateVoucher(ctx, fullCode, 30, "", "batch-x", nil)

	rr := apiReq(t, h, "GET", "/api/admin/vouchers", "rb_voucher_ro", "")
	body := rr.Body.String()
	if strings.Contains(body, fullCode) {
		t.Errorf("response leaks full voucher code: %s", body)
	}
	// Confirm we DID return the prefix, so the API isn't broken.
	if !strings.Contains(body, "SECR…") {
		t.Errorf("response should include 4-char prefix + ellipsis; body=%s", body)
	}
}

func TestAPIVoucherListLimitParam(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_voucher_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	ctx := context.Background()
	for i := 0; i < 6; i++ {
		_, _ = app.DB.CreateVoucher(ctx, "LIM"+strings.Repeat("X", 9)+itoaSmall(i), 30, "", "batch-l", nil)
	}
	rr := apiReq(t, h, "GET", "/api/admin/vouchers?limit=4", "rb_voucher_ro", "")
	var resp struct {
		Vouchers []apiVoucher `json:"vouchers"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Vouchers) != 4 {
		t.Errorf("limit=4 should return 4; got %d", len(resp.Vouchers))
	}
}

func TestAPIVoucherListRejectsNoToken(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_voucher_ro", Label: "x"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/vouchers", "", "")
	if rr.Code != 401 {
		t.Errorf("no token: %d", rr.Code)
	}
}

func TestVoucherCodePrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"ABC", "ABC"},
		{"ABCD", "ABCD"},
		{"ABCDE", "ABCD…"},
		{"BATCHA1A1A1A1", "BATC…"},
	}
	for _, c := range cases {
		if got := voucherCodePrefix(c.in); got != c.want {
			t.Errorf("voucherCodePrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
