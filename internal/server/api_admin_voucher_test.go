package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
)

func TestAPIVoucherGenerateHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/vouchers/generate", "rb_w",
		`{"count":5,"days":30,"batch":"api-gen-test","label":"corp-A","expires_days":180}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Batch   string   `json:"batch"`
		Created int      `json:"created"`
		Codes   []string `json:"codes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Created != 5 || len(resp.Codes) != 5 {
		t.Errorf("expected 5 codes, got %d created / %d in list", resp.Created, len(resp.Codes))
	}
	if resp.Batch != "api-gen-test" {
		t.Errorf("batch echoed wrong: %q", resp.Batch)
	}
	// Codes should be pretty-formatted (4-4-4 with dashes) so callers can
	// print them directly. We don't check the exact format here, just that
	// each code has dashes and is the expected length.
	for _, c := range resp.Codes {
		if !strings.Contains(c, "-") {
			t.Errorf("code %q should be pretty-formatted with dashes", c)
		}
		if len(c) != 14 { // 4+1+4+1+4
			t.Errorf("code %q wrong length", c)
		}
	}
	// DB rows actually exist.
	ctx := context.Background()
	stats, _ := app.DB.VoucherBatchStats(ctx)
	var found bool
	for _, s := range stats {
		if s.Batch == "api-gen-test" {
			found = true
			if s.Total != 5 {
				t.Errorf("batch should have 5 vouchers; got %d", s.Total)
			}
		}
	}
	if !found {
		t.Error("api-gen-test batch missing from VoucherBatchStats")
	}
}

func TestAPIVoucherGenerateDefaultsBatchName(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	// Omit batch — handler should mint a timestamp-based default.
	rr := apiReq(t, h, "POST", "/api/admin/vouchers/generate", "rb_w",
		`{"count":2,"days":30}`)
	var resp struct {
		Batch string `json:"batch"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !strings.HasPrefix(resp.Batch, "B") {
		t.Errorf("auto-batch should start with 'B'; got %q", resp.Batch)
	}
}

func TestAPIVoucherGenerateRejectsOversizeCount(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/vouchers/generate", "rb_w",
		`{"count":5000,"days":30}`)
	if rr.Code != 400 {
		t.Errorf("oversize count should give 400; got %d", rr.Code)
	}
}

func TestAPIVoucherGenerateRejectsZeroDays(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/vouchers/generate", "rb_w",
		`{"count":10,"days":0}`)
	if rr.Code != 400 {
		t.Errorf("zero days should give 400; got %d", rr.Code)
	}
}

func TestAPIVoucherGenerateReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/vouchers/generate", "rb_ro",
		`{"count":5,"days":30}`)
	if rr.Code != 403 {
		t.Errorf("readonly token should get 403; got %d", rr.Code)
	}
}

func TestAPIVoucherBatchRevokeHappyPath(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	// Seed 4 vouchers in batch "api-kill": 1 redeemed, 1 already revoked, 2 unused.
	for _, c := range []string{"APIK1111APIK", "APIK2222APIK", "APIK3333APIK", "APIK4444APIK"} {
		if _, err := app.DB.CreateVoucher(ctx, c, 30, "", "api-kill", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := app.DB.RedeemVoucher(ctx, "APIK1111APIK", "AA:BB:CC:DD:EE:F1", nil); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.RevokeVoucher(ctx, "APIK2222APIK"); err != nil {
		t.Fatal(err)
	}

	rr := apiReq(t, h, "POST", "/api/admin/vouchers/batch/revoke", "rb_w",
		`{"batch":"api-kill"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Revoked int `json:"revoked"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Revoked != 2 {
		t.Errorf("expected 2 newly-revoked; got %d", resp.Revoked)
	}
	// Audit row landed with the via=api marker so reviewers can tell source.
	entries, _ := app.DB.ListAudit(ctx, 10)
	found := false
	for _, e := range entries {
		if e.Action == "voucher_batch_revoke" && e.Target == "api-kill" {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit detail should mark via=api; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("voucher_batch_revoke audit row missing")
	}
}

func TestAPIVoucherBatchRevokeReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/vouchers/batch/revoke", "rb_ro",
		`{"batch":"anything"}`)
	if rr.Code != 403 {
		t.Errorf("readonly should get 403; got %d", rr.Code)
	}
}

func TestAPIVoucherBatchRevokeEmptyBatchHitsUnbatched(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	_, _ = app.DB.CreateVoucher(ctx, "NOAPI1111NOA", 30, "", "", nil)
	_, _ = app.DB.CreateVoucher(ctx, "BATAPI111BAT", 30, "", "real", nil)

	rr := apiReq(t, h, "POST", "/api/admin/vouchers/batch/revoke", "rb_w",
		`{"batch":""}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	var resp struct {
		Revoked int `json:"revoked"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Revoked != 1 {
		t.Errorf("expected only the unbatched voucher revoked; got %d", resp.Revoked)
	}
	v, _ := app.DB.GetVoucher(ctx, "BATAPI111BAT")
	if v == nil || v.Revoked {
		t.Errorf("batched voucher must not be touched; got %+v", v)
	}
}

// Anti-regression: response must not leak the password_hash field via any
// path through the voucher endpoints. Same red-line check the user-listing
// endpoint has.
func TestAPIVoucherGenerateResponseHasNoSensitiveFields(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/vouchers/generate", "rb_w",
		`{"count":1,"days":30}`)
	body := rr.Body.String()
	for _, banned := range []string{"password_hash", "totp_secret", "session_token"} {
		if strings.Contains(body, banned) {
			t.Errorf("response leaks sensitive field %q: %s", banned, body)
		}
	}
}
