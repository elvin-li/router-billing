package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// RevokeVoucherBatch should flip exactly the still-usable rows in the named
// batch and leave redeemed / already-revoked / other-batch rows alone.
func TestRevokeVoucherBatchOnlyAffectsUsable(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// batch killme: 3 usable + 1 already-redeemed + 1 already-revoked.
	for _, c := range []string{"KILL1111KILL", "KILL2222KILL", "KILL3333KILL", "KILL4444KILL", "KILL5555KILL"} {
		if _, err := app.DB.CreateVoucher(ctx, c, 30, "", "killme", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := app.DB.RedeemVoucher(ctx, "KILL4444KILL", "AA:BB:CC:DD:EE:01", nil); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.RevokeVoucher(ctx, "KILL5555KILL"); err != nil {
		t.Fatal(err)
	}
	// Untouched control batch: should remain unaffected.
	if _, err := app.DB.CreateVoucher(ctx, "KEEP1111KEEP", 30, "", "keepme", nil); err != nil {
		t.Fatal(err)
	}

	n, err := app.DB.RevokeVoucherBatch(ctx, "killme")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("expected 3 rows flipped, got %d", n)
	}

	// killme: the 3 originally-usable should now be revoked.
	for _, c := range []string{"KILL1111KILL", "KILL2222KILL", "KILL3333KILL"} {
		v, _ := app.DB.GetVoucher(ctx, c)
		if v == nil || !v.Revoked {
			t.Errorf("%s should be revoked; got %+v", c, v)
		}
	}
	// Already-redeemed row must NOT be marked revoked (revoking would lie
	// about real usage; redeemed_at survives).
	v4, _ := app.DB.GetVoucher(ctx, "KILL4444KILL")
	if v4 == nil || v4.Revoked || v4.RedeemedAt == nil {
		t.Errorf("redeemed voucher should stay redeemed-only; got %+v", v4)
	}
	// Already-revoked row stays revoked (no double-flip side effect — count
	// shouldn't include it).
	v5, _ := app.DB.GetVoucher(ctx, "KILL5555KILL")
	if v5 == nil || !v5.Revoked {
		t.Errorf("already-revoked should stay revoked; got %+v", v5)
	}
	// Other batch untouched.
	keep, _ := app.DB.GetVoucher(ctx, "KEEP1111KEEP")
	if keep == nil || keep.Revoked {
		t.Errorf("other-batch voucher should not be affected; got %+v", keep)
	}
}

func TestRevokeVoucherBatchEmptyBatchHitsUnbatched(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	// 2 unbatched vouchers + 1 batched. The batched one must survive a
	// RevokeVoucherBatch("") call — the empty string is the canonical
	// representation of the "(no batch)" bucket.
	_, _ = app.DB.CreateVoucher(ctx, "NOBAT111NOBT", 30, "", "", nil)
	_, _ = app.DB.CreateVoucher(ctx, "NOBAT222NOBT", 30, "", "", nil)
	_, _ = app.DB.CreateVoucher(ctx, "BATCH111BTCH", 30, "", "real", nil)

	n, err := app.DB.RevokeVoucherBatch(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 unbatched rows revoked, got %d", n)
	}
	v, _ := app.DB.GetVoucher(ctx, "BATCH111BTCH")
	if v == nil || v.Revoked {
		t.Errorf("batched voucher must not be touched; got %+v", v)
	}
}

func TestAdminVoucherBatchRevokeEndToEnd(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	for _, c := range []string{"AAAAEEEE1111", "AAAAEEEE2222", "AAAAEEEE3333"} {
		if _, err := app.DB.CreateVoucher(ctx, c, 30, "", "e2e-batch", nil); err != nil {
			t.Fatal(err)
		}
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/vouchers/batch/revoke",
		url.Values{"_csrf": {csrf}, "batch": {"e2e-batch"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=batch_revoke") || !strings.Contains(loc, "revoked=3") {
		t.Errorf("redirect should signal batch_revoke success; got %s", loc)
	}

	// All three should be revoked.
	for _, c := range []string{"AAAAEEEE1111", "AAAAEEEE2222", "AAAAEEEE3333"} {
		v, _ := app.DB.GetVoucher(ctx, c)
		if v == nil || !v.Revoked {
			t.Errorf("%s should be revoked; got %+v", c, v)
		}
	}

	// Audit trail should record the batch + count for ops review.
	entries, _ := app.DB.ListAudit(ctx, 10)
	found := false
	for _, e := range entries {
		if e.Action == "voucher_batch_revoke" && e.Target == "e2e-batch" {
			found = true
			if !strings.Contains(e.Detail, "count=3") {
				t.Errorf("audit detail should include count=3; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("voucher_batch_revoke audit row missing")
	}
}

func TestAdminVoucherBatchRevokeRequiresCSRF(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	// Same jar but omit the _csrf form field — double-submit pattern must
	// reject the request even with a valid session cookie.
	res, _ := do(t, h, "POST", "/admin/vouchers/batch/revoke",
		url.Values{"batch": {"anything"}}, jar)
	if res.StatusCode != 403 {
		t.Errorf("missing csrf should give 403; got %d", res.StatusCode)
	}
}

func TestAdminVoucherBatchRevokeUIShowsButton(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.CreateVoucher(ctx, "UIVIS1111UIV", 30, "", "show-button", nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/vouchers", nil, jar)
	if !strings.Contains(body, "/admin/vouchers/batch/revoke") {
		t.Error("voucher page should expose the batch-revoke form")
	}
	if !strings.Contains(body, "show-button") {
		t.Error("page should include the batch name we just created")
	}
}
