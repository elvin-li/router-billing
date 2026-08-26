package server

import (
	"net/url"
	"strings"
	"testing"
)

// Regression (v0.100): the raw voucher code was concatenated unescaped
// into the /redeem redirect — "X&ok=1" injected a fake success flag and
// "X#frag" truncated the query. Now everything goes through
// url.QueryEscape and must round-trip exactly.
func TestRedeemCodeEscapedInRedirect(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	res, _ := do(t, h, "POST", "/redeem",
		url.Values{"code": {"X&ok=1"}, "mac": {"aa:bb:cc:dd:ee:ff"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	u, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location doesn't parse: %v", err)
	}
	q := u.Query()
	if got := q.Get("code"); got != "X&ok=1" {
		t.Errorf("code round-trip = %q, want %q", got, "X&ok=1")
	}
	if q.Get("ok") != "" {
		t.Errorf("injected ok=1 leaked into the redirect: %s", res.Header.Get("Location"))
	}
	if q.Get("err") == "" {
		t.Error("err flash missing from redirect")
	}
}

// Regression (v0.100): admin-supplied batch names were embedded raw in the
// post-generate redirect. "a&ok=err" would inject params; spaces made the
// Location header invalid.
func TestVoucherGenerateBatchEscapedInRedirect(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/vouchers/generate",
		url.Values{"_csrf": {csrf}, "count": {"1"}, "days": {"7"}, "batch": {"a&b c"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if strings.Contains(loc, " ") {
		t.Errorf("Location contains a raw space: %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location doesn't parse: %v", err)
	}
	if got := u.Query().Get("batch"); got != "a&b c" {
		t.Errorf("batch round-trip = %q, want %q", got, "a&b c")
	}
}

// Regression (v0.100): revoking the unbatched bucket redirected with a
// literal `batch=(no batch)` — raw space and parens in the Location header.
func TestVoucherBatchRevokeNoBatchRedirectValid(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	// One unbatched voucher to revoke.
	if _, err := app.DB.CreateVoucher(contextForTest(), "NOBATCH23456", 30, "", "", nil); err != nil {
		t.Fatal(err)
	}

	res, _ := do(t, h, "POST", "/admin/vouchers/batch/revoke",
		url.Values{"_csrf": {csrf}, "batch": {"(no batch)"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if strings.Contains(loc, " ") {
		t.Errorf("Location contains a raw space: %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location doesn't parse: %v", err)
	}
	q := u.Query()
	if q.Get("ok") != "batch_revoke" || q.Get("revoked") != "1" {
		t.Errorf("unexpected flash params: %s", loc)
	}
	if got := q.Get("batch"); got != "(no batch)" {
		t.Errorf("batch round-trip = %q, want %q", got, "(no batch)")
	}
}
