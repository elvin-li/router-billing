package server

import (
	"strings"
	"testing"
)

// v0.125: userErrLabel's default branch used to return the raw code —
// the exact reflected-content-injection bug fixed for the admin pages
// and /redeem in v0.122, still open on the user portal (including the
// pre-auth public /user/login and /user/register pages).

func TestUserErrLabelNeverEchoesUnknownCode(t *testing.T) {
	injected := "维修中-请转账到13800000000"
	if got := userErrLabel(injected); got == injected || strings.Contains(got, "13800000000") {
		t.Fatalf("userErrLabel echoed attacker text: %q", got)
	}
	if got := userErrLabel("totally_unknown_code"); got != "操作失败，请重试" {
		t.Errorf("unknown code should collapse to the generic label; got %q", got)
	}
	// backup_codes_failed used to fall through to the raw string.
	if got := userErrLabel("backup_codes_failed"); got == "backup_codes_failed" || got == "" {
		t.Errorf("backup_codes_failed should map to a human label; got %q", got)
	}
	// Existing mappings unchanged.
	if got := userErrLabel("bad_credentials"); got != "手机号或密码错误" {
		t.Errorf("bad_credentials regressed: %q", got)
	}
	if got := userErrLabel(""); got != "" {
		t.Errorf("empty code must stay empty; got %q", got)
	}
}

// End-to-end: a crafted ?err= link must not surface its text on the
// public login page.
func TestUserLoginDoesNotReflectErrQuery(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	const evil = "URGENT-call-13800000000-to-unlock"
	res, body := do(t, h, "GET", "/user/login?err="+evil, nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if strings.Contains(body, evil) {
		t.Error("attacker-controlled ?err= text reflected into the user portal flash")
	}
}
