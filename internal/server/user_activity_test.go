package server

import (
	"net/url"
	"strings"
	"testing"

	"router-billing/internal/db"
)

func TestUserMePageShowsRecentActivity(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()

	// Register + login + fail-login + login again so there's a mix to show.
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800139040"}, "password": {"actv-pw"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("register: %d", res.StatusCode)
	}
	jar := cookieJar(res)

	do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139040"}, "password": {"WRONG"}}, nil)

	res2, body := do(t, h, "GET", "/user/me", nil, jar)
	if res2.StatusCode != 200 {
		t.Fatalf("/user/me: %d", res2.StatusCode)
	}
	if !strings.Contains(body, "最近活动") {
		t.Error("page should have 最近活动 section")
	}
	// The register row must appear (most recent first).
	if !strings.Contains(body, "注册") {
		t.Error("activity should include 注册")
	}
	if !strings.Contains(body, "登录失败（密码错误）") {
		t.Error("activity should include the failed login")
	}
}

func TestActivityLabelKnowsAllSecurityEvents(t *testing.T) {
	// The label function is a long switch — confirm every value renders to a
	// non-empty Chinese label (i.e. nothing falls through to the action name
	// for the events the user actually cares about).
	known := []string{
		"login", "login_failed", "login_suspended", "register",
		"password_change", "password_reset", "password_reset_request", "password_reset_failed",
		"2fa_failed", "2fa_locked", "2fa_enroll_begin", "2fa_enroll_failed",
		"2fa_enrolled", "2fa_disabled", "2fa_disable_failed",
		"2fa_backup_codes_issued", "2fa_backup_codes_regenerated",
		"2fa_trusted_device_issued", "2fa_trusted_device_revoked", "2fa_trusted_devices_revoked_all",
		"replace", "claim", "label",
	}
	for _, k := range known {
		got := activityLabel(k)
		if got == k {
			t.Errorf("activityLabel(%q) fell through to action name", k)
		}
		if got == "" {
			t.Errorf("activityLabel(%q) returned empty string", k)
		}
		// Must contain at least one non-ASCII rune (Chinese label).
		hasNonASCII := false
		for _, r := range got {
			if r >= 0x80 {
				hasNonASCII = true
				break
			}
		}
		if !hasNonASCII {
			t.Errorf("activityLabel(%q) = %q has no Chinese chars", k, got)
		}
	}
}

func TestActivityLabelFallthroughForUnknown(t *testing.T) {
	// Unknown actions must pass through verbatim — never silently lost.
	if got := activityLabel("custom_admin_action"); got != "custom_admin_action" {
		t.Errorf("unknown action should pass through; got %q", got)
	}
}

func TestExtractIPFromDetail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"no ip here", ""},
		{"ip=10.0.0.5", "10.0.0.5"},
		{"foo ip=192.168.1.1 bar", "192.168.1.1"},
		{"via=sms provider=aliyun ip=1.2.3.4", "1.2.3.4"},
		{"trailing ip=2001:db8::1,extra", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := extractIPFromDetail(c.in); got != c.want {
			t.Errorf("extractIPFromDetail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatActivityShape(t *testing.T) {
	entries := []db.AuditEntry{
		{Action: "login", Detail: "via=totp ip=10.0.0.1"},
		{Action: "register", Detail: "192.168.1.1"},
	}
	vs := formatActivity(entries)
	if len(vs) != 2 {
		t.Fatalf("expected 2; got %d", len(vs))
	}
	if vs[0].Label != "登录" {
		t.Errorf("first label = %q", vs[0].Label)
	}
	if vs[0].IP != "10.0.0.1" {
		t.Errorf("first IP = %q", vs[0].IP)
	}
	if vs[1].Label != "注册" {
		t.Errorf("second label = %q", vs[1].Label)
	}
	// Register's detail is bare IP string, not "ip=..." — extractor returns "".
	if vs[1].IP != "" {
		t.Errorf("second IP should be empty; got %q", vs[1].IP)
	}
}
