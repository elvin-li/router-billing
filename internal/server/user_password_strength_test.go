package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestPasswordStrengthLaxDefault(t *testing.T) {
	app := setupTestApp(t)
	// Cfg.Security.PasswordStrength is empty by default → lax.
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800150000"}, "password": {"123456"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "/user/me") {
		t.Errorf("lax mode should accept 123456; redirect=%s", res.Header.Get("Location"))
	}
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800150000")
	if u == nil {
		t.Error("user should be created in lax mode")
	}
}

func TestPasswordStrengthStrictRejectsWeak(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security.PasswordStrength = "strict"
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800150001"}, "password": {"123456"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "err=bad_password") {
		t.Errorf("strict mode should reject 123456; redirect=%s", loc)
	}
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800150001")
	if u != nil {
		t.Error("user should NOT be created in strict mode with weak pw")
	}
}

func TestPasswordStrengthStrictAcceptsMixedShort(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security.PasswordStrength = "strict"
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800150002"}, "password": {"zb6kf9"}}, nil)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if strings.Contains(res.Header.Get("Location"), "err=") {
		t.Errorf("strict mode should accept zb6kf9; got %s", res.Header.Get("Location"))
	}
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800150002")
	if u == nil {
		t.Error("user should be created with mixed short pw in strict mode")
	}
}

func TestPasswordStrengthStrictAcceptsLongPassphrase(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.Security.PasswordStrength = "strict"
	h := app.Routes()
	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800150003"}, "password": {"correcthorsebatterystaple"}}, nil)
	if strings.Contains(res.Header.Get("Location"), "err=") {
		t.Errorf("strict mode should accept long passphrase; got %s", res.Header.Get("Location"))
	}
}

func TestPasswordStrengthStrictAppliesToReset(t *testing.T) {
	// /user/me password-change path should also use the strict validator.
	app := setupTestApp(t)
	app.Cfg.Security.PasswordStrength = "strict"
	h := app.Routes()

	res, _ := do(t, h, "POST", "/user/register",
		url.Values{"phone": {"13800150004"}, "password": {"zb6kf9"}}, nil)
	jar := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/me", nil, jar)
	for k, v := range cookieJar(res2) {
		jar[k] = v
	}
	csrf := jar[csrfCookieName]

	// Try to change to a weak password — should be rejected.
	res3, _ := do(t, h, "POST", "/user/password",
		url.Values{
			"_csrf":        {csrf},
			"old_password": {"zb6kf9"},
			"new_password": {"123456"},
		}, jar)
	if !strings.Contains(res3.Header.Get("Location"), "err=bad_password") {
		t.Errorf("strict mode reject on change; got %s", res3.Header.Get("Location"))
	}
}
