package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// planKeyOK is the lone validator that decides what plan_keys can land in
// the URL/audit/DB. Pin every edge case here so we don't accidentally
// loosen it during a future refactor.
func TestPlanKeyOK(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"month", true},
		{"day-7", true},
		{"day_7", true},
		{"WEEK1", true},
		{"a", true},
		{strings.Repeat("a", 32), true},
		{"", false},                      // empty
		{strings.Repeat("a", 33), false}, // too long
		{"has space", false},
		{"has/slash", false},
		{"has?query", false},
		{"has.dot", false},
		{"中文", false}, // non-ASCII
		{"plus+sign", false},
		{"semi;colon", false},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			if got := planKeyOK(c.key); got != c.want {
				t.Errorf("planKeyOK(%q) = %v, want %v", c.key, got, c.want)
			}
		})
	}
}

func TestAdminPlanSaveAcceptsValid(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/plans/save",
		url.Values{
			"_csrf":       {csrf},
			"key":         {"valid-plan"},
			"label":       {"30 天"},
			"days":        {"30"},
			"price_cents": {"500"},
			"sort_order":  {"10"},
			"enabled":     {"on"},
		}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("expected 303; got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "ok=1") {
		t.Errorf("expected ok=1 redirect; got %s", loc)
	}
	// Plan should be persisted.
	plans, _ := app.DB.ListPlans(context.Background())
	found := false
	for _, p := range plans {
		if p.Key == "valid-plan" {
			found = true
		}
	}
	if !found {
		t.Error("valid plan was not saved")
	}
}

func TestAdminPlanSaveRejectsBadKey(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/plans/save",
		url.Values{
			"_csrf":       {csrf},
			"key":         {"has/slash"},
			"label":       {"X"},
			"days":        {"30"},
			"price_cents": {"100"},
		}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=bad_key") {
		t.Errorf("expected err=bad_key; got %s", res.Header.Get("Location"))
	}
}

func TestAdminPlanSaveRejectsDaysTooLarge(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/plans/save",
		url.Values{
			"_csrf":       {csrf},
			"key":         {"toolong"},
			"label":       {"X"},
			"days":        {"99999"}, // 270+ years
			"price_cents": {"100"},
		}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=days_too_large") {
		t.Errorf("expected err=days_too_large; got %s", res.Header.Get("Location"))
	}
	// Plan must NOT have landed.
	plans, _ := app.DB.ListPlans(context.Background())
	for _, p := range plans {
		if p.Key == "toolong" {
			t.Error("rejected plan was saved anyway")
		}
	}
}

func TestAdminPlanSaveRejectsPriceTooLarge(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/plans/save",
		url.Values{
			"_csrf":       {csrf},
			"key":         {"pricey"},
			"label":       {"X"},
			"days":        {"30"},
			"price_cents": {"99999999"}, // ¥999,999.99 — extra zero
		}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=price_too_large") {
		t.Errorf("expected err=price_too_large; got %s", res.Header.Get("Location"))
	}
}

func TestAdminPlanSaveRejectsLabelTooLong(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/plans/save",
		url.Values{
			"_csrf":       {csrf},
			"key":         {"longlabel"},
			"label":       {strings.Repeat("X", 100)},
			"days":        {"30"},
			"price_cents": {"100"},
		}, jar)
	if !strings.Contains(res.Header.Get("Location"), "err=label_too_long") {
		t.Errorf("expected err=label_too_long; got %s", res.Header.Get("Location"))
	}
}
