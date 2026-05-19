package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/models"
)

func TestAPIPlanListReturnsConfigAndDB(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	// Seed a DB-overlay plan; the config-fallback plans from setupTestApp
	// should also appear.
	_ = app.DB.UpsertPlan(context.Background(), models.Plan{Key: "week", Label: "7 天", Days: 7, PriceCents: 250, SortOrder: 10, Enabled: true})

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/plans", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Plans []struct {
			Key   string `json:"key"`
			Label string `json:"label"`
			Days  int    `json:"days"`
		} `json:"plans"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Plans) == 0 {
		t.Fatal("plans should not be empty (config fallbacks alone should yield rows)")
	}
	found := false
	for _, p := range resp.Plans {
		if p.Key == "week" && p.Days == 7 {
			found = true
		}
	}
	if !found {
		t.Error("DB-overlay plan 'week' missing from response")
	}
}

func TestAPIPlanSavePersists(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/plans/save", "rb_w",
		`{"key":"api-month","label":"30 天 (API)","days":30,"price_cents":500,"enabled":true}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	plans, _ := app.DB.ListPlans(context.Background())
	found := false
	for _, p := range plans {
		if p.Key == "api-month" {
			found = true
			if p.Days != 30 || p.PriceCents != 500 {
				t.Errorf("plan persisted wrong: %+v", p)
			}
		}
	}
	if !found {
		t.Error("saved plan not in DB")
	}

	// Audit row with via=api so reviewers can distinguish from UI saves.
	entries, _ := app.DB.ListAudit(context.Background(), 10)
	auditFound := false
	for _, e := range entries {
		if e.Action == "plan_save" && e.Target == "api-month" {
			auditFound = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit should mark via=api; got %q", e.Detail)
			}
		}
	}
	if !auditFound {
		t.Error("plan_save audit row missing")
	}
}

func TestAPIPlanSaveValidationMatches(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()

	cases := []struct {
		name      string
		body      string
		wantField string
	}{
		{"bad_key", `{"key":"has/slash","label":"X","days":30,"price_cents":100}`, "key"},
		{"label_too_long", `{"key":"x","label":"` + strings.Repeat("Y", 100) + `","days":30,"price_cents":100}`, "label"},
		{"days_too_large", `{"key":"x","label":"X","days":99999,"price_cents":100}`, "days"},
		{"price_too_large", `{"key":"x","label":"X","days":30,"price_cents":99999999}`, "price_cents"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := apiReq(t, h, "POST", "/api/admin/plans/save", "rb_w", c.body)
			if rr.Code != 400 {
				t.Errorf("expected 400; got %d", rr.Code)
			}
			var resp struct {
				Field string `json:"field"`
			}
			_ = json.Unmarshal(rr.Body.Bytes(), &resp)
			if resp.Field != c.wantField {
				t.Errorf("field hint: got %q want %q", resp.Field, c.wantField)
			}
		})
	}
}

func TestAPIPlanDeleteHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	_ = app.DB.UpsertPlan(context.Background(), models.Plan{Key: "doomed", Label: "X", Days: 1, PriceCents: 100, Enabled: true})
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/plans/delete", "rb_w", `{"key":"doomed"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d", rr.Code)
	}
	plans, _ := app.DB.ListPlans(context.Background())
	for _, p := range plans {
		if p.Key == "doomed" {
			t.Error("plan still present after delete")
		}
	}
}

func TestAPIPlanDeleteMissingKeyIs400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/plans/delete", "rb_w", `{}`)
	if rr.Code != 400 {
		t.Errorf("missing key should be 400; got %d", rr.Code)
	}
}

func TestAPIPlanSaveReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/plans/save", "rb_ro",
		`{"key":"x","label":"X","days":30,"price_cents":100}`)
	if rr.Code != 403 {
		t.Errorf("readonly write should be 403; got %d", rr.Code)
	}
}

func TestAPIPlanDeleteReadonlyRejected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/plans/delete", "rb_ro", `{"key":"x"}`)
	if rr.Code != 403 {
		t.Errorf("readonly delete should be 403; got %d", rr.Code)
	}
}

// readonly token CAN read /api/admin/plans (GET).
func TestAPIPlanListReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/plans", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly GET should be 200; got %d", rr.Code)
	}
}
