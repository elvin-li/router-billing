package server

import (
	"context"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"router-billing/internal/models"
)

// GET /admin/plans — list (DB overlay first, fall back to config) + add/edit form
func (a *App) handleAdminPlans(w http.ResponseWriter, r *http.Request) {
	plans := a.activePlans(r.Context())
	a.render(w, "admin_plans.html", a.adminCtx(r, "plans", map[string]any{
		"Plans": plans,
	}))
}

// POST /admin/plans/save  {key, label, days, price_cents, sort_order, enabled}
func (a *App) handleAdminPlanSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/plans", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(r.PostForm.Get("key"))
	label := strings.TrimSpace(r.PostForm.Get("label"))
	days, _ := strconv.Atoi(r.PostForm.Get("days"))
	price, _ := strconv.Atoi(r.PostForm.Get("price_cents"))
	sortOrder, _ := strconv.Atoi(r.PostForm.Get("sort_order"))
	enabled := r.PostForm.Get("enabled") != "off"
	if key == "" || label == "" || days <= 0 || price <= 0 {
		http.Redirect(w, r, "/admin/plans?err=invalid_days", http.StatusSeeOther)
		return
	}
	p := models.Plan{
		Key: key, Label: label, Days: days, PriceCents: price,
		SortOrder: sortOrder, Enabled: enabled,
	}
	if err := a.DB.UpsertPlan(r.Context(), p); err != nil {
		log.Printf("plan save: %v", err)
		http.Redirect(w, r, "/admin/plans?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "plan_save", key, label)
	http.Redirect(w, r, "/admin/plans?ok=1", http.StatusSeeOther)
}

// POST /admin/plans/delete  {key}
func (a *App) handleAdminPlanDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/plans", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(r.PostForm.Get("key"))
	if err := a.DB.DeletePlan(r.Context(), key); err != nil {
		log.Printf("plan delete: %v", err)
	}
	a.DB.Audit(r.Context(), "admin", "plan_delete", key, "")
	http.Redirect(w, r, "/admin/plans?ok=1", http.StatusSeeOther)
}

// activePlans returns DB plans where present, falling back to config plans.
// Config plans that have a same-keyed DB row are replaced; new DB plans are added.
// Config plans the admin hasn't touched still work.
func (a *App) activePlans(ctx context.Context) []models.Plan {
	out := map[string]models.Plan{}
	for k, p := range a.Cfg.Plans {
		out[k] = models.Plan{
			Key: k, Label: p.Label, Days: p.Days,
			PriceCents: p.PriceCents, Enabled: true,
			UpdatedAt: time.Time{},
		}
	}
	if dbPlans, err := a.DB.ListPlans(ctx); err == nil {
		for _, p := range dbPlans {
			out[p.Key] = p
		}
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		pi, pj := out[keys[i]], out[keys[j]]
		if pi.SortOrder != pj.SortOrder {
			return pi.SortOrder < pj.SortOrder
		}
		return pi.Days < pj.Days
	})
	res := make([]models.Plan, 0, len(keys))
	for _, k := range keys {
		res = append(res, out[k])
	}
	return res
}
