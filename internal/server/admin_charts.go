package server

import (
	"context"
	"net/http"
	"sort"
	"time"

	"router-billing/internal/config"
	"router-billing/internal/models"
)

// GET /admin/charts.json — last 30 days of stats_daily snapshots, with today's
// live numbers patched on the tail point so the chart is fresh.
func (a *App) handleAdminCharts(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.ListStatsDaily(r.Context(), 30)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	live, _ := a.DB.Stats(r.Context())
	today := time.Now().UTC().Format("2006-01-02")
	if len(rows) == 0 || rows[len(rows)-1].Day != today {
		rows = append(rows, models.StatsDaily{
			Day:          today,
			MacTotal:     live.Total,
			MacActive:    live.Active,
			UsersTotal:   live.Users,
			RevenueCents: live.RevenueCents,
			SnapshotAt:   time.Now().UTC(),
		})
	} else {
		i := len(rows) - 1
		rows[i].MacTotal = live.Total
		rows[i].MacActive = live.Active
		rows[i].UsersTotal = live.Users
		rows[i].RevenueCents = live.RevenueCents
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows})
}

// effectivePlans returns the merged config + DB plan set.
// DB overrides config; disabled DB plans remove config plans of the same key.
func (a *App) effectivePlans(ctx context.Context) map[string]config.Plan {
	out := map[string]config.Plan{}
	for k, p := range a.Cfg.Plans {
		out[k] = p
	}
	if dbPlans, err := a.DB.ListPlans(ctx); err == nil {
		for _, p := range dbPlans {
			if !p.Enabled {
				delete(out, p.Key)
				continue
			}
			out[p.Key] = config.Plan{Label: p.Label, Days: p.Days, PriceCents: p.PriceCents}
		}
	}
	return out
}

// effectivePlanKeys returns the keys in stable order (by days asc).
func (a *App) effectivePlanKeys(ctx context.Context) []string {
	plans := a.effectivePlans(ctx)
	keys := make([]string, 0, len(plans))
	for k := range plans {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return plans[keys[i]].Days < plans[keys[j]].Days
	})
	return keys
}
