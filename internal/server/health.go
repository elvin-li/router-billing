package server

// Public /health endpoint — no auth, suitable for load balancers, uptime
// monitors (UptimeRobot, Pingdom, etc.), and k8s readiness probes.
//
// Distinct from /admin/health (cookie-gated, full operational stats),
// /api/admin/health (Bearer-gated, same payload as /admin/health), and
// /metrics (Bearer-gated, Prometheus exposition). Those three reveal
// operational detail that shouldn't be on the open internet.
//
// /health stays minimal on purpose: just enough for a monitor to decide
// "is the service alive and can it talk to its DB?" — no row counts, no
// revenue figures, no provider names.

import (
	"context"
	"net/http"
	"time"
)

// GET /health  (and /healthz alias)
//
// 200 OK  -> { "status": "ok",     "version": "...", "uptime_seconds": N }
// 503     -> { "status": "degraded", "error": "db ping: ..." }
//
// The DB ping is a `SELECT 1` round-trip with a 2-second deadline so a
// hung sqlite doesn't keep monitors hanging — they get the 503 and can
// page the operator.
func (a *App) handlePublicHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// `SELECT 1` round-trip to validate the connection. If sqlite is wedged
	// or the file is gone, this returns ctx.DeadlineExceeded or a driver
	// error and we surface that as 503 so monitors can page.
	_, err := a.DB.Exec(ctx, `SELECT 1`)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "degraded",
			"error":  "db ping: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        a.Version,
		"uptime_seconds": int(time.Since(a.StartAt).Seconds()),
	})
}
