package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GET /admin/stats/stream — SSE that pushes the dashboard stats every 5s.
// Consumed by the JS on /admin/macs to update stat-cards live without reload.
func (a *App) handleAdminStatsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	send := func() {
		stats, _ := a.DB.Stats(r.Context())
		att, _ := a.DB.Attention(r.Context())
		buf, _ := json.Marshal(map[string]any{
			"total":           stats.Total,
			"active":          stats.Active,
			"expired":         stats.Expired,
			"users":           stats.Users,
			"revenue_cents":   stats.RevenueCents,
			"attention":       att,
			"attention_total": att.Total(),
			"ts":              time.Now().Unix(),
		})
		fmt.Fprintf(w, "event: stats\ndata: %s\n\n", buf)
		flusher.Flush()
	}

	send()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	hb := time.NewTicker(25 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
			send()
		case <-hb.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}
