package server

import (
	"context"
	"time"

	"router-billing/internal/db"
)

// attentionCacheTTL bounds how stale the sidebar-badge / dashboard
// attention counters may be. Three seconds is invisible to a human admin
// but collapses the 6-COUNT query set that used to run:
//   - once per admin page render for the sidebar badges (adminCtx),
//   - a second time on pages that also display the counters (dashboard,
//     /admin/macs, /admin/health),
//   - every 5s per connected SSE stats stream,
//
// all funneled through the single SQLite connection a low-end router runs.
const attentionCacheTTL = 3 * time.Second

// attention returns the current AttentionCounts, served from a short-lived
// per-process cache. Errors are not cached — a failed refresh returns the
// zero value for this call and the next call retries.
func (a *App) attention(ctx context.Context) db.AttentionCounts {
	a.attMu.Lock()
	if !a.attAt.IsZero() && time.Since(a.attAt) < attentionCacheTTL {
		v := a.attVal
		a.attMu.Unlock()
		return v
	}
	a.attMu.Unlock()

	att, err := a.DB.Attention(ctx)
	if err != nil {
		return att
	}
	a.attMu.Lock()
	a.attVal, a.attAt = att, time.Now()
	a.attMu.Unlock()
	return att
}
