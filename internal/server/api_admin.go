// Programmatic admin API for monitoring scripts / CI / external dashboards.
//
// Auth: `Authorization: Bearer <token>` where <token> matches one of the
// strings in config.api_tokens[].token. Constant-time compared. No CSRF
// (Bearer auth is not vulnerable to it).
//
// Endpoints — all gated by requireAPIToken:
//
//	GET  /api/admin/health        — JSON identical to /admin/health
//	GET  /api/admin/macs          — list MAC rows
//	POST /api/admin/macs/grant    — {mac, days, label?}: extend or add
//	POST /api/admin/macs/revoke   — {mac}: delete from DB + firewall
//
// Returns JSON. 401 on missing/wrong token, 400 on bad input, 500 on DB
// errors. Every action lands in audit_log with actor "api:<label>".
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"router-billing/internal/config"
	"router-billing/internal/db"
	"router-billing/internal/models"
	"router-billing/internal/voucher"
)

// requireAPITokenWrite extracts Authorization: Bearer <token>, verifies it
// against config.api_tokens, and blocks read-only tokens from non-GET
// methods. Used for endpoints that mutate state.
func (a *App) requireAPITokenWrite(h func(w http.ResponseWriter, r *http.Request, actor string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := a.matchBearerOrUnauthorized(w, r)
		if tok == nil {
			return
		}
		if r.Method != http.MethodGet && tok.ReadOnly {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "token is read-only"})
			return
		}
		h(w, r, "api:"+tokenLabel(tok))
	}
}

// requireAPITokenRead accepts any token (read-only or full) for read paths.
// Today this is functionally identical to requireAPITokenWrite for GET — it
// exists so the route-table reads as documentation for which endpoint needs
// which scope.
func (a *App) requireAPITokenRead(h func(w http.ResponseWriter, r *http.Request, actor string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := a.matchBearerOrUnauthorized(w, r)
		if tok == nil {
			return
		}
		h(w, r, "api:"+tokenLabel(tok))
	}
}

// matchBearerOrUnauthorized parses the Authorization header, looks up the
// token, applies the per-token rate limit (if configured), and writes a
// 401 / 429 response on failure. Returns nil iff the response is already
// written.
func (a *App) matchBearerOrUnauthorized(w http.ResponseWriter, r *http.Request) *config.APIToken {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing Bearer token"})
		return nil
	}
	tok := a.Cfg.MatchAPITokenFull(strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer ")))
	if tok == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return nil
	}
	if tok.RateLimitPerMin > 0 {
		if !a.apiTokenAllow(tokenLabel(tok), tok.RateLimitPerMin) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return nil
		}
	}
	return tok
}

// apiTokenAllow consults (or lazily creates) the per-token rate limiter
// and returns whether this request is within budget. Each token gets its
// own counter keyed by label, with a 60-second rolling window.
func (a *App) apiTokenAllow(label string, perMin int) bool {
	a.apiTokenLimiterMu.Lock()
	defer a.apiTokenLimiterMu.Unlock()
	if a.apiTokenLimiter == nil {
		a.apiTokenLimiter = map[string]*rateLimiter{}
	}
	rl, ok := a.apiTokenLimiter[label]
	if !ok || rl.max != perMin {
		// First request OR config change since boot — install a fresh
		// limiter with the configured budget.
		rl = newRateLimiter(perMin, time.Minute)
		a.apiTokenLimiter[label] = rl
	}
	return rl.allow(label)
}

func tokenLabel(t *config.APIToken) string {
	if t.Label == "" {
		return "unnamed-token"
	}
	return t.Label
}

// GET /api/admin/health
func (a *App) handleAPIHealth(w http.ResponseWriter, r *http.Request, _ string) {
	a.handleAdminHealth(w, r) // already-built admin handler; we just bypassed cookie auth
}

// GET /api/admin/macs
// GET /api/admin/macs?q=&status=&user_id=&limit=
//
// Pre-v0.40 returned every MAC unfiltered (which could be 10k+ on a
// long-running install — way too much over a slow link). Now accepts:
//
//	q       — substring match on MAC/label (via existing SearchMACs)
//	status  — active|expired|blocked (exact match)
//	user_id — int; returns only MACs owned by that user
//	limit   — int, default 200, cap 1000
//
// When user_id is set it routes through the indexed ListMACsForUser path;
// q/status post-filter the result in Go since the row count is bounded
// by what one user owns (a few dozen at most). Without user_id, the
// substring/status filter goes through SearchMACs.
//
// Empty filters → 200 most recent MACs (preserves the original semantic
// for callers that don't pass any params, just with a sane row cap).
func (a *App) handleAPIMACList(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	limit := 200
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	statusFilter := strings.TrimSpace(q.Get("status"))
	qSearch := strings.TrimSpace(q.Get("q"))
	userIDStr := strings.TrimSpace(q.Get("user_id"))

	var macs []models.MAC
	var err error
	if userIDStr != "" {
		n, perr := strconv.ParseInt(userIDStr, 10, 64)
		if perr != nil || n <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad user_id"})
			return
		}
		macs, err = a.DB.ListMACsForUser(r.Context(), n)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		// Post-filter on q + status in memory — row count is bounded by
		// one user's devices, typically << 100.
		if qSearch != "" || statusFilter != "" {
			filtered := macs[:0]
			for _, m := range macs {
				if statusFilter != "" && string(m.Status) != statusFilter {
					continue
				}
				if qSearch != "" && !strings.Contains(m.Mac, qSearch) && !strings.Contains(m.Label, qSearch) {
					continue
				}
				filtered = append(filtered, m)
			}
			macs = filtered
		}
		if len(macs) > limit {
			macs = macs[:limit]
		}
	} else if qSearch != "" || statusFilter != "" {
		macs, err = a.DB.SearchMACs(r.Context(), qSearch, statusFilter, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	} else {
		// No filters — limit the unfiltered list too, since the legacy
		// no-cap behavior could ship 10k+ rows on busy installs.
		all, lerr := a.DB.ListMACs(r.Context())
		if lerr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": lerr.Error()})
			return
		}
		if len(all) > limit {
			all = all[:limit]
		}
		macs = all
	}
	writeJSON(w, http.StatusOK, map[string]any{"macs": macs, "count": len(macs)})
}

// GET /api/admin/version   Bearer <any-token>
//
// Minimal endpoint returning just the running version + uptime + build
// info. Faster than /api/admin/health which runs DB queries; useful for
// status-page widgets that poll every few seconds.
//
//	-> 200 { "version": "v0.81", "uptime_seconds": 12345,
//	         "wechat_enabled": true, "alipay_enabled": true }
//
// Read-only token acceptable.
func (a *App) handleAPIVersion(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        a.Version,
		"uptime_seconds": int(time.Since(a.StartAt).Seconds()),
		"wechat_enabled": a.WeChat != nil,
		"alipay_enabled": a.Alipay != nil,
	})
}

// GET /api/admin/plans/sales?days=N   Bearer <any-token>
//
// Per-plan paid-revenue + order count over the last N days. For ops
// dashboards charting "which plan is selling best?" without HTML scrape.
//
//	-> 200 { "plans": [ {"plan":"month","orders":42,"revenue_cents":21000},
//	                    ... ],
//	         "days":  30 }
//
// days defaults to 30, max 3650. Read-only token acceptable.
func (a *App) handleAPIPlansSales(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	days := 30
	if s := r.URL.Query().Get("days"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 3650 {
			days = n
		}
	}
	sales, err := a.DB.PlanSalesSince(r.Context(), days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type apiPlanSale struct {
		Plan         string `json:"plan"`
		Orders       int    `json:"orders"`
		RevenueCents int    `json:"revenue_cents"`
	}
	out := make([]apiPlanSale, 0, len(sales))
	for _, p := range sales {
		out = append(out, apiPlanSale{
			Plan: p.Plan, Orders: p.OrdersCount, RevenueCents: p.TotalCents,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plans": out,
		"days":  days,
	})
}

// POST /api/admin/macs/label   Bearer <write-token>
//
//	{ "mac": "AA:BB:CC:DD:EE:FF", "label": "office tablet" }
//	-> 200 { "status": "ok", "mac": "..." }
//	   400 missing/malformed; 404 not found
//
// Programmatic admin counterpart to the user-side /user/macs/label form.
// Useful for bulk-rename automation after a customer-ID migration without
// touching expiry. Label trimmed + capped 64 chars.
//
// Audit: mac_label target=mac detail="label=<value> via=api ip=...".
func (a *App) handleAPIMACLabel(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		MAC   string `json:"mac"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	normalized, ok := models.NormalizeMAC(req.MAC)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	m, err := a.DB.GetMAC(r.Context(), normalized)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if m == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mac not found"})
		return
	}
	label := strings.TrimSpace(req.Label)
	if len(label) > 64 {
		label = label[:64]
	}
	if err := a.DB.SetMACLabel(r.Context(), normalized, label); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "mac_label", normalized,
		"label="+label+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"mac":    normalized,
	})
}

// POST /api/admin/macs/notes   Bearer <write-token>
//
//	{ "mac": "AA:BB:CC:DD:EE:FF", "notes": "support context" }
//	-> 200 { "status": "ok", "mac": "..." }
//	   400 if mac missing/malformed
//	   404 if mac not found
//
// Programmatic equivalent of v0.82's UI notes form. Useful for sync from
// an external CRM or ticketing system: "the customer's ticket says X,
// stamp it onto the MAC record."
//
// Unlike the import path (v0.83) which preserves existing notes on empty
// input, this explicit endpoint OVERWRITES — including to empty string,
// which is how callers clear a stale note. The semantic difference is
// intentional: the import endpoint is "bulk upsert, don't clobber
// context"; this endpoint is "set the field to exactly this value."
func (a *App) handleAPIMACNotes(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		MAC   string `json:"mac"`
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	normalized, ok := models.NormalizeMAC(req.MAC)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	m, err := a.DB.GetMAC(r.Context(), normalized)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if m == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mac not found"})
		return
	}
	notes := strings.TrimSpace(req.Notes)
	if len(notes) > 1000 {
		notes = notes[:1000]
	}
	if err := a.DB.SetMACNotes(r.Context(), normalized, notes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "mac_notes", normalized,
		"len="+strconv.Itoa(len(notes))+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"mac":    normalized,
	})
}

// GET /api/admin/macs/get?mac=...   Bearer <any-token>
//
// Programmatic equivalent of v0.48's UI MAC detail page. Returns the
// MAC row, current sighting (or null), the user that owns it (or null),
// up to 50 recent orders, and the audit timeline targeting this MAC.
//
//	-> 200 { "mac": {...}, "owner": {...}|null, "sighting": {...}|null,
//	         "orders": [...], "audit": [...] }
//	   400 if mac param missing or malformed
//	   404 if mac not found in macs table
//
// Read-only token acceptable — same posture as v0.47 order/get.
// Anti-leak: owner field is stripped of password_hash / totp_secret /
// totp_pending.
func (a *App) handleAPIMACGet(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	macStr := strings.TrimSpace(r.URL.Query().Get("mac"))
	if macStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mac required"})
		return
	}
	normalized, ok := models.NormalizeMAC(macStr)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	m, err := a.DB.GetMAC(r.Context(), normalized)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if m == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mac not found"})
		return
	}
	// Owner — strip auth material.
	type apiOwner struct {
		ID          int64     `json:"id"`
		Phone       string    `json:"phone"`
		Suspended   bool      `json:"suspended"`
		TOTPEnabled bool      `json:"totp_enabled"`
		CreatedAt   time.Time `json:"created_at"`
	}
	var ownerOut *apiOwner
	if m.UserID != nil {
		u, _ := a.DB.GetUser(r.Context(), *m.UserID)
		if u != nil {
			ownerOut = &apiOwner{
				ID:          u.ID,
				Phone:       u.Phone,
				Suspended:   u.Suspended,
				TOTPEnabled: u.TOTPSecret != "",
				CreatedAt:   u.CreatedAt,
			}
		}
	}
	sighting, _ := a.DB.GetSightingForMAC(r.Context(), normalized)
	orders, _ := a.DB.SearchOrders(r.Context(), normalized, "", 50)
	timeline, _ := a.DB.SearchAudit(r.Context(), db.AuditFilter{
		Target: normalized,
		Limit:  200,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"mac":      m,
		"owner":    ownerOut,
		"sighting": sighting,
		"orders":   orders,
		"audit":    timeline,
	})
}

// GET /api/admin/sessions?kind=admin|user   Bearer <any-token>
//
// Programmatic mirror of /admin/sessions. Returns active session rows
// for monitoring (e.g. alert if admin session count > expected, or
// chart user concurrent-session trends).
//
//	-> 200 { "sessions": [ {kind, subject, user_id, expires_at}, ... ],
//	         "count": N }
//
// Token fields are NEVER returned — leaking a session token would
// effectively give the holder all the auth those sessions have.
// kind filter: "admin" or "user" or empty (both).
//
// Read-only token acceptable.
func (a *App) handleAPISessions(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	kindFilter := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kindFilter != "" && kindFilter != "admin" && kindFilter != "user" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind must be admin or user"})
		return
	}
	all, err := a.DB.ListActiveSessions(r.Context(), 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Deliberately no Token / IsCurrent fields — leaking a session token
	// would effectively hand the holder authentication.
	type apiSession struct {
		Kind      string    `json:"kind"`
		Subject   string    `json:"subject,omitempty"`
		UserID    *int64    `json:"user_id,omitempty"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	out := make([]apiSession, 0, len(all))
	for _, s := range all {
		if kindFilter != "" && s.Kind != kindFilter {
			continue
		}
		out = append(out, apiSession{
			Kind: s.Kind, Subject: s.Subject, UserID: s.UserID,
			ExpiresAt: s.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": out,
		"count":    len(out),
	})
}

// GET /api/admin/audit/totals?since=YYYY-MM-DD&until=YYYY-MM-DD   Bearer <any-token>
//
// Returns action-frequency counts over the date range. Useful for ops
// dashboards charting "grants this week vs last week" or for compliance
// reports needing "X logins, Y grants, Z revokes during this quarter."
//
//	-> 200 { "totals": [ {"action": "grant", "count": 42}, ... ],
//	         "total":  N }
//
// `total` is the sum across all actions (so the caller doesn't have to
// add them up again). Read-only token acceptable.
func (a *App) handleAPIAuditTotals(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	q := r.URL.Query()
	totals, err := a.DB.CountAuditActionsByDate(r.Context(),
		strings.TrimSpace(q.Get("since")),
		strings.TrimSpace(q.Get("until")))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type apiTotal struct {
		Action string `json:"action"`
		Count  int    `json:"count"`
	}
	out := make([]apiTotal, 0, len(totals))
	sum := 0
	for _, t := range totals {
		out = append(out, apiTotal{Action: t.Action, Count: t.Count})
		sum += t.Count
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totals": out,
		"total":  sum,
	})
}

// GET /api/admin/audit/distinct?field=actor|action   Bearer <any-token>
//
// Returns the distinct set of audit_log.<field> values, sorted, for
// populating autocomplete UI in custom dashboards. Single endpoint
// keeps the API surface tidy; `field` is required and rejected if
// not in the allowlist.
//
//	-> 200 { "values": ["admin:bob", "admin:alice", ...] }
//	   400 if field is missing or unknown
//
// Read-only token acceptable.
func (a *App) handleAPIAuditDistinct(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	field := strings.TrimSpace(r.URL.Query().Get("field"))
	var values []string
	var err error
	switch field {
	case "actor":
		values, err = a.DB.DistinctAuditActors(r.Context())
	case "action":
		values, err = a.DB.DistinctAuditActions(r.Context())
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "field must be actor or action"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if values == nil {
		values = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"values": values})
}

// GET /api/admin/sightings?since_hours=24   Bearer <any-token>
//
// Programmatic access to the device_sightings table. Useful for ops
// automation that wants to inventory devices currently on the paid SSID:
// "give me everyone seen in the last hour and cross-check against
// active MACs to detect drift."
//
//	-> 200 { "sightings": [ {mac, last_ip, hostname, first_seen,
//	                         last_seen}, ... ], "count": N }
//
// since_hours defaults to 24, max 720 (30 days). Read-only token
// acceptable — no auth material in the payload.
func (a *App) handleAPISightings(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	hours := 24
	if s := r.URL.Query().Get("since_hours"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 720 {
			hours = n
		}
	}
	sightings, err := a.DB.ListRecentSightings(r.Context(), time.Duration(hours)*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sightings": sightings,
		"count":     len(sightings),
	})
}

// GET /api/admin/dashboard   Bearer <any-token>
//
// Programmatic equivalent of the /admin/dashboard panels. Returns the
// snapshot used to render the dash plus the attention counters. Useful
// for ops scripts that want to chart trends without scraping HTML.
//
//	-> 200 {
//	     "snapshot": { today_revenue_cents, today_paid_orders,
//	                   today_new_users, today_new_macs,
//	                   week7_revenue_cents, week7_paid_orders,
//	                   month30_revenue_cents, month30_paid_orders,
//	                   month30_new_users, prev_month30_revenue_cents,
//	                   prev_month30_paid_orders, prev_month30_new_users,
//	                   active_sessions },
//	     "attention": { expiring_soon, stale_pending, suspended_users,
//	                    failed_today, sms_failures_24h,
//	                    webhook_failures_24h }
//	   }
//
// Read-only token acceptable — payload contains aggregate stats only,
// no user-identifying data.
func (a *App) handleAPIDashboard(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	snap, _ := a.DB.DashboardSnapshot(r.Context())
	att, _ := a.DB.Attention(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"snapshot": map[string]int{
			"today_revenue_cents":        snap.TodayRevenueCents,
			"today_paid_orders":          snap.TodayPaidOrders,
			"today_new_users":            snap.TodayNewUsers,
			"today_new_macs":             snap.TodayNewMACs,
			"week7_revenue_cents":        snap.Week7RevenueCents,
			"week7_paid_orders":          snap.Week7PaidOrders,
			"month30_revenue_cents":      snap.Month30RevenueCents,
			"month30_paid_orders":        snap.Month30PaidOrders,
			"month30_new_users":          snap.Month30NewUsers,
			"prev_month30_revenue_cents": snap.PrevMonth30RevenueCents,
			"prev_month30_paid_orders":   snap.PrevMonth30PaidOrders,
			"prev_month30_new_users":     snap.PrevMonth30NewUsers,
			"active_sessions":            snap.ActiveSessions,
		},
		"attention": map[string]int{
			"expiring_soon":        att.ExpiringSoon,
			"stale_pending":        att.StalePending,
			"suspended_users":      att.SuspendedUsers,
			"failed_today":         att.FailedToday,
			"sms_failures_24h":     att.SMSFailures24h,
			"webhook_failures_24h": att.WebhookFailures24h,
		},
	})
}

// POST /api/admin/users/suspend   Bearer <write-token>
//
//	{ "user_id": 42, "suspend": true }
//	-> 200 { "status": "ok", "user_id": 42, "suspended": true }
//	   400 if user_id missing
//	   404 if user not found
//
// Programmatic equivalent of v0.5's /admin/users/suspend UI button.
// Suspended users keep their existing MAC time but can't log in
// (sessions are killed and login is denied with a clear error message).
// Useful for anti-abuse automation that wants to lock accounts on a
// fraud signal from elsewhere.
//
// Audit row: `user_suspend` (or `user_unsuspend`) target=user_id
// detail="via=api ip=...".
func (a *App) handleAPIUserSuspend(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		UserID  int64 `json:"user_id"`
		Suspend bool  `json:"suspend"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	if req.UserID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id required"})
		return
	}
	user, err := a.DB.GetUser(r.Context(), req.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if err := a.DB.SuspendUser(r.Context(), req.UserID, req.Suspend); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// SuspendUser sets suspended=1; we also need to evict their sessions
	// so a currently-logged-in suspended user can't keep using the system
	// on a stale cookie. Match UI semantics.
	if req.Suspend {
		_, _ = a.DB.DeleteSessionsByUserID(r.Context(), req.UserID)
	}
	action := "user_unsuspend"
	if req.Suspend {
		action = "user_suspend"
	}
	a.DB.Audit(r.Context(), actor, action, strconv.FormatInt(req.UserID, 10),
		"via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"user_id":   req.UserID,
		"suspended": req.Suspend,
	})
}

// POST /api/admin/users/notify-expiry   Bearer <write-token>
//
//	{ "user_id": 42, "on": true }
//	-> 200 { "status": "ok", "user_id": 42, "notify_expiry": true }
//	   404 if user not found
//
// Flips the per-user opt-out for the expiry-reminder SMS sweep. Useful
// for support workflows like "this customer asked us to stop texting
// them" or for bulk re-enable scripts after a deliverability issue.
//
// Audit row: `user_notify_pref` with target=user_id detail="on=Y via=api ip=...".
func (a *App) handleAPIUserNotifyExpiry(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		UserID int64 `json:"user_id"`
		On     bool  `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	if req.UserID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id required"})
		return
	}
	user, err := a.DB.GetUser(r.Context(), req.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if err := a.DB.SetUserNotifyExpiry(r.Context(), req.UserID, req.On); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	onStr := "0"
	if req.On {
		onStr = "1"
	}
	a.DB.Audit(r.Context(), actor, "user_notify_pref", strconv.FormatInt(req.UserID, 10),
		"on="+onStr+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"user_id":       req.UserID,
		"notify_expiry": req.On,
	})
}

// apiUserSummary is the shape returned by /api/admin/users — deliberately a
// subset of models.User without password_hash / totp_secret / totp_pending
// so a leaked monitoring token can't exfiltrate auth material.
type apiUserSummary struct {
	ID          int64     `json:"id"`
	Phone       string    `json:"phone"`
	Suspended   bool      `json:"suspended"`
	TOTPEnabled bool      `json:"totp_enabled"`
	MACs        int       `json:"macs"`
	CreatedAt   time.Time `json:"created_at"`
}

// apiVoucher mirrors models.Voucher minus the raw code — we deliberately
// truncate to a prefix in the JSON so a leaked monitoring token can't
// harvest unredeemed codes for redemption. Same anti-leak posture as
// /api/admin/users hiding password hashes.
type apiVoucher struct {
	ID             int64      `json:"id"`
	CodePrefix     string     `json:"code_prefix"` // first 4 chars + "…"
	Days           int        `json:"days"`
	Label          string     `json:"label,omitempty"`
	Batch          string     `json:"batch,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RedeemedAt     *time.Time `json:"redeemed_at,omitempty"`
	RedeemedByMac  string     `json:"redeemed_by_mac,omitempty"`
	RedeemedUserID *int64     `json:"redeemed_user_id,omitempty"`
	Revoked        bool       `json:"revoked"`
	CreatedAt      time.Time  `json:"created_at"`
}

// GET /api/admin/vouchers?batch=&limit=
//
// Returns vouchers (default 200, max 1000). Optional `batch` filter mirrors
// the /admin/vouchers UI. Codes are returned as 4-char prefixes only — the
// usable plaintext stays out of the JSON since a token leak shouldn't enable
// free MAC time.
func (a *App) handleAPIVoucherList(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	limit := 200
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	vouchers, err := a.DB.ListVouchers(r.Context(), q.Get("batch"), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]apiVoucher, 0, len(vouchers))
	for _, v := range vouchers {
		out = append(out, apiVoucher{
			ID:             v.ID,
			CodePrefix:     voucherCodePrefix(v.Code),
			Days:           v.Days,
			Label:          v.Label,
			Batch:          v.Batch,
			ExpiresAt:      v.ExpiresAt,
			RedeemedAt:     v.RedeemedAt,
			RedeemedByMac:  v.RedeemedByMac,
			RedeemedUserID: v.RedeemedUserID,
			Revoked:        v.Revoked,
			CreatedAt:      v.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"vouchers": out})
}

// voucherCodePrefix is the truncation used in the JSON response — 4 chars +
// "…". Anything shorter (defensive only — real codes are 12 chars) returns
// the code as-is.
func voucherCodePrefix(code string) string {
	if len(code) <= 4 {
		return code
	}
	return code[:4] + "…"
}

// apiAuditEntry is the JSON shape returned by /api/admin/audit. Mirrors
// db.AuditEntry but with explicit JSON tags so the API contract is stable
// even if the DB type changes.
type apiAuditEntry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// GET /api/admin/audit?actor=&action=&target=&since=&until=&limit=
//
// Read-only view of the audit_log table. Same filter knobs as the admin
// /admin/audit page. Default limit 200, max 1000.
func (a *App) handleAPIAuditList(w http.ResponseWriter, r *http.Request, _ string) {
	q := r.URL.Query()
	limit := 200
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	entries, err := a.DB.SearchAudit(r.Context(), db.AuditFilter{
		Actor:  q.Get("actor"),
		Action: q.Get("action"),
		Target: q.Get("target"),
		Q:      q.Get("q"),
		Since:  q.Get("since"),
		Until:  q.Get("until"),
		Limit:  limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]apiAuditEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, apiAuditEntry{
			ID: e.ID, At: e.At, Actor: e.Actor, Action: e.Action,
			Target: e.Target, Detail: e.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// GET /api/admin/orders?limit=&status=
//
// Returns the most-recent orders (default 100, max 500). Optional `status`
// filter (pending|paid|failed|expired) does in-memory filtering since
// ListOrders doesn't support it directly — fine for the small datasets the
// monitoring use-case actually queries.
//
// Same shape as the CSV export (`/admin/export/orders.csv`), just JSON.
func (a *App) handleAPIOrderList(w http.ResponseWriter, r *http.Request, _ string) {
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	orders, err := a.DB.ListOrders(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filtered := orders[:0]
		for _, o := range orders {
			if string(o.Status) == status {
				filtered = append(filtered, o)
			}
		}
		orders = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": orders})
}

// GET /api/admin/users?q=&limit=&suspended=1&totp=1
//
// Returns up to `limit` users (default 200, max 500). Filters:
//   - q          phone substring (LIKE %q%)
//   - suspended  "1" / "0" → exact match on the suspended flag
//   - totp       "1" → only users with TOTP enabled
//     "0" → only users WITHOUT TOTP (helpful for "who should we
//     nudge to enable 2FA?" reports)
//
// Filters compose — `?q=138&suspended=0&totp=0` returns "active users
// with a 138-prefix phone who haven't enabled 2FA yet."
//
// Same response shape as v0.40: { users: [...], count: N }.
func (a *App) handleAPIUserList(w http.ResponseWriter, r *http.Request, _ string) {
	qstr := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := 200
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	users, err := a.DB.SearchUsers(r.Context(), qstr, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Post-filter on suspended / totp in-memory since the row count is
	// bounded by `limit` (≤500). Adding two more SQL branches for one-off
	// filters would be more bookkeeping than benefit.
	q := r.URL.Query()
	suspendedFilter := q.Get("suspended")
	totpFilter := q.Get("totp")
	if suspendedFilter != "" || totpFilter != "" {
		filtered := users[:0]
		for _, u := range users {
			if suspendedFilter == "1" && !u.Suspended {
				continue
			}
			if suspendedFilter == "0" && u.Suspended {
				continue
			}
			if totpFilter == "1" && u.TOTPSecret == "" {
				continue
			}
			if totpFilter == "0" && u.TOTPSecret != "" {
				continue
			}
			filtered = append(filtered, u)
		}
		users = filtered
	}

	macCount := map[int64]int{}
	if macs, _ := a.DB.ListMACs(r.Context()); macs != nil {
		for _, m := range macs {
			if m.UserID != nil {
				macCount[*m.UserID]++
			}
		}
	}
	out := make([]apiUserSummary, 0, len(users))
	for _, u := range users {
		out = append(out, apiUserSummary{
			ID:          u.ID,
			Phone:       u.Phone,
			Suspended:   u.Suspended,
			TOTPEnabled: u.TOTPSecret != "",
			MACs:        macCount[u.ID],
			CreatedAt:   u.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "count": len(out)})
}

type apiGrantReq struct {
	MAC   string `json:"mac"`
	Days  int    `json:"days"`
	Label string `json:"label"`
}

// POST /api/admin/macs/grant
func (a *App) handleAPIMACGrant(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiGrantReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	mac, ok := models.NormalizeMAC(req.MAC)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	if req.Days <= 0 || req.Days > 3650 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "days must be in 1..3650"})
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = actor // default attribution
	}
	m, err := a.MACSvc.Extend(r.Context(), mac, label, req.Days, nil)
	if err != nil {
		log.Printf("api grant %s: %v", mac, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "grant", mac, "days="+itoaSmall(req.Days)+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"mac": m})
}

type apiRevokeReq struct {
	MAC string `json:"mac"`
}

type apiSMSReq struct {
	Phone   string `json:"phone"`
	Message string `json:"message"`
}

type apiMACImportRow struct {
	MAC   string `json:"mac"`
	Days  int    `json:"days,omitempty"`
	Label string `json:"label,omitempty"`
	Notes string `json:"notes,omitempty"` // v0.83 — capped 1000 chars
}

type apiMACImportReq struct {
	DefaultDays int               `json:"default_days,omitempty"`
	MACs        []apiMACImportRow `json:"macs"`
}

// POST /api/admin/macs/import  Bearer <write-token>
//
// Bulk grant. Mirrors the /admin/macs/import textarea but accepts JSON
// for scripting. Each row missing `days` uses `default_days` (or 30 if
// that's also missing).
//
//	{ "default_days": 365,
//	  "macs": [ {"mac": "AA:BB:CC:DD:EE:FF", "days": 30, "label": "phone"},
//	            {"mac": "aa-bb-cc-dd-ee-01", "label": "tv"} ] }
//
// Returns the added/failed counts. Each grant audits as the existing
// "grant" action so the trail matches the UI path.
func (a *App) handleAPIMACImport(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiMACImportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	if len(req.MACs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "macs required"})
		return
	}
	if len(req.MACs) > 1000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many rows (max 1000)"})
		return
	}
	defaultDays := req.DefaultDays
	if defaultDays <= 0 {
		defaultDays = 30
	}
	added, failed := 0, 0
	for _, row := range req.MACs {
		mac, ok := models.NormalizeMAC(row.MAC)
		if !ok {
			failed++
			continue
		}
		days := row.Days
		if days <= 0 {
			days = defaultDays
		}
		if _, err := a.MACSvc.Extend(r.Context(), mac, strings.TrimSpace(row.Label), days, nil); err != nil {
			log.Printf("api mac import %s: %v", mac, err)
			failed++
			continue
		}
		// v0.83: optional notes (max 1000 chars). Empty string = leave
		// existing notes untouched (would overwrite to empty otherwise
		// on re-import, which is a footgun).
		if notes := strings.TrimSpace(row.Notes); notes != "" {
			if len(notes) > 1000 {
				notes = notes[:1000]
			}
			if err := a.DB.SetMACNotes(r.Context(), mac, notes); err != nil {
				log.Printf("api mac import notes %s: %v", mac, err)
			}
		}
		a.DB.Audit(r.Context(), actor, "grant", mac,
			"days="+strconv.Itoa(days)+" via=api ip="+clientIP(r))
		added++
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "failed": failed})
}

type apiRefundReq struct {
	OrderNo string `json:"order_no"`
	Reason  string `json:"reason,omitempty"`
}

// POST /api/admin/orders/refund  Bearer <write-token>
//
//	{ "order_no": "...", "reason": "..." }
//
// Programmatic refund — same atomic DB transition as the UI button
// (MarkOrderRefunded rolls back the MAC's expires_at + sets status to
// "refunded"). Useful for chargeback automation tied to webhook
// handlers on the gateway side. Write-scope only.
//
// Returns the post-state MAC summary so the caller can confirm the
// expiry rollback landed.
func (a *App) handleAPIOrderRefund(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiRefundReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	orderNo := strings.TrimSpace(req.OrderNo)
	if orderNo == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "order_no required"})
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > 200 {
		reason = reason[:200]
	}
	mac, err := a.DB.MarkOrderRefunded(r.Context(), orderNo, reason)
	if err != nil {
		log.Printf("api refund %s: %v", orderNo, err)
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "only paid"):
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "order_refunded", orderNo,
		"reason="+reason+" via=api ip="+clientIP(r))
	if mac != nil && mac.Status == models.MACExpired {
		go func() {
			ctx := context.Background()
			if err := a.MACSvc.Resync(ctx); err != nil {
				log.Printf("api refund post-resync: %v", err)
			}
		}()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "refunded",
		"mac":    mac,
	})
}

// POST /api/admin/sms/send  {phone, message}
//
// Programmatically send an SMS through whatever provider is wired. Useful
// for monitoring scripts that want to text the operator when something
// urgent fires (DB-corruption alert, repeated failed admin logins, etc.).
//
// Requires a non-readonly Bearer token. Same validation as the admin UI:
// phone must match models.ValidPhone, message capped at 500 chars. Writes
// the same audit entries (sms_test on success, sms_test_failed otherwise).
func (a *App) handleAPISMSSend(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	if a.SMS == nil || !a.SMS.Available() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sms provider not configured"})
		return
	}
	var req apiSMSReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	phone := strings.TrimSpace(req.Phone)
	msg := strings.TrimSpace(req.Message)
	if !models.ValidPhone(phone) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid phone"})
		return
	}
	if msg == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message is required"})
		return
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	if err := a.SendSMS(r.Context(), phone, msg); err != nil {
		log.Printf("api sms %s: %v", phone, err)
		a.DB.Audit(r.Context(), actor, "sms_test_failed", phone,
			"provider="+a.SMS.Name()+" err="+err.Error()+" ip="+clientIP(r))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "sms_test", phone,
		"provider="+a.SMS.Name()+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"status": "sent", "provider": a.SMS.Name()})
}

// POST /api/admin/macs/revoke
func (a *App) handleAPIMACRevoke(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiRevokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	mac, ok := models.NormalizeMAC(req.MAC)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mac"})
		return
	}
	if err := a.MACSvc.Delete(r.Context(), mac); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "revoke", mac, "via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type apiVoucherGenReq struct {
	Count       int    `json:"count"`
	Days        int    `json:"days"`
	Batch       string `json:"batch,omitempty"`
	Label       string `json:"label,omitempty"`
	ExpiresDays int    `json:"expires_days,omitempty"`
}

// POST /api/admin/vouchers/generate  Bearer <write-token>
//
//	{ "count": 100, "days": 30, "batch": "promo-2026Q2",
//	  "label": "summer-promo", "expires_days": 180 }
//	-> 200 { "batch": "promo-2026Q2", "created": 100,
//	         "codes": ["AB12-CD34-EF56", ...] }
//
// Mirrors /admin/vouchers/generate but returns the freshly-minted codes in
// the JSON response (which is the whole point — the partner needs the
// plaintext to print / sell them). Codes are PRETTY-formatted (4-4-4 with
// dashes) so the response can be piped straight into a printer template
// without re-formatting.
//
// Limits: count is clamped to [1,1000] and days must be positive; expires_days
// is optional (omitted means "no expiry"). Batch defaults to a timestamp-based
// label if absent (same as the UI). Each generated code retries up to 3 times
// on the very unlikely 12-char collision.
//
// Audit: `voucher_batch` target=<batch> detail="count=N days=D via=api".
// Same shape as the UI generator so the trail looks consistent regardless of
// origin.
func (a *App) handleAPIVoucherGenerate(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiVoucherGenReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	if req.Count <= 0 || req.Count > 1000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "count must be 1..1000"})
		return
	}
	if req.Days <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "days must be > 0"})
		return
	}
	batch := strings.TrimSpace(req.Batch)
	if batch == "" {
		batch = "B" + time.Now().UTC().Format("20060102-150405")
	}
	var expires *time.Time
	if req.ExpiresDays > 0 {
		t := time.Now().UTC().AddDate(0, 0, req.ExpiresDays)
		expires = &t
	}

	codes := make([]string, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		// Up to 3 retries on collision (12-char alphabet collision is
		// effectively impossible at this scale, but the UI handler does
		// the same defensive retry).
		for try := 0; try < 3; try++ {
			code, err := voucher.New()
			if err != nil {
				log.Printf("api voucher gen: %v", err)
				break
			}
			if _, err := a.DB.CreateVoucher(r.Context(), code, req.Days, req.Label, batch, expires); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique") {
					continue
				}
				log.Printf("api voucher insert: %v", err)
				break
			}
			codes = append(codes, voucher.Pretty(code))
			break
		}
	}
	a.DB.Audit(r.Context(), actor, "voucher_batch", batch,
		"count="+strconv.Itoa(len(codes))+" days="+strconv.Itoa(req.Days)+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"batch":   batch,
		"created": len(codes),
		"codes":   codes,
	})
}

type apiVoucherBatchRevokeReq struct {
	Batch string `json:"batch"`
}

// POST /api/admin/vouchers/batch/revoke  Bearer <write-token>
//
//	{ "batch": "promo-2026Q2" }
//	-> 200 { "revoked": 42 }
//
// Paired with the v0.26 UI batch-revoke button. Mass-kills every still-usable
// voucher in `batch`; already-redeemed rows are intentionally untouched
// (revoking them would lie about real usage). Pass "" to revoke the unbatched
// bucket (same semantics as VoucherBatchStats's "(no batch)" row).
//
// Audit: `voucher_batch_revoke` with detail "count=N via=api ip=...".
func (a *App) handleAPIVoucherBatchRevoke(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiVoucherBatchRevokeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	batch := strings.TrimSpace(req.Batch)
	n, err := a.DB.RevokeVoucherBatch(r.Context(), batch)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	displayBatch := batch
	if displayBatch == "" {
		displayBatch = "(no batch)"
	}
	a.DB.Audit(r.Context(), actor, "voucher_batch_revoke", displayBatch,
		"count="+strconv.Itoa(n)+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

type apiUserGrantReq struct {
	UserID int64  `json:"user_id"`
	Days   int    `json:"days"`
	Label  string `json:"label,omitempty"`
}

// POST /api/admin/users/grant  Bearer <write-token>
//
//	{ "user_id": 42, "days": 30, "label": "support-extend" }
//	-> 200 { "user_id": 42, "macs_extended": 3,
//	         "macs": [ {"mac": "AA:BB:CC:DD:EE:01", "expires_at": "..."}, ... ] }
//
// Convenience endpoint: extends every MAC owned by user_id by `days`. Useful
// for support workflows ("customer called, lost their phone — give them
// 7 days on everything") and for partner integrations that track users
// by their own ID rather than per-device MAC.
//
// A user with zero MACs is NOT an error — returns 200 with macs_extended=0.
// Nonexistent user_id returns 404. Per-MAC failures (firewall sync, etc.)
// log but don't fail the whole batch; the response macs list is the set
// that actually got extended.
//
// Audit: one `grant` entry per MAC (matching the UI / /api/admin/macs/grant
// shape) so reviewers see the full fan-out, plus one `user_grant` summary
// row at the top with the total.
func (a *App) handleAPIUserGrant(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiUserGrantReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	if req.UserID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id required"})
		return
	}
	if req.Days <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "days must be > 0"})
		return
	}

	user, err := a.DB.GetUser(r.Context(), req.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	macs, err := a.DB.ListMACsForUser(r.Context(), req.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "user-grant"
	}

	type extendedMAC struct {
		MAC       string    `json:"mac"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	out := make([]extendedMAC, 0, len(macs))
	for i := range macs {
		extended, err := a.MACSvc.Extend(r.Context(), macs[i].Mac, label, req.Days, &req.UserID)
		if err != nil {
			log.Printf("api user grant %d mac=%s: %v", req.UserID, macs[i].Mac, err)
			continue
		}
		a.DB.Audit(r.Context(), actor, "grant", macs[i].Mac,
			"days="+strconv.Itoa(req.Days)+" via=api user_id="+strconv.FormatInt(req.UserID, 10)+" ip="+clientIP(r))
		out = append(out, extendedMAC{MAC: extended.Mac, ExpiresAt: extended.ExpiresAt})
	}
	// Summary audit row so reviewers don't have to grep for N grant rows
	// at the same timestamp to reconstruct the batch.
	a.DB.Audit(r.Context(), actor, "user_grant", strconv.FormatInt(req.UserID, 10),
		"days="+strconv.Itoa(req.Days)+" macs="+strconv.Itoa(len(out))+" via=api ip="+clientIP(r))

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":       req.UserID,
		"macs_extended": len(out),
		"macs":          out,
	})
}

// apiSMSLogEntry mirrors db.SMSLogEntry but with JSON-friendly field
// names + an ISO timestamp. Plaintext SMS messages are sensitive (they
// can contain temp passwords / reset codes / TOTP-recovery hints), so the
// message field is returned as-is — same trust model as the persistent
// DB which already holds it.
// GET /api/admin/orders/get?order_no=...   Bearer <any-token>
//
// Programmatic equivalent of v0.42's UI detail page. Returns the order
// row, the linked MAC's current state (or null if deleted), and the
// audit timeline targeting this order_no. Useful for support automation:
// "given an order number from a customer ticket, build a unified view
// without scraping the admin HTML."
//
//	-> 200 { "order": {...}, "mac": {...}|null, "audit": [...] }
//	   404 if order_no not found
//
// Read-only token acceptable — the response only carries the order's
// already-stored fields plus public audit text. No password_hash or other
// auth material is in the payload.
func (a *App) handleAPIOrderGet(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	orderNo := strings.TrimSpace(r.URL.Query().Get("order_no"))
	if orderNo == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "order_no required"})
		return
	}
	order, err := a.DB.GetOrder(r.Context(), orderNo)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if order == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	// MAC may be nil if the device was deleted after the order — still
	// return the order itself + timeline so support can investigate.
	mac, _ := a.DB.GetMAC(r.Context(), order.Mac)
	timeline, _ := a.DB.SearchAudit(r.Context(), db.AuditFilter{
		Target: orderNo,
		Limit:  200,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"order": order,
		"mac":   mac,
		"audit": timeline,
	})
}

type apiSMSLogEntry struct {
	ID       int64     `json:"id"`
	SentAt   time.Time `json:"sent_at"`
	Provider string    `json:"provider"`
	Phone    string    `json:"phone"`
	Message  string    `json:"message"`
	Success  bool      `json:"success"`
	ErrorMsg string    `json:"error_msg,omitempty"`
}

// GET /api/admin/sms/log?limit=N&phone=...&only_failed=1   Bearer <any-token>
//
// Programmatic access to the v0.43 sms_log table. Useful for monitoring
// scripts that want to alert on a streak of FAIL rows (e.g. Aliyun creds
// rotated and ops forgot to update them) without scraping the /admin
// HTML page.
//
//	-> 200 { "logs": [ {id, sent_at, provider, phone, message,
//	                   success, error_msg}, ... ], "count": N }
//
// Optional filters (v0.45):
//   - phone=13800...       exact match (support workflows)
//   - only_failed=1        success=0 only (monitoring alerts)
//
// limit defaults to 100, max 1000. Newest rows first.
func (a *App) handleAPISMSLog(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	q := r.URL.Query()
	limit := 100
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	logs, err := a.DB.SearchSMSLogs(r.Context(), db.SMSLogFilter{
		Phone:      strings.TrimSpace(q.Get("phone")),
		OnlyFailed: q.Get("only_failed") == "1",
		Since:      strings.TrimSpace(q.Get("since")),
		Until:      strings.TrimSpace(q.Get("until")),
		Limit:      limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]apiSMSLogEntry, 0, len(logs))
	for _, l := range logs {
		out = append(out, apiSMSLogEntry{
			ID: l.ID, SentAt: l.SentAt, Provider: l.Provider,
			Phone: l.Phone, Message: l.Message, Success: l.Success,
			ErrorMsg: l.ErrorMsg,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": out, "count": len(out)})
}

type apiWebhookDelivery struct {
	ID         int64     `json:"id"`
	SentAt     time.Time `json:"sent_at"`
	EventType  string    `json:"event_type"`
	MAC        string    `json:"mac,omitempty"`
	Attempt    int       `json:"attempt"`
	StatusCode int       `json:"status_code"`
	Success    bool      `json:"success"`
	DurationMs int64     `json:"duration_ms"`
	ErrorMsg   string    `json:"error_msg,omitempty"`
}

// GET /api/admin/webhook/log?limit=N&only_failed=1   Bearer <any-token>
//
// Programmatic access to the v0.49 webhook_deliveries table. Same posture
// as /api/admin/sms/log (v0.44/v0.45) — read-only token acceptable since
// the payload is the operator's own delivery state, not auth material.
//
// Common monitoring pattern: cron polls `?only_failed=1&limit=20`; alerts
// when any row's `sent_at` is within the last 5 minutes — webhook is
// presently broken and pages need a human.
//
//	-> 200 { "logs": [...], "count": N }
//
// limit defaults to 100, max 1000. Newest rows first.
func (a *App) handleAPIWebhookLog(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	q := r.URL.Query()
	limit := 100
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	logs, err := a.DB.SearchWebhookDeliveries(r.Context(), db.WebhookDeliveryFilter{
		EventType:  strings.TrimSpace(q.Get("event_type")),
		MAC:        strings.TrimSpace(q.Get("mac")),
		OnlyFailed: q.Get("only_failed") == "1",
		Since:      strings.TrimSpace(q.Get("since")),
		Until:      strings.TrimSpace(q.Get("until")),
		Limit:      limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]apiWebhookDelivery, 0, len(logs))
	for _, l := range logs {
		out = append(out, apiWebhookDelivery{
			ID: l.ID, SentAt: l.SentAt, EventType: l.EventType, MAC: l.MAC,
			Attempt: l.Attempt, StatusCode: l.StatusCode, Success: l.Success,
			DurationMs: l.DurationMs, ErrorMsg: l.ErrorMsg,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": out, "count": len(out)})
}

// POST /api/admin/maintenance/optimize-now  Bearer <write-token>
//
// API mirror of v0.39's UI button. Runs `PRAGMA optimize` (SQLite's
// recommended lightweight reanalysis). Sub-second on every realistic
// router-billing DB size.
//
//	-> 200 { "ms": N }
//
// VACUUM is intentionally NOT exposed via API for the same reason it's
// not on the UI button — it can hold a write lock for minutes. Operators
// who want disk reclaim run `sqlite3 ... "VACUUM"` manually during a
// quiet window.
//
// Audit: `optimize_now` detail="ms=N via=api ip=...".
func (a *App) handleAPIOptimizeNow(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	start := time.Now()
	if _, err := a.DB.Exec(r.Context(), "PRAGMA optimize"); err != nil {
		a.DB.Audit(r.Context(), actor, "optimize_now_failed", "",
			"err="+err.Error()+" via=api ip="+clientIP(r))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ms := time.Since(start).Milliseconds()
	a.DB.Audit(r.Context(), actor, "optimize_now", "",
		"ms="+strconv.FormatInt(ms, 10)+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ms": ms})
}

// POST /api/admin/maintenance/expire-now  Bearer <write-token>
//
// Programmatic mirror of v0.35's UI button. Runs ExpireDueMACs +
// MACSvc.Resync. Useful for deploy scripts that just rolled a config
// change and want to immediately reflect it in the firewall.
//
//	-> 200 { "expired": N }
//
// Audit: `expire_now` detail="expired=N via=api ip=...".
func (a *App) handleAPIExpireNow(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	expired, err := a.DB.ExpireDueMACs(r.Context())
	if err != nil {
		a.DB.Audit(r.Context(), actor, "expire_now_failed", "",
			"err="+err.Error()+" via=api ip="+clientIP(r))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if rerr := a.MACSvc.Resync(r.Context()); rerr != nil {
		log.Printf("api expire-now resync: %v", rerr)
	}
	a.DB.Audit(r.Context(), actor, "expire_now", "",
		"expired="+strconv.Itoa(len(expired))+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"expired": len(expired)})
}

// POST /api/admin/maintenance/audit-trim  Bearer <write-token>
//
// Programmatic mirror of v0.35's audit-trim UI button. Runs
// PurgeAuditLog(security.audit_log_keep). Useful when the cap has just
// been lowered in config and the operator wants the new retention applied
// without waiting for the 2-hour purgeLoop tick.
//
//	-> 200 { "kept": N }
//
// Audit: `audit_trim` detail="keep=N via=api ip=...".
func (a *App) handleAPIAuditTrim(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	keep := a.Cfg.Security.AuditLogRetention()
	if err := a.DB.PurgeAuditLog(r.Context(), keep); err != nil {
		a.DB.Audit(r.Context(), actor, "audit_trim_failed", "",
			"err="+err.Error()+" via=api ip="+clientIP(r))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "audit_trim", "",
		"keep="+strconv.Itoa(keep)+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"kept": keep})
}

// POST /api/admin/orders/cancel-stale   Bearer <write-token>
//
//	{ "older_than_hours": 24 }  // optional, default 24
//	-> 200 { "canceled": N }
//
// Bulk cleanup: flips every order with status='pending' AND created_at
// older than the cutoff to status='failed' in one SQL statement. Designed
// for hourly cron use to keep the pending backlog small.
//
// Bounds: older_than_hours in [1, 720] (1h .. 30d). 0 / unset → 24.
// Atomic single UPDATE so a payment that arrives mid-sweep can't lose:
// the status='pending' guard in the WHERE makes the race correct.
//
// Audit row: `orders_cancel_stale` with count + cutoff hours.
func (a *App) handleAPIOrderCancelStale(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		OlderThanHours int `json:"older_than_hours"`
	}
	// Tolerate empty body: cleanup cron may POST nothing and rely on the
	// 24h default.
	_ = json.NewDecoder(r.Body).Decode(&req)
	hours := req.OlderThanHours
	if hours <= 0 {
		hours = 24
	}
	if hours > 720 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "older_than_hours must be <= 720"})
		return
	}
	n, err := a.DB.CancelStalePendingOrders(r.Context(), time.Duration(hours)*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "orders_cancel_stale", "",
		"count="+strconv.Itoa(n)+" hours="+strconv.Itoa(hours)+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"canceled": n})
}

// POST /api/admin/orders/cancel   Bearer <write-token>
//
//	{ "order_no": "ORD-..." }
//	-> 200 { "status": "canceled", "order_no": "..." }
//	   404 if order_no not found
//	   409 if order isn't pending (already paid / failed / refunded)
//
// Cleanup automation for stuck pending orders: customer abandoned the
// payment, gateway never reported back, etc. Transitions pending → failed
// atomically (UPDATE WHERE status='pending'), so a race that just paid
// the order can't lose the payment. Audit row carries `via=api`.
func (a *App) handleAPIOrderCancel(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		OrderNo string `json:"order_no"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	orderNo := strings.TrimSpace(req.OrderNo)
	if orderNo == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "order_no required"})
		return
	}
	o, err := a.DB.CancelPendingOrder(r.Context(), orderNo)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
			return
		}
		// Status mismatch (not pending) → 409.
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "order_canceled", orderNo,
		"via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "canceled",
		"order_no": o.OrderNo,
	})
}

type apiAuditNoteReq struct {
	Note   string `json:"note"`
	Action string `json:"action,omitempty"` // default "manual_note"
	Target string `json:"target,omitempty"`
}

// POST /api/admin/audit/note   Bearer <write-token>
//
//	{ "note": "Refund issued via gateway dashboard",
//	  "action": "manual_note",       // optional; defaults to "manual_note"
//	  "target": "ORD-1234" }         // optional
//	-> 200 { "status": "ok" }
//
// Programmatic counterpart to the UI's /admin/audit/note form. Useful for
// webhook handlers or external automation that want to leave a trace
// in the existing audit table without inventing a new logging surface.
//
// Same length cap as the UI handler (1000 chars on note); empty note is
// rejected with 400 so a deploy script doesn't accidentally fill the
// table with whitespace.
//
// Custom `action` lets ops-tooling tag entries (e.g. "deploy",
// "config_reload") for later searchability while staying inside the
// audit_log table the existing UI already renders.
func (a *App) handleAPIAuditNote(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiAuditNoteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	note := strings.TrimSpace(req.Note)
	if note == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "note required"})
		return
	}
	if len(note) > 1000 {
		note = note[:1000]
	}
	action := strings.TrimSpace(req.Action)
	if action == "" {
		action = "manual_note"
	}
	// Defense: don't let API callers spoof system actions. Reserved
	// action prefixes used by background loops should stay distinct from
	// API-supplied free-text. The UI's "manual_note" stays the obvious
	// default + safe choice.
	if action != "manual_note" {
		// Validate custom action shape — same constraints as plan_key so
		// the audit search box can find rows. Loose-but-not-arbitrary.
		if !planKeyOK(action) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "action must match [A-Za-z0-9_-]{1,32} or be omitted",
				"field": "action",
			})
			return
		}
	}
	target := strings.TrimSpace(req.Target)
	if len(target) > 200 {
		target = target[:200]
	}
	a.DB.Audit(r.Context(), actor, action, target, note+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/admin/webhook/test  Bearer <write-token>
//
// Programmatic equivalent of the /admin/maintenance/test-webhook button.
// Enqueues a `type=test` event through the existing Notifier. Useful for
// CI / deploy-time integration checks ("after the new release rolls out,
// confirm our webhook handler still receives events").
//
//	-> 200 { "status": "enqueued", "url": "https://..." }
//	   503 if the webhook isn't configured.
//
// Delivery is async (the Notifier owns its queue); a 200 means the event
// was queued, not that the downstream service received it. The caller
// confirms receipt on their own side, OR watches the audit log for the
// retry/drop pattern.
func (a *App) handleAPIWebhookTest(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	if a.Notifier == nil || a.Cfg.Webhook.URL == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "webhook not configured"})
		return
	}
	a.Notifier.Send(notifyTestEvent(actor, clientIP(r)))
	a.DB.Audit(r.Context(), actor, "webhook_test", "",
		"url="+a.Cfg.Webhook.URL+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "enqueued",
		"url":    a.Cfg.Webhook.URL,
	})
}

type apiUserGrantByPhoneReq struct {
	Phone string `json:"phone"`
	Days  int    `json:"days"`
	Label string `json:"label,omitempty"`
}

// POST /api/admin/users/grant-by-phone  Bearer <write-token>
//
//	{ "phone": "13800120001", "days": 7, "label": "support-extend" }
//	-> 200 { "user_id": 42, "phone": "13800120001",
//	         "macs_extended": 3, "macs": [...] }
//
// Convenience over v0.29's /api/admin/users/grant: takes the phone number
// (which the support agent typed off a call) instead of requiring a
// pre-resolved user_id. Phone is validated through models.ValidPhone
// before lookup so a typo'd input becomes a clear 400 instead of a
// silent 404.
func (a *App) handleAPIUserGrantByPhone(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiUserGrantByPhoneReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	phone := strings.TrimSpace(req.Phone)
	if !models.ValidPhone(phone) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid phone"})
		return
	}
	if req.Days <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "days must be > 0"})
		return
	}
	user, err := a.DB.GetUserByPhone(r.Context(), phone)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no user for phone"})
		return
	}

	macs, err := a.DB.ListMACsForUser(r.Context(), user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "user-grant-by-phone"
	}

	type extendedMAC struct {
		MAC       string    `json:"mac"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	out := make([]extendedMAC, 0, len(macs))
	for i := range macs {
		extended, err := a.MACSvc.Extend(r.Context(), macs[i].Mac, label, req.Days, &user.ID)
		if err != nil {
			log.Printf("api user grant-by-phone %s mac=%s: %v", phone, macs[i].Mac, err)
			continue
		}
		a.DB.Audit(r.Context(), actor, "grant", macs[i].Mac,
			"days="+strconv.Itoa(req.Days)+" via=api phone="+phone+" ip="+clientIP(r))
		out = append(out, extendedMAC{MAC: extended.Mac, ExpiresAt: extended.ExpiresAt})
	}
	a.DB.Audit(r.Context(), actor, "user_grant", strconv.FormatInt(user.ID, 10),
		"days="+strconv.Itoa(req.Days)+" macs="+strconv.Itoa(len(out))+" via=api phone="+phone+" ip="+clientIP(r))

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":       user.ID,
		"phone":         user.Phone,
		"macs_extended": len(out),
		"macs":          out,
	})
}

type apiPlan struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Days       int    `json:"days"`
	PriceCents int    `json:"price_cents"`
	SortOrder  int    `json:"sort_order"`
	Enabled    bool   `json:"enabled"`
	// UpdatedAt zero-value omitted so config-file plans (no DB row) don't
	// echo a 0001-01-01 timestamp.
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// GET /api/admin/plans  Bearer <any-token>
//
// Returns the resolved plan list — same merge logic as the /admin/plans UI
// (DB overlay first, fall back to config-defined plans). Useful for
// integrations that build their own /buy flow and need to know what plans
// are currently offered.
func (a *App) handleAPIPlanList(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	plans := a.activePlans(r.Context())
	out := make([]apiPlan, 0, len(plans))
	for _, p := range plans {
		ap := apiPlan{
			Key: p.Key, Label: p.Label, Days: p.Days, PriceCents: p.PriceCents,
			SortOrder: p.SortOrder, Enabled: p.Enabled,
		}
		if !p.UpdatedAt.IsZero() {
			t := p.UpdatedAt
			ap.UpdatedAt = &t
		}
		out = append(out, ap)
	}
	writeJSON(w, http.StatusOK, map[string]any{"plans": out})
}

// POST /api/admin/plans/save  Bearer <write-token>
//
//	{ "key": "month", "label": "30 天", "days": 30,
//	  "price_cents": 500, "sort_order": 10, "enabled": true }
//	-> 200 { "status": "ok" }
//
// Same validation as the UI handler (see v0.31): planKeyOK + bounds on
// days/price/label. Validation failures return 400 with a `field` hint so
// the caller can show a useful message.
func (a *App) handleAPIPlanSave(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req apiPlan
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	key := strings.TrimSpace(req.Key)
	label := strings.TrimSpace(req.Label)
	if key == "" || label == "" || req.Days <= 0 || req.PriceCents <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key/label required, days+price_cents must be > 0"})
		return
	}
	if !planKeyOK(key) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad key (must match [A-Za-z0-9_-]{1,32})", "field": "key"})
		return
	}
	if len(label) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label too long (max 64)", "field": "label"})
		return
	}
	if req.Days > 3650 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "days too large (max 3650)", "field": "days"})
		return
	}
	if req.PriceCents > 10000000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "price_cents too large (max 10_000_000)", "field": "price_cents"})
		return
	}
	p := models.Plan{
		Key: key, Label: label, Days: req.Days, PriceCents: req.PriceCents,
		SortOrder: req.SortOrder, Enabled: req.Enabled,
	}
	if err := a.DB.UpsertPlan(r.Context(), p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "plan_save", key, "label="+label+" via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/admin/plans/delete  Bearer <write-token>
//
//	{ "key": "month" }  -> 200 { "status": "ok" }
//
// No-op on missing key (matches UI behavior). The config-defined fallback
// plan (if any) remains visible — UI semantics is "delete DB override; let
// the config base re-surface."
func (a *App) handleAPIPlanDelete(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "key required"})
		return
	}
	if err := a.DB.DeletePlan(r.Context(), key); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.DB.Audit(r.Context(), actor, "plan_delete", key, "via=api ip="+clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// itoaSmall: 1..3650 covers our range; no fmt dep needed.
func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
