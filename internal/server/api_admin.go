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
	"encoding/json"
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

// GET /api/admin/users?q=&limit=
//
// Returns up to `limit` users (default 200, max 500). Phone substring filter
// via `q`. Same shape as the CSV export, just JSON.
func (a *App) handleAPIUserList(w http.ResponseWriter, r *http.Request, _ string) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := 200
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	users, err := a.DB.SearchUsers(r.Context(), q, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
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
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
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
