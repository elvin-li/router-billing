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
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"router-billing/internal/config"
	"router-billing/internal/models"
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
// token, and writes a 401 response on miss. Returns nil iff the response is
// already written.
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
	return tok
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
func (a *App) handleAPIMACList(w http.ResponseWriter, r *http.Request, _ string) {
	macs, err := a.DB.ListMACs(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"macs": macs})
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
