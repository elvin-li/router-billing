package server

import (
	"net/http"
)

// GET /admin/api-tokens — read-only view of configured Bearer tokens.
//
// Shows label / readonly / rate-limit / token prefix (first 4 chars + "…")
// so admins can see what's wired up without exposing the secret. Adding
// or removing tokens still happens via config.yaml — the UI is intentional
// read-only so a compromised admin session can't silently extract them.
//
// "view full token" is NOT a feature. If an admin needs to rotate, they
// generate a new token (`--gen-api-token` CLI) and remove the old one
// from config — same as v0.0.
func (a *App) handleAdminAPITokens(w http.ResponseWriter, r *http.Request) {
	type row struct {
		Label    string
		Prefix   string
		ReadOnly bool
		PerMin   int
		Empty    bool // token field is empty (config typo)
	}
	rows := make([]row, 0, len(a.Cfg.APITokens))
	for _, t := range a.Cfg.APITokens {
		rows = append(rows, row{
			Label: func() string {
				if t.Label == "" {
					return "(unlabeled)"
				}
				return t.Label
			}(),
			Prefix: func() string {
				if t.Token == "" {
					return "(empty!)"
				}
				if len(t.Token) <= 4 {
					return t.Token
				}
				return t.Token[:4] + "…"
			}(),
			ReadOnly: t.ReadOnly,
			PerMin:   t.RateLimitPerMin,
			Empty:    t.Token == "",
		})
	}
	a.render(w, "admin_api_tokens.html", a.adminCtx(r, "api-tokens", map[string]any{
		"Tokens": rows,
	}))
}
