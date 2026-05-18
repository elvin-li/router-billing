package server

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"router-billing/internal/db"
	"router-billing/internal/models"
)

// GET /admin/health  → JSON
func (a *App) handleAdminHealth(w http.ResponseWriter, r *http.Request) {
	stats, _ := a.DB.Stats(r.Context())
	fwMACs, fwErr := a.MACSvc.FW.List(r.Context())
	fwStatus := "ok"
	if fwErr != nil {
		fwStatus = fwErr.Error()
	}
	dbSize := int64(-1)
	if st, err := os.Stat(a.Cfg.DBPath); err == nil {
		dbSize = st.Size()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":             a.Version,
		"uptime_seconds":      int(time.Since(a.StartAt).Seconds()),
		"db_path":             a.Cfg.DBPath,
		"db_size_bytes":       dbSize,
		"paid_iface":          a.Cfg.PaidIface,
		"wechat_enabled":      a.WeChat != nil,
		"alipay_enabled":      a.Alipay != nil,
		"mac_total":           stats.Total,
		"mac_active":          stats.Active,
		"mac_expired":         stats.Expired,
		"user_count":          stats.Users,
		"revenue_cents":       stats.RevenueCents,
		"firewall_set_count":  len(fwMACs),
		"firewall_set_status": fwStatus,
	})
}

// GET /admin/audit?actor=&action=&target=&since=&until=  → HTML
func (a *App) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := db.AuditFilter{
		Actor:  strings.TrimSpace(q.Get("actor")),
		Action: strings.TrimSpace(q.Get("action")),
		Target: strings.TrimSpace(q.Get("target")),
		Since:  strings.TrimSpace(q.Get("since")),
		Until:  strings.TrimSpace(q.Get("until")),
		Limit:  300,
	}
	entries, err := a.DB.SearchAudit(r.Context(), f)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	actions, _ := a.DB.DistinctAuditActions(r.Context())
	a.render(w, "admin_audit.html", a.adminCtx(r, "audit", map[string]any{
		"Entries": entries,
		"Filter":  f,
		"Actions": actions,
	}))
}

// POST /admin/macs/import  body: textarea with one MAC per line, optional label+days
//
//	AA:BB:CC:DD:EE:FF,365,charger-1
//	AA:BB:CC:DD:EE:FE,30
//	AA:BB:CC:DD:EE:FD
func (a *App) handleAdminMACImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/macs", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	defaultDays, _ := strconv.Atoi(r.PostForm.Get("default_days"))
	if defaultDays <= 0 {
		defaultDays = 365
	}
	body := r.PostForm.Get("bulk")
	added, failed := 0, 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		mac, ok := models.NormalizeMAC(strings.TrimSpace(parts[0]))
		if !ok {
			failed++
			continue
		}
		days := defaultDays
		if len(parts) > 1 {
			if d, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && d > 0 {
				days = d
			}
		}
		label := "imported"
		if len(parts) > 2 {
			if v := strings.TrimSpace(parts[2]); v != "" {
				label = v
			}
		}
		if _, err := a.MACSvc.Extend(r.Context(), mac, label, days, nil); err != nil {
			log.Printf("import %s: %v", mac, err)
			failed++
			continue
		}
		added++
	}
	a.DB.Audit(r.Context(), "admin", "bulk_import", "",
		fmt.Sprintf("added=%d failed=%d", added, failed))
	http.Redirect(w, r, fmt.Sprintf("/admin/macs?ok=import&added=%d&failed=%d", added, failed), http.StatusSeeOther)
}

// GET /admin/export/macs.csv
func (a *App) handleAdminExportMACs(w http.ResponseWriter, r *http.Request) {
	macs, err := a.DB.ListMACs(r.Context())
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="macs.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"mac", "label", "status", "expires_at", "user_id", "created_at"})
	for _, m := range macs {
		uid := ""
		if m.UserID != nil {
			uid = strconv.FormatInt(*m.UserID, 10)
		}
		_ = cw.Write([]string{
			m.Mac,
			m.Label,
			string(m.Status),
			m.ExpiresAt.UTC().Format(time.RFC3339),
			uid,
			m.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
}

// GET /admin/export/users.csv
//
// One row per registered user. Phone + suspended + 2FA-enabled + count of
// MACs + created_at. Excludes password_hash + totp_secret + totp_pending —
// those should never leave the DB.
func (a *App) handleAdminExportUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.DB.ListUsers(r.Context(), 5000)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	// Pre-aggregate mac counts so we don't N+1.
	macCount := map[int64]int{}
	if macs, _ := a.DB.ListMACs(r.Context()); macs != nil {
		for _, m := range macs {
			if m.UserID != nil {
				macCount[*m.UserID]++
			}
		}
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="users.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"id", "phone", "suspended", "totp_enabled", "macs", "created_at"})
	for _, u := range users {
		susp := "0"
		if u.Suspended {
			susp = "1"
		}
		t2fa := "0"
		if u.TOTPSecret != "" {
			t2fa = "1"
		}
		_ = cw.Write([]string{
			strconv.FormatInt(u.ID, 10),
			u.Phone,
			susp,
			t2fa,
			strconv.Itoa(macCount[u.ID]),
			u.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
}

// GET /admin/export/audit.csv?actor=&action=&target=&since=&until=&limit=
//
// CSV companion to /admin/audit. Same filter knobs. Default limit 1000,
// max 10000 (much bigger than the HTML page's 300 — CSV export is
// expected for compliance dumps where higher row counts matter).
func (a *App) handleAdminExportAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 1000
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 10000 {
			limit = n
		}
	}
	entries, err := a.DB.SearchAudit(r.Context(), db.AuditFilter{
		Actor:  strings.TrimSpace(q.Get("actor")),
		Action: strings.TrimSpace(q.Get("action")),
		Target: strings.TrimSpace(q.Get("target")),
		Since:  strings.TrimSpace(q.Get("since")),
		Until:  strings.TrimSpace(q.Get("until")),
		Limit:  limit,
	})
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"id", "at", "actor", "action", "target", "detail"})
	for _, e := range entries {
		_ = cw.Write([]string{
			strconv.FormatInt(e.ID, 10),
			e.At.UTC().Format(time.RFC3339),
			e.Actor, e.Action, e.Target, e.Detail,
		})
	}
}

// GET /admin/export/orders.csv?q=&status=&since=&until=
//
// Same filter params as /admin/orders so admins can export the exact
// view they're looking at. When no filter is set, falls back to ListOrders
// with a generous 5000-row cap (the original v0.0 behavior).
func (a *App) handleAdminExportOrders(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	since := strings.TrimSpace(r.URL.Query().Get("since"))
	until := strings.TrimSpace(r.URL.Query().Get("until"))
	var orders []models.Order
	var err error
	if q == "" && status == "" && since == "" && until == "" {
		orders, err = a.DB.ListOrders(r.Context(), 5000)
	} else {
		orders, err = a.DB.SearchOrdersFiltered(r.Context(), db.OrderFilter{
			Q: q, Status: status, Since: since, Until: until, Limit: 1000,
		})
	}
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="orders.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"order_no", "mac", "plan", "days", "amount_cents", "status", "method", "trade_no", "user_id", "paid_at", "created_at"})
	for _, o := range orders {
		uid := ""
		if o.UserID != nil {
			uid = strconv.FormatInt(*o.UserID, 10)
		}
		paid := ""
		if o.PaidAt != nil {
			paid = o.PaidAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			o.OrderNo, o.Mac, o.Plan, strconv.Itoa(o.Days),
			strconv.Itoa(o.AmountCents), string(o.Status), o.PaymentMethod, o.TradeNo,
			uid, paid, o.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
}
