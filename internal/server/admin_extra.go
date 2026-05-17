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

// GET /admin/export/orders.csv
func (a *App) handleAdminExportOrders(w http.ResponseWriter, r *http.Request) {
	orders, err := a.DB.ListOrders(r.Context(), 5000)
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
