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
//
// v0.61 expanded the payload with the attention counters that
// /admin/dashboard already shows, so monitoring scripts that poll
// /api/admin/health can alert without computing it themselves.
func (a *App) handleAdminHealth(w http.ResponseWriter, r *http.Request) {
	stats, _ := a.DB.Stats(r.Context())
	att, _ := a.DB.Attention(r.Context())
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
		// v0.61: attention counters previously only visible via the
		// dashboard. Monitoring scripts can now alert on these without
		// parsing HTML.
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

// POST /admin/audit/note  {note}
//
// Lets an admin write a free-text manual entry into the audit log. Useful
// for out-of-band actions: "refund issued via Aliyun console", "user
// called and confirmed they lost their phone", etc. Actor is the admin's
// username; action is "manual_note"; target is empty; detail is the
// supplied text.
func (a *App) handleAdminAuditNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/audit", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(r.PostForm.Get("note"))
	if note == "" {
		http.Redirect(w, r, "/admin/audit?err=empty_note", http.StatusSeeOther)
		return
	}
	if len(note) > 1000 {
		note = note[:1000]
	}
	// Try to attribute to the actual admin username — read it from the
	// session subject.
	actor := "admin"
	if c, err := r.Cookie(adminCookieName); err == nil {
		if sess, _ := a.DB.GetSession(r.Context(), c.Value); sess != nil && sess.Subject != "" {
			actor = "admin:" + sess.Subject
		}
	}
	a.DB.Audit(r.Context(), actor, "manual_note", "", note+" ip="+clientIP(r))
	http.Redirect(w, r, "/admin/audit?ok=note", http.StatusSeeOther)
}

// GET /admin/audit?actor=&action=&target=&since=&until=  → HTML
func (a *App) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := db.AuditFilter{
		Actor:  strings.TrimSpace(q.Get("actor")),
		Action: strings.TrimSpace(q.Get("action")),
		Target: strings.TrimSpace(q.Get("target")),
		Q:      strings.TrimSpace(q.Get("q")),
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
	actors, _ := a.DB.DistinctAuditActors(r.Context())
	totalRows, _ := a.DB.CountAudit(r.Context())
	retention := a.Cfg.Security.AuditLogRetention()
	// v0.86: action-frequency totals honoring the current date filter so
	// the chip row at the top of /admin/audit shows the operator the
	// volume distribution in the window they're looking at.
	actionTotals, _ := a.DB.CountAuditActionsByDate(r.Context(), f.Since, f.Until)
	a.render(w, "admin_audit.html", a.adminCtx(r, "audit", map[string]any{
		"Entries":      entries,
		"Filter":       f,
		"Actions":      actions,
		"Actors":       actors,
		"ActionTotals": actionTotals,
		"TotalRows":    totalRows,
		"Retention":    retention,
		"UsagePct": func() int {
			if retention <= 0 {
				return 0
			}
			return totalRows * 100 / retention
		}(),
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
		// v0.83: optional 4th column = free-text notes (max 1000 chars).
		// Empty value or no column → no notes set.
		notes := ""
		if len(parts) > 3 {
			if v := strings.TrimSpace(parts[3]); v != "" {
				notes = v
				if len(notes) > 1000 {
					notes = notes[:1000]
				}
			}
		}
		if _, err := a.MACSvc.Extend(r.Context(), mac, label, days, nil); err != nil {
			log.Printf("import %s: %v", mac, err)
			failed++
			continue
		}
		if notes != "" {
			if err := a.DB.SetMACNotes(r.Context(), mac, notes); err != nil {
				log.Printf("import %s notes: %v", mac, err)
				// Don't bump `failed` — the MAC itself imported fine,
				// only the optional notes-write failed.
			}
		}
		added++
	}
	a.DB.Audit(r.Context(), "admin", "bulk_import", "",
		fmt.Sprintf("added=%d failed=%d", added, failed))
	http.Redirect(w, r, fmt.Sprintf("/admin/macs?ok=import&added=%d&failed=%d", added, failed), http.StatusSeeOther)
}

// GET /admin/export/macs.csv?q=&status=&user_id=
//
// v0.67: same filter set as v0.40's /api/admin/macs so the CSV export
// matches what's on the /admin/macs screen. Active filters switch the
// downloaded filename to macs-filtered.csv (matches v0.41 voucher +
// v0.66 users export pattern).
func (a *App) handleAdminExportMACs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	qSearch := strings.TrimSpace(q.Get("q"))
	statusFilter := strings.TrimSpace(q.Get("status"))
	userIDStr := strings.TrimSpace(q.Get("user_id"))
	var userID int64
	if userIDStr != "" {
		if n, perr := strconv.ParseInt(userIDStr, 10, 64); perr == nil && n > 0 {
			userID = n
		}
	}

	var macs []models.MAC
	var err error
	if userID > 0 {
		macs, err = a.DB.ListMACsForUser(r.Context(), userID)
		if err != nil {
			http.Error(w, "db", http.StatusInternalServerError)
			return
		}
		// Post-filter q + status in memory (bounded by user's MAC count).
		// Case-insensitive to match the SQL LIKE path used when no
		// user_id is set — pre-v0.108 a lowercase "aa:bb" query matched
		// there but not here (MACs are stored uppercase).
		if qSearch != "" || statusFilter != "" {
			qLower := strings.ToLower(qSearch)
			filtered := macs[:0]
			for _, m := range macs {
				if statusFilter != "" && string(m.Status) != statusFilter {
					continue
				}
				if qSearch != "" &&
					!strings.Contains(strings.ToLower(m.Mac), qLower) &&
					!strings.Contains(strings.ToLower(m.Label), qLower) {
					continue
				}
				filtered = append(filtered, m)
			}
			macs = filtered
		}
	} else if qSearch != "" || statusFilter != "" {
		macs, err = a.DB.SearchMACs(r.Context(), qSearch, statusFilter, 5000)
		if err != nil {
			http.Error(w, "db", http.StatusInternalServerError)
			return
		}
	} else {
		macs, err = a.DB.ListMACs(r.Context())
		if err != nil {
			http.Error(w, "db", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	filename := "macs.csv"
	if qSearch != "" || statusFilter != "" || userID > 0 {
		filename = "macs-filtered.csv"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
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

// GET /admin/export/users.csv?q=&suspended=&totp=
//
// One row per registered user. Phone + suspended + 2FA-enabled + count of
// MACs + created_at. Excludes password_hash + totp_secret + totp_pending —
// those should never leave the DB.
//
// v0.66: accepts the same q / suspended / totp filters as /api/admin/users
// (v0.57) so the CSV export matches what's on screen.
func (a *App) handleAdminExportUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	qSearch := strings.TrimSpace(q.Get("q"))
	users, err := a.DB.SearchUsers(r.Context(), qSearch, 5000)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	// Post-filter on suspended / totp (matches v0.57's API semantics).
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
	// Filename includes the filters when set so the download is self-
	// describing alongside v0.41's voucher export.
	filename := "users.csv"
	if qSearch != "" || suspendedFilter != "" || totpFilter != "" {
		filename = "users-filtered.csv"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
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

// GET /admin/export/sms-log.csv?phone=&only_failed=&since=&until=
//
// CSV companion to /admin/sms-log. Same filter knobs (v0.45 + v0.79).
// Default limit 1000, max 10000 — matches the audit export's compliance-
// dump posture.
func (a *App) handleAdminExportSMSLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 1000
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 10000 {
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
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	filename := "sms-log.csv"
	if q.Get("phone") != "" || q.Get("only_failed") == "1" || q.Get("since") != "" || q.Get("until") != "" {
		filename = "sms-log-filtered.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"id", "sent_at", "provider", "phone", "message", "success", "error_msg"})
	for _, l := range logs {
		successStr := "0"
		if l.Success {
			successStr = "1"
		}
		_ = cw.Write([]string{
			strconv.FormatInt(l.ID, 10),
			l.SentAt.UTC().Format(time.RFC3339),
			l.Provider,
			l.Phone,
			l.Message,
			successStr,
			l.ErrorMsg,
		})
	}
}

// GET /admin/export/webhook-log.csv?event_type=&mac=&only_failed=&since=&until=
//
// CSV companion to /admin/webhook-log. Same filter knobs (v0.69 + v0.79).
func (a *App) handleAdminExportWebhookLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 1000
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 10000 {
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
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	filename := "webhook-log.csv"
	anyFilter := q.Get("event_type") != "" || q.Get("mac") != "" || q.Get("only_failed") == "1" ||
		q.Get("since") != "" || q.Get("until") != ""
	if anyFilter {
		filename = "webhook-log-filtered.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"id", "sent_at", "event_type", "mac", "attempt", "status_code", "success", "duration_ms", "error_msg"})
	for _, l := range logs {
		successStr := "0"
		if l.Success {
			successStr = "1"
		}
		_ = cw.Write([]string{
			strconv.FormatInt(l.ID, 10),
			l.SentAt.UTC().Format(time.RFC3339),
			l.EventType,
			l.MAC,
			strconv.Itoa(l.Attempt),
			strconv.Itoa(l.StatusCode),
			successStr,
			strconv.FormatInt(l.DurationMs, 10),
			l.ErrorMsg,
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
		Q:      strings.TrimSpace(q.Get("q")),
		Since:  strings.TrimSpace(q.Get("since")),
		Until:  strings.TrimSpace(q.Get("until")),
		Limit:  limit,
	})
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	filename := "audit.csv"
	if q.Get("actor") != "" || q.Get("action") != "" || q.Get("target") != "" ||
		q.Get("q") != "" || q.Get("since") != "" || q.Get("until") != "" {
		filename = "audit-filtered.csv"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
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
	userIDStr := strings.TrimSpace(r.URL.Query().Get("user_id"))
	var userID int64
	if userIDStr != "" {
		if n, perr := strconv.ParseInt(userIDStr, 10, 64); perr == nil && n > 0 {
			userID = n
		}
	}
	var orders []models.Order
	var err error
	if q == "" && status == "" && since == "" && until == "" && userID == 0 {
		orders, err = a.DB.ListOrders(r.Context(), 5000)
	} else {
		orders, err = a.DB.SearchOrdersFiltered(r.Context(), db.OrderFilter{
			Q: q, Status: status, Since: since, Until: until, UserID: userID, Limit: 1000,
		})
	}
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	// Filename flags active filters — matches the macs/users/sms/webhook
	// export pattern so the download is self-describing.
	filename := "orders.csv"
	if q != "" || status != "" || since != "" || until != "" || userID > 0 {
		filename = "orders-filtered.csv"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
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
