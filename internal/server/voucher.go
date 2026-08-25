package server

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"router-billing/internal/db"
	"router-billing/internal/models"
	"router-billing/internal/notify"
	"router-billing/internal/voucher"
)

// -------- ADMIN --------

// GET /admin/vouchers
// POST /admin/vouchers/generate {count, days, batch, expires_days, label}
// POST /admin/vouchers/revoke   {code}
// GET  /admin/vouchers/export.csv?batch=...
func (a *App) handleAdminVouchers(w http.ResponseWriter, r *http.Request) {
	batch := r.URL.Query().Get("batch")
	list, err := a.DB.ListVouchers(r.Context(), batch, 500)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	// Compute counts for the visible set (so admin sees redeemed vs unredeemed).
	var total, redeemed, revoked, expired int
	now := time.Now().UTC()
	for _, v := range list {
		total++
		if v.Revoked {
			revoked++
			continue
		}
		if v.RedeemedAt != nil {
			redeemed++
			continue
		}
		if v.ExpiresAt != nil && v.ExpiresAt.Before(now) {
			expired++
		}
	}
	// Batch summary — independent of the per-row list above. Shows every
	// batch's inventory at a glance for "how many of batch X are still
	// usable" reconciliation.
	batchStats, _ := a.DB.VoucherBatchStats(r.Context())

	// Pass through raw query params so the import-result flash can read
	// added=/failed= counts.
	rawQuery := map[string]string{}
	for k := range r.URL.Query() {
		rawQuery[k] = r.URL.Query().Get(k)
	}
	a.render(w, "admin_vouchers.html", a.adminCtx(r, "vouchers", map[string]any{
		"Vouchers":   list,
		"Batch":      batch,
		"Counts":     map[string]int{"total": total, "redeemed": redeemed, "revoked": revoked, "expired": expired, "unused": total - redeemed - revoked - expired},
		"BatchStats": batchStats,
		"Query0":     rawQuery,
	}))
}

// POST /admin/vouchers/import (form-encoded `bulk` textarea)
//
// Comma-separated CSV-ish import for codes that were printed offline.
// Each line: `code,days[,label[,batch[,expires_at_RFC3339]]]`. Skips
// blank lines and `# ...` comments. Codes go through voucher.Canon so
// users can paste dashed forms.
//
// Returns to /admin/vouchers with added=N failed=M reasons in the flash.
// Each created voucher is audited individually so the existing per-row
// trail still works.
//
// All inserts run in a single SQLite transaction (CreateVouchersBulk) —
// pre-v0.103 each row was its own implicit txn so a 1000-row import did
// 1000 fsyncs ≈ several seconds even on SSD. Now: one fsync at COMMIT.
// UNIQUE collisions still don't roll back the rest (SQLite stmt-level
// errors don't abort the surrounding tx), so a duplicate paste in the
// middle of an import doesn't lose the rest.
func (a *App) handleAdminVouchersImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/vouchers", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	bulk := r.PostForm.Get("bulk")

	// Two-pass: first parse every line into specs (cheap, no DB), then a
	// single bulk insert. Rejected-at-parse rows count as failed.
	var (
		specs   []db.VoucherSpec
		failed  int
		auditIP = a.clientIP(r)
	)
	for _, raw := range strings.Split(bulk, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		code := voucher.Canon(parts[0])
		if code == "" || len(code) < 6 {
			failed++
			continue
		}
		days := 30
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && n > 0 {
				days = n
			}
		}
		label := ""
		if len(parts) >= 3 {
			label = strings.TrimSpace(parts[2])
		}
		batch := ""
		if len(parts) >= 4 {
			batch = strings.TrimSpace(parts[3])
		}
		var expires *time.Time
		if len(parts) >= 5 {
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[4])); err == nil {
				expires = &t
			}
		}
		specs = append(specs, db.VoucherSpec{
			Code: code, Days: days, Label: label, Batch: batch, ExpiresAt: expires,
		})
	}

	results, err := a.DB.CreateVouchersBulk(r.Context(), specs)
	if err != nil {
		log.Printf("voucher bulk import: %v", err)
		http.Redirect(w, r, "/admin/vouchers?err=db", http.StatusSeeOther)
		return
	}
	added := 0
	for i, ok := range results {
		if !ok {
			failed++
			continue
		}
		added++
		// Per-row audit happens after the single tx so the timeline
		// still records every imported code, but the slow part (sync to
		// disk) only fsyncs once for the inserts. Audit rows themselves
		// are best-effort and not in our hot loop.
		s := specs[i]
		a.DB.Audit(r.Context(), "admin", "voucher_imported", s.Code,
			"days="+strconv.Itoa(s.Days)+" batch="+s.Batch+" ip="+auditIP)
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/vouchers?ok=import&added=%d&failed=%d", added, failed), http.StatusSeeOther)
}

func (a *App) handleAdminVouchersGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/vouchers", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	count, _ := strconv.Atoi(r.PostForm.Get("count"))
	days, _ := strconv.Atoi(r.PostForm.Get("days"))
	expiresDays, _ := strconv.Atoi(r.PostForm.Get("expires_days"))
	batch := strings.TrimSpace(r.PostForm.Get("batch"))
	label := strings.TrimSpace(r.PostForm.Get("label"))

	if count <= 0 || count > 1000 {
		http.Redirect(w, r, "/admin/vouchers?err=invalid_days", http.StatusSeeOther)
		return
	}
	if days <= 0 {
		http.Redirect(w, r, "/admin/vouchers?err=invalid_days", http.StatusSeeOther)
		return
	}
	if batch == "" {
		batch = "B" + time.Now().UTC().Format("20060102-150405")
	}
	var expires *time.Time
	if expiresDays > 0 {
		t := time.Now().UTC().AddDate(0, 0, expiresDays)
		expires = &t
	}

	// Generate `count` candidates upfront, dedupe in-memory (12-char codes
	// from a 32-symbol alphabet have ~zero realistic collision rate, but
	// the dedupe is cheap insurance), then bulk-insert in one tx.
	// Pre-v0.103 each row was a separate fsync; 1000-voucher batches
	// took several seconds. Now: ~1 fsync.
	specs := make([]db.VoucherSpec, 0, count)
	seen := make(map[string]struct{}, count)
	for len(specs) < count {
		code, err := voucher.New()
		if err != nil {
			log.Printf("voucher gen: %v", err)
			break
		}
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		specs = append(specs, db.VoucherSpec{
			Code: code, Days: days, Label: label, Batch: batch, ExpiresAt: expires,
		})
	}
	results, err := a.DB.CreateVouchersBulk(r.Context(), specs)
	if err != nil {
		log.Printf("voucher bulk generate: %v", err)
		http.Redirect(w, r, "/admin/vouchers?err=db", http.StatusSeeOther)
		return
	}
	created := 0
	for _, ok := range results {
		if ok {
			created++
		}
	}
	a.DB.Audit(r.Context(), "admin", "voucher_batch", batch,
		fmt.Sprintf("count=%d days=%d", created, days))
	http.Redirect(w, r, "/admin/vouchers?batch="+url.QueryEscape(batch)+"&ok=1", http.StatusSeeOther)
}

func (a *App) handleAdminVouchersRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/vouchers", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	code := voucher.Canon(r.PostForm.Get("code"))
	if err := a.DB.RevokeVoucher(r.Context(), code); err != nil {
		log.Printf("revoke voucher: %v", err)
	}
	a.DB.Audit(r.Context(), "admin", "voucher_revoke", code, "")
	http.Redirect(w, r, redirectBack(r, "ok=1"), http.StatusSeeOther)
}

// POST /admin/vouchers/batch/revoke   {batch}
//
// Mass-revoke every still-usable voucher in a batch. Useful when a partner
// deal falls through and the entire batch needs to be killed — clicking
// each row's revoke button would take forever for a 500-row batch.
// Redeemed vouchers are intentionally untouched (revoking those would
// invalidate real usage). Returns to /admin/vouchers with revoked=N in the
// flash so the UI can confirm the count.
func (a *App) handleAdminVoucherBatchRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/vouchers", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	batch := strings.TrimSpace(r.PostForm.Get("batch"))
	// Special "(no batch)" sentinel maps back to empty string for the DB
	// query — that's what VoucherBatchStats labels the unbatched bucket.
	if batch == "(no batch)" {
		batch = ""
	}
	n, err := a.DB.RevokeVoucherBatch(r.Context(), batch)
	if err != nil {
		log.Printf("revoke voucher batch %q: %v", batch, err)
		http.Redirect(w, r, "/admin/vouchers?err=db", http.StatusSeeOther)
		return
	}
	displayBatch := batch
	if displayBatch == "" {
		displayBatch = "(no batch)"
	}
	a.DB.Audit(r.Context(), "admin", "voucher_batch_revoke", displayBatch,
		fmt.Sprintf("count=%d ip=%s", n, a.clientIP(r)))
	http.Redirect(w, r,
		fmt.Sprintf("/admin/vouchers?ok=batch_revoke&revoked=%d&batch=%s", n, url.QueryEscape(displayBatch)),
		http.StatusSeeOther)
}

// GET /admin/vouchers/export.csv?batch=&status=
//
// status filter (optional): unused|redeemed|revoked|expired. Matches the
// derived status the per-row CSV already emits, so an operator who
// downloaded a previous export and filtered "status=redeemed" in Excel
// can now ask for that directly. The filter happens in Go (since the
// DB doesn't store the derived status column) — list size is capped
// at 1000 by the underlying ListVouchers so the in-memory pass is fine.
func (a *App) handleAdminVouchersExport(w http.ResponseWriter, r *http.Request) {
	batch := r.URL.Query().Get("batch")
	wantStatus := strings.TrimSpace(r.URL.Query().Get("status"))
	list, err := a.DB.ListVouchers(r.Context(), batch, 1000)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	stamp := time.Now().Format("20060102-150405")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	filenameSuffix := batch
	if wantStatus != "" {
		filenameSuffix = batch + "-" + wantStatus
	}
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="vouchers-%s-%s.csv"`, filenameSuffix, stamp))
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"code_pretty", "code", "days", "batch", "expires_at", "status", "redeemed_by_mac", "created_at"})
	now := time.Now().UTC()
	for _, v := range list {
		status := "unused"
		if v.Revoked {
			status = "revoked"
		} else if v.RedeemedAt != nil {
			status = "redeemed"
		} else if v.ExpiresAt != nil && v.ExpiresAt.Before(now) {
			status = "expired"
		}
		if wantStatus != "" && status != wantStatus {
			continue
		}
		expires := ""
		if v.ExpiresAt != nil {
			expires = v.ExpiresAt.Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			voucher.Pretty(v.Code),
			v.Code,
			strconv.Itoa(v.Days),
			v.Batch,
			expires,
			status,
			v.RedeemedByMac,
			v.CreatedAt.Format(time.RFC3339),
		})
	}
}

// -------- PUBLIC / USER --------

// GET /redeem — standalone page; works for unauthenticated users too.
// The printed voucher carries a QR like http://router-ip:8080/redeem?code=XXX-XXX
func (a *App) handleRedeemPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, "redeem.html", map[string]any{
		"Code":      r.URL.Query().Get("code"),
		"MAC":       a.detectMAC(r),
		"LoggedIn":  a.currentUserID(r) != 0,
		"OK":        r.URL.Query().Get("ok"),
		"Err":       r.URL.Query().Get("err"),
		"Days":      r.URL.Query().Get("days"),
		"ExpiresAt": r.URL.Query().Get("expires_at"),
		"Version":   a.Version,
	})
}

// POST /redeem  {code, mac?}
func (a *App) handleRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/redeem", http.StatusSeeOther)
		return
	}
	// Rate-limit by client IP. 10 tries / 10 minutes is generous for honest
	// fat-finger typos and prohibitive for brute-forcing the 12-char alphabet.
	if a.redeemLimiter != nil && !a.redeemLimiter.allow(a.clientIP(r)) {
		http.Redirect(w, r, "/redeem?err="+url.QueryEscape("尝试过于频繁，请 10 分钟后再试"), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	// codeRaw is raw user input — always query-escape it in redirects.
	// Pre-v0.100 it was concatenated as-is, so "X&ok=1" or "X#f" could
	// inject extra query params / truncate the redirect URL.
	codeRaw := r.PostForm.Get("code")
	code := voucher.Canon(codeRaw)
	if err := voucher.Validate(code); err != nil {
		http.Redirect(w, r, "/redeem?code="+url.QueryEscape(codeRaw)+"&err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	macInput := r.PostForm.Get("mac")
	if macInput == "" {
		macInput = a.detectMAC(r)
	}
	mac, ok := models.NormalizeMAC(macInput)
	if !ok {
		http.Redirect(w, r, "/redeem?code="+url.QueryEscape(codeRaw)+"&err="+url.QueryEscape("无法识别 MAC，请填写"), http.StatusSeeOther)
		return
	}

	// User context: link the redemption (and the MAC ownership) to current user if logged in.
	var userID *int64
	if uid := a.currentUserID(r); uid != 0 {
		userID = &uid
	}

	v, err := a.DB.RedeemVoucher(r.Context(), code, mac, userID)
	if err != nil {
		http.Redirect(w, r, "/redeem?code="+url.QueryEscape(codeRaw)+"&err="+url.QueryEscape(redeemErrLabel(err)), http.StatusSeeOther)
		return
	}
	// Apply the time to the MAC.
	m, err := a.MACSvc.Extend(r.Context(), mac, "voucher:"+v.Batch, v.Days, userID)
	if err != nil {
		log.Printf("redeem extend %s: %v", mac, err)
		http.Redirect(w, r, "/redeem?code="+url.QueryEscape(codeRaw)+"&err="+url.QueryEscape("授权失败请联系管理员"), http.StatusSeeOther)
		return
	}
	actor := "user-anon"
	if userID != nil {
		actor = fmt.Sprintf("user:%d", *userID)
	}
	a.DB.Audit(r.Context(), actor, "redeem", mac, "voucher="+code)
	uid := int64(0)
	if userID != nil {
		uid = *userID
	}
	a.Notifier.Send(notify.Event{
		Type:    "redeem",
		Actor:   actor,
		MAC:     mac,
		UserID:  uid,
		Days:    v.Days,
		Voucher: code,
	})

	q := fmt.Sprintf("/redeem?ok=1&days=%d&expires_at=%s",
		v.Days, m.ExpiresAt.Format("2006-01-02"))
	http.Redirect(w, r, q, http.StatusSeeOther)
}

func redeemErrLabel(err error) string {
	switch {
	case errors.Is(err, db.ErrVoucherNotFound):
		return "充值码不存在或已被作废"
	case errors.Is(err, db.ErrVoucherUsed):
		return "该充值码已被使用"
	case errors.Is(err, db.ErrVoucherRevoked):
		return "该充值码已作废"
	case errors.Is(err, db.ErrVoucherExpired):
		return "该充值码已过期"
	default:
		return err.Error()
	}
}
