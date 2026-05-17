package server

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	a.render(w, "admin_vouchers.html", a.adminCtx(r, "vouchers", map[string]any{
		"Vouchers": list,
		"Batch":    batch,
		"Counts":   map[string]int{"total": total, "redeemed": redeemed, "revoked": revoked, "expired": expired, "unused": total - redeemed - revoked - expired},
	}))
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

	created := 0
	for i := 0; i < count; i++ {
		// Up to 3 retries on the very unlikely 12-char collision.
		for try := 0; try < 3; try++ {
			code, err := voucher.New()
			if err != nil {
				log.Printf("voucher gen: %v", err)
				break
			}
			if _, err := a.DB.CreateVoucher(r.Context(), code, days, label, batch, expires); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "unique") {
					continue
				}
				log.Printf("voucher insert: %v", err)
				break
			}
			created++
			break
		}
	}
	a.DB.Audit(r.Context(), "admin", "voucher_batch", batch,
		fmt.Sprintf("count=%d days=%d", created, days))
	http.Redirect(w, r, "/admin/vouchers?batch="+batch+"&ok=1", http.StatusSeeOther)
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

func (a *App) handleAdminVouchersExport(w http.ResponseWriter, r *http.Request) {
	batch := r.URL.Query().Get("batch")
	list, err := a.DB.ListVouchers(r.Context(), batch, 1000)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	stamp := time.Now().Format("20060102-150405")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="vouchers-%s-%s.csv"`, batch, stamp))
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	codeRaw := r.PostForm.Get("code")
	code := voucher.Canon(codeRaw)
	if err := voucher.Validate(code); err != nil {
		http.Redirect(w, r, "/redeem?code="+codeRaw+"&err="+httpEsc(err.Error()), http.StatusSeeOther)
		return
	}
	macInput := r.PostForm.Get("mac")
	if macInput == "" {
		macInput = a.detectMAC(r)
	}
	mac, ok := models.NormalizeMAC(macInput)
	if !ok {
		http.Redirect(w, r, "/redeem?code="+codeRaw+"&err="+httpEsc("无法识别 MAC，请填写"), http.StatusSeeOther)
		return
	}

	// User context: link the redemption (and the MAC ownership) to current user if logged in.
	var userID *int64
	if uid := a.currentUserID(r); uid != 0 {
		userID = &uid
	}

	v, err := a.DB.RedeemVoucher(r.Context(), code, mac, userID)
	if err != nil {
		http.Redirect(w, r, "/redeem?code="+codeRaw+"&err="+httpEsc(redeemErrLabel(err)), http.StatusSeeOther)
		return
	}
	// Apply the time to the MAC.
	m, err := a.MACSvc.Extend(r.Context(), mac, "voucher:"+v.Batch, v.Days, userID)
	if err != nil {
		log.Printf("redeem extend %s: %v", mac, err)
		http.Redirect(w, r, "/redeem?code="+codeRaw+"&err=授权失败请联系管理员", http.StatusSeeOther)
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

// httpEsc is a tiny URL-encoder for our redirect query strings.
func httpEsc(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '&', '?', '#', '=', '+', '%', ' ':
			b.WriteString(fmt.Sprintf("%%%02X", r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
