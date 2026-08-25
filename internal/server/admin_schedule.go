package server

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"router-billing/internal/models"
)

func backgroundCtx() context.Context { return context.Background() }
func timeNow() time.Time             { return time.Now() }

// GET  /admin/macs/schedule?mac=AA:BB:..  → editor form
// POST /admin/macs/schedule {mac, days=1&days=2&..., start_hr, start_min, end_hr, end_min, clear}
func (a *App) handleAdminMACSchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		a.handleAdminMACScheduleSave(w, r)
		return
	}
	mac, ok := models.NormalizeMAC(r.URL.Query().Get("mac"))
	if !ok {
		http.Redirect(w, r, "/admin/macs?err=invalid_mac", http.StatusSeeOther)
		return
	}
	m, err := a.DB.GetMAC(r.Context(), mac)
	if err != nil || m == nil {
		http.Redirect(w, r, "/admin/macs?err=invalid_mac", http.StatusSeeOther)
		return
	}
	sched, _ := models.ParseSchedule(m.ScheduleJSON)
	a.render(w, "admin_mac_schedule.html", a.adminCtx(r, "macs", map[string]any{
		"MAC":         m,
		"Schedule":    sched,
		"HasSchedule": !sched.IsEmpty(),
	}))
}

func (a *App) handleAdminMACScheduleSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	mac, ok := models.NormalizeMAC(r.PostForm.Get("mac"))
	if !ok {
		http.Redirect(w, r, "/admin/macs?err=invalid_mac", http.StatusSeeOther)
		return
	}
	if r.PostForm.Get("clear") == "1" {
		if err := a.DB.SetMACSchedule(r.Context(), mac, ""); err != nil {
			log.Printf("clear schedule %s: %v", mac, err)
		}
		// Re-add to firewall (no restriction → should be in) — but ONLY
		// when the row is actually entitled to be online. Pre-v0.108 this
		// Add was unconditional, so clearing a schedule on a blocked or
		// expired MAC silently put it back into the paid set until the
		// next resync.
		if m, _ := a.DB.GetMAC(r.Context(), mac); macEligibleForFirewall(m) {
			_ = a.MACSvc.FW.Add(r.Context(), mac)
		}
		a.DB.Audit(r.Context(), "admin", "schedule_clear", mac, "")
		http.Redirect(w, r, "/admin/macs?ok=1", http.StatusSeeOther)
		return
	}
	var days []int
	for _, v := range r.PostForm["days"] {
		d, err := strconv.Atoi(v)
		if err == nil && d >= 1 && d <= 7 {
			days = append(days, d)
		}
	}
	sh, _ := strconv.Atoi(r.PostForm.Get("start_hr"))
	sm, _ := strconv.Atoi(r.PostForm.Get("start_min"))
	eh, _ := strconv.Atoi(r.PostForm.Get("end_hr"))
	em, _ := strconv.Atoi(r.PostForm.Get("end_min"))
	startMin := sh*60 + sm
	endMin := eh*60 + em
	if startMin < 0 || startMin > 1439 || endMin < 0 || endMin > 1439 || len(days) == 0 {
		http.Redirect(w, r, "/admin/macs/schedule?mac="+mac+"&err=invalid_days", http.StatusSeeOther)
		return
	}
	sched := models.MacSchedule{Days: days, StartMin: startMin, EndMin: endMin}
	if err := a.DB.SetMACSchedule(r.Context(), mac, sched.JSON()); err != nil {
		log.Printf("save schedule %s: %v", mac, err)
		http.Redirect(w, r, "/admin/macs/schedule?mac="+mac+"&err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "admin", "schedule_set", mac, sched.String())
	// Apply immediately so admin sees the effect without waiting for the
	// minute-tick goroutine.
	go a.applyOneSchedule(mac, sched)
	http.Redirect(w, r, "/admin/macs?ok=1", http.StatusSeeOther)
}

func (a *App) applyOneSchedule(mac string, sched models.MacSchedule) {
	ctx := backgroundCtx()
	// Never let a schedule write resurrect a blocked/expired MAC: the
	// minute-tick enforcer only iterates ListActiveMACs, but this
	// immediate-apply path used to Add unconditionally, so saving an
	// "active hours" window on an ineligible MAC granted it access.
	m, err := a.DB.GetMAC(ctx, mac)
	if err != nil || !macEligibleForFirewall(m) {
		_ = a.MACSvc.FW.Remove(ctx, mac)
		return
	}
	if sched.Active(timeNow()) {
		_ = a.MACSvc.FW.Add(ctx, mac)
	} else {
		_ = a.MACSvc.FW.Remove(ctx, mac)
	}
}

// macEligibleForFirewall mirrors the WHERE clause Resync builds the set
// from (ListActiveMACs): status=active AND unexpired. nil-safe.
func macEligibleForFirewall(m *models.MAC) bool {
	return m != nil && m.Status == models.MACActive && m.ExpiresAt.After(timeNow())
}
