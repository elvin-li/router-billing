package server

import (
	"net/http"
	"time"

	"router-billing/internal/models"
)

// waitFor registers a one-shot channel for the given order. Caller MUST
// unregister via unwait when done (defer recommended).
func (a *App) waitFor(orderNo string) chan struct{} {
	ch := make(chan struct{}, 1)
	a.waitMu.Lock()
	a.waiters[orderNo] = append(a.waiters[orderNo], ch)
	a.waitMu.Unlock()
	return ch
}

func (a *App) unwait(orderNo string, ch chan struct{}) {
	a.waitMu.Lock()
	defer a.waitMu.Unlock()
	list := a.waiters[orderNo]
	out := list[:0]
	for _, c := range list {
		if c != ch {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		delete(a.waiters, orderNo)
	} else {
		a.waiters[orderNo] = out
	}
}

func (a *App) signalOrder(orderNo string) {
	a.waitMu.Lock()
	chs := a.waiters[orderNo]
	delete(a.waiters, orderNo)
	a.waitMu.Unlock()
	for _, ch := range chs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// GET /api/pay/wait?order_no=X
// Long-polls up to 60s for the order to become paid. Returns immediately if
// the order is already paid (or once it transitions during the wait).
// Also opportunistically queries upstream every 5s if it hasn't been queried
// recently — this means the webhook isn't needed at all in dev / no-HTTPS.
func (a *App) handlePayWait(w http.ResponseWriter, r *http.Request) {
	orderNo := r.URL.Query().Get("order_no")
	if orderNo == "" {
		http.Error(w, "missing order_no", http.StatusBadRequest)
		return
	}
	o, err := a.DB.GetOrder(r.Context(), orderNo)
	if err != nil || o == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if o.Status == models.OrderPaid {
		a.respondPaid(w, r, o)
		return
	}

	ch := a.waitFor(orderNo)
	defer a.unwait(orderNo, ch)

	deadline := time.Now().Add(60 * time.Second)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ch:
			// finalizeOrder ran; re-fetch and respond.
			o2, _ := a.DB.GetOrder(r.Context(), orderNo)
			if o2 != nil && o2.Status == models.OrderPaid {
				a.respondPaid(w, r, o2)
				return
			}
		case <-tick.C:
			// Tick: opportunistic upstream query.
			o2, _ := a.DB.GetOrder(r.Context(), orderNo)
			if o2 != nil && o2.Status == models.OrderPaid {
				a.respondPaid(w, r, o2)
				return
			}
			if o2 != nil && a.shouldQueryNow(o2) {
				a.queryOrder(r.Context(), *o2)
				o3, _ := a.DB.GetOrder(r.Context(), orderNo)
				if o3 != nil && o3.Status == models.OrderPaid {
					a.respondPaid(w, r, o3)
					return
				}
			}
		case <-r.Context().Done():
			return
		}
	}
	// Timed out — browser will reissue.
	writeJSON(w, http.StatusOK, map[string]any{
		"order_no": orderNo,
		"status":   "pending",
	})
}

func (a *App) respondPaid(w http.ResponseWriter, r *http.Request, o *models.Order) {
	resp := map[string]any{
		"order_no": o.OrderNo,
		"status":   "paid",
		"mac":      o.Mac,
	}
	if mm, _ := a.DB.GetMAC(r.Context(), o.Mac); mm != nil {
		resp["expires_at"] = mm.ExpiresAt
	}
	writeJSON(w, http.StatusOK, resp)
}
