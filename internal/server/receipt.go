package server

import (
	"fmt"
	"net/http"

	"router-billing/internal/models"
)

// GET /receipt?order_no=...  → printable receipt page (商家/用户/admin 都能开)
//
// Only paid orders render. Anyone with the order_no can view — it's a tiny
// data leak (price + MAC) but the order_no carries 64 bits of crypto-random
// suffix (v0.106; 32 bits before) so guessing is infeasible. This is the
// standard tradeoff for "click the link in your payment confirmation".
func (a *App) handleReceipt(w http.ResponseWriter, r *http.Request) {
	orderNo := r.URL.Query().Get("order_no")
	if orderNo == "" {
		http.Error(w, "missing order_no", http.StatusBadRequest)
		return
	}
	o, err := a.DB.GetOrder(r.Context(), orderNo)
	if err != nil || o == nil {
		http.NotFound(w, r)
		return
	}
	if o.Status != models.OrderPaid {
		http.Error(w, "订单尚未完成支付", http.StatusForbidden)
		return
	}
	planLabel := o.Plan
	if p, ok := a.effectivePlans(r.Context())[o.Plan]; ok {
		planLabel = p.Label
	}
	// Best-effort merchant name (defaults to "WiFi 上网计费" if not set).
	merchant := "WiFi 上网计费服务"
	if a.Cfg.SSIDs.Paid != "" {
		merchant = fmt.Sprintf("WiFi: %s", a.Cfg.SSIDs.Paid)
	}
	a.render(w, "receipt.html", map[string]any{
		"Order":     o,
		"PlanLabel": planLabel,
		"Merchant":  merchant,
		"AmtYuan":   fmt.Sprintf("%d.%02d", o.AmountCents/100, o.AmountCents%100),
	})
}
