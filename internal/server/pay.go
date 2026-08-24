package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"router-billing/internal/models"
	"router-billing/internal/notify"
	"router-billing/internal/pay"
)

type payCreateReq struct {
	MAC      string `json:"mac"`
	Plan     string `json:"plan"`
	Provider string `json:"provider"` // wechat | alipay
}

type payCreateResp struct {
	OrderNo string `json:"order_no"`
	QRCode  string `json:"qr_code"`
	QRPNG   string `json:"qr_png"`
	Amount  string `json:"amount"`
	Plan    string `json:"plan"`
	Days    int    `json:"days"`
}

// POST /api/pay/create  {mac, plan, provider}
func (a *App) handlePayCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	// Cheap defense against payment-intent flood from a single source — both
	// WeChat and Alipay rate-limit downstream, but every flood-create costs
	// us a sqlite write + outbound HTTPS roundtrip. 20/min/IP is generous
	// for the worst legitimate user (fat-finger reload spam).
	if a.payCreateLimiter != nil && !a.payCreateLimiter.allow(a.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "请求过于频繁，请稍候再试",
		})
		return
	}
	var req payCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.MAC == "" {
		req.MAC = a.detectMAC(r)
	}
	mac, ok := models.NormalizeMAC(req.MAC)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "无法识别 MAC 地址，请刷新页面或手动输入"})
		return
	}
	plan, ok := a.effectivePlans(r.Context())[req.Plan]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "未知套餐"})
		return
	}

	// If the request carries a user session cookie, link the order to that user.
	var userID *int64
	if c, _ := r.Cookie(userCookieName); c != nil && c.Value != "" {
		if sess, _ := a.DB.GetSession(r.Context(), c.Value); sess != nil && sess.Kind == "user" {
			userID = sess.UserID
		}
	}

	orderNo := newOrderNo()
	order := &models.Order{
		OrderNo:       orderNo,
		Mac:           mac,
		Plan:          req.Plan,
		Days:          plan.Days,
		AmountCents:   plan.PriceCents,
		Status:        models.OrderPending,
		PaymentMethod: strings.ToLower(req.Provider),
		UserID:        userID,
	}
	if err := a.DB.CreateOrder(r.Context(), order); err != nil {
		log.Printf("create order: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "数据库错误"})
		return
	}

	subject := fmt.Sprintf("路由器上网-%s-%s", plan.Label, mac)
	var qrPayload string

	switch order.PaymentMethod {
	case "wechat":
		if a.WeChat == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "微信支付未启用"})
			return
		}
		res, err := a.WeChat.Precreate(r.Context(), orderNo, subject, plan.PriceCents)
		if err != nil {
			log.Printf("wechat precreate: %v", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "微信下单失败"})
			return
		}
		qrPayload = res.QRCode
	case "alipay":
		if a.Alipay == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "支付宝支付未启用"})
			return
		}
		res, err := a.Alipay.Precreate(r.Context(), orderNo, subject, plan.PriceCents)
		if err != nil {
			log.Printf("alipay precreate: %v", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "支付宝下单失败"})
			return
		}
		qrPayload = res.QRCode
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "未知支付方式"})
		return
	}

	writeJSON(w, http.StatusOK, payCreateResp{
		OrderNo: orderNo,
		QRCode:  qrPayload,
		QRPNG:   fmt.Sprintf("/api/pay/qr?order_no=%s&payload=%s", orderNo, url.QueryEscape(qrPayload)),
		Amount:  fmt.Sprintf("%d.%02d", plan.PriceCents/100, plan.PriceCents%100),
		Plan:    req.Plan,
		Days:    plan.Days,
	})
}

// GET /api/pay/status?order_no=...
// Opportunistically queries upstream if pending — gives us a webhook-free path.
func (a *App) handlePayStatus(w http.ResponseWriter, r *http.Request) {
	orderNo := r.URL.Query().Get("order_no")
	if orderNo == "" {
		http.Error(w, "missing order_no", http.StatusBadRequest)
		return
	}
	o, err := a.DB.GetOrder(r.Context(), orderNo)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	if o == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if o.Status == models.OrderPending && a.shouldQueryNow(o) {
		a.queryOrder(r.Context(), *o)
		// re-read after possible mutation
		if o2, err := a.DB.GetOrder(r.Context(), orderNo); err == nil && o2 != nil {
			o = o2
		}
	}
	resp := map[string]any{
		"order_no": o.OrderNo,
		"status":   o.Status,
		"mac":      o.Mac,
	}
	if o.Status == models.OrderPaid {
		if mm, _ := a.DB.GetMAC(r.Context(), o.Mac); mm != nil {
			resp["expires_at"] = mm.ExpiresAt
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) shouldQueryNow(o *models.Order) bool {
	if o.LastQueriedAt == nil {
		return true
	}
	return time.Since(*o.LastQueriedAt) > 2*time.Second
}

// queryOrder hits the upstream PSP and (if SUCCESS) finalizes.
// Safe to call from both the periodic poller and the on-demand /status handler.
func (a *App) queryOrder(ctx context.Context, o models.Order) {
	var notice *pay.PaidNotice
	var paid bool
	var err error
	switch o.PaymentMethod {
	case "wechat":
		if a.WeChat == nil {
			return
		}
		notice, paid, err = a.WeChat.Query(ctx, o.OrderNo)
	case "alipay":
		if a.Alipay == nil {
			return
		}
		notice, paid, err = a.Alipay.Query(ctx, o.OrderNo)
	default:
		return
	}
	_ = a.DB.MarkOrderQueried(ctx, o.OrderNo)
	if err != nil {
		log.Printf("pay-query %s/%s: %v", o.PaymentMethod, o.OrderNo, err)
		return
	}
	if !paid {
		return
	}
	if err := a.finalizeOrder(ctx, notice.OrderNo, notice.TradeNo); err != nil {
		log.Printf("pay-query finalize %s: %v", notice.OrderNo, err)
	}
}

// PollPendingOrders runs in the background. Picks up pending orders whose
// last upstream query is stale and queries them. This gives us a working
// payment flow even without an HTTPS webhook URL.
func (a *App) PollPendingOrders(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 4 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.pollOnce(ctx)
		}
	}
}

func (a *App) pollOnce(ctx context.Context) {
	orders, err := a.DB.ListPendingOrdersToPoll(ctx, 3*time.Second, 30*time.Minute, 50)
	if err != nil {
		log.Printf("pay-poll: list: %v", err)
		return
	}
	for _, o := range orders {
		a.queryOrder(ctx, o)
	}
}

// POST /notify/wx
func (a *App) handleNotifyWeChat(w http.ResponseWriter, r *http.Request) {
	if a.WeChat == nil {
		http.Error(w, "disabled", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	// Verify the Wechatpay-Signature header (proves call is from WeChat) BEFORE
	// trusting the body. Soft-fail on header verification — if the platform
	// cert fetch failed, we still have AES-GCM body authentication. Log loudly.
	if err := a.WeChat.VerifyNotifyHeaders(r.Context(), r.Header, body); err != nil {
		log.Printf("wechat notify header verify failed (still trying AES-GCM): %v", err)
	}
	notice, err := a.WeChat.DecodeNotify(body)
	if err != nil {
		log.Printf("wechat notify decode: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "FAIL", "message": err.Error()})
		return
	}
	if err := a.finalizeOrder(r.Context(), notice.OrderNo, notice.TradeNo); err != nil {
		log.Printf("wechat finalize %s: %v", notice.OrderNo, err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "FAIL", "message": err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": "SUCCESS"})
}

// POST /notify/ali
func (a *App) handleNotifyAlipay(w http.ResponseWriter, r *http.Request) {
	if a.Alipay == nil {
		http.Error(w, "disabled", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	notice, err := a.Alipay.DecodeNotify(r.PostForm)
	if err != nil {
		log.Printf("alipay notify decode: %v", err)
		_, _ = w.Write([]byte("failure"))
		return
	}
	if err := a.finalizeOrder(r.Context(), notice.OrderNo, notice.TradeNo); err != nil {
		log.Printf("alipay finalize %s: %v", notice.OrderNo, err)
		_, _ = w.Write([]byte("failure"))
		return
	}
	_, _ = w.Write([]byte("success"))
}

// finalizeOrder marks the order paid and grants the MAC. Idempotent.
func (a *App) finalizeOrder(ctx context.Context, orderNo, tradeNo string) error {
	a.pollMu.Lock()
	defer a.pollMu.Unlock()

	transitioned, order, err := a.DB.MarkOrderPaid(ctx, orderNo, tradeNo)
	if err != nil {
		return err
	}
	if !transitioned {
		return nil
	}
	if err := a.MACSvc.GrantFromOrder(ctx, order); err != nil {
		return err
	}
	// Wake any browser long-polling /api/pay/wait for this order.
	a.signalOrder(orderNo)
	a.DB.Audit(ctx, "webhook:"+order.PaymentMethod, "pay", order.Mac,
		fmt.Sprintf("order=%s amount=%d", order.OrderNo, order.AmountCents))
	uid := int64(0)
	if order.UserID != nil {
		uid = *order.UserID
	}
	a.Notifier.Send(notify.Event{
		Type:    "pay",
		Actor:   order.PaymentMethod,
		MAC:     order.Mac,
		UserID:  uid,
		Amount:  order.AmountCents,
		Days:    order.Days,
		OrderNo: order.OrderNo,
	})
	return nil
}

func newOrderNo() string {
	u := strings.ReplaceAll(uuid.NewString(), "-", "")
	return "B" + time.Now().UTC().Format("20060102150405") + u[:8]
}
