package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"router-billing/internal/arp"
	"router-billing/internal/models"

	"rsc.io/qr"
)

type portalData struct {
	MAC        string
	DetectedOK bool
	Plans      []planView
	WeChatOn   bool
	AlipayOn   bool
	LoggedIn   bool
}

type planView struct {
	Key   string
	Label string
	Days  int
	Yuan  string
}

func (a *App) handlePortal(w http.ResponseWriter, r *http.Request) {
	mac := a.detectMAC(r)
	// ?mac=XX:XX overrides detection (e.g. "renew this MAC" link from /user/me).
	if q := r.URL.Query().Get("mac"); q != "" {
		if norm, ok := models.NormalizeMAC(q); ok {
			mac = norm
		}
	}
	loggedIn := a.currentUserID(r) != 0
	data := portalData{
		MAC:        mac,
		DetectedOK: mac != "",
		Plans:      a.planViews(r.Context()),
		WeChatOn:   a.WeChat != nil,
		AlipayOn:   a.Alipay != nil,
		LoggedIn:   loggedIn,
	}
	a.render(w, "portal.html", data)
}

func (a *App) planViews(ctx context.Context) []planView {
	plans := a.effectivePlans(ctx)
	var out []planView
	for _, k := range a.effectivePlanKeys(ctx) {
		p := plans[k]
		out = append(out, planView{
			Key:   k,
			Label: p.Label,
			Days:  p.Days,
			Yuan:  fmt.Sprintf("%d.%02d", p.PriceCents/100, p.PriceCents%100),
		})
	}
	return out
}

// detectMAC resolves remote IP → MAC via `ip neigh`. Returns "" on failure.
func (a *App) detectMAC(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" || strings.HasPrefix(host, "127.") || host == "::1" {
		return ""
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	mac, err := arp.Lookup(ctx, host)
	if err != nil {
		log.Printf("arp lookup for %s: %v", host, err)
		return ""
	}
	return mac
}

// /api/me returns current detected MAC + active expiry if any.
func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	mac := a.detectMAC(r)
	resp := map[string]any{"mac": mac}
	if mac != "" {
		m, err := a.DB.GetMAC(r.Context(), mac)
		if err == nil && m != nil && m.Status == models.MACActive && m.ExpiresAt.After(time.Now()) {
			resp["expires_at"] = m.ExpiresAt
			resp["active"] = true
		} else {
			resp["active"] = false
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// /pay/success — shown after polling sees status=paid.
func (a *App) handlePaySuccess(w http.ResponseWriter, r *http.Request) {
	mac := ""
	// Normalize the ?mac= override — DB rows store the canonical
	// uppercase-colon form, so a lowercase query param would otherwise
	// miss both the MAC row and the receipt lookup.
	if q := r.URL.Query().Get("mac"); q != "" {
		if norm, ok := models.NormalizeMAC(q); ok {
			mac = norm
		}
	}
	if mac == "" {
		mac = a.detectMAC(r)
	}
	var m *models.MAC
	if mac != "" {
		mm, _ := a.DB.GetMAC(r.Context(), mac)
		m = mm
	}
	// Find the most recent paid order for this MAC so we can offer a receipt link.
	var receiptOrderNo string
	if mac != "" {
		if o, _ := a.DB.LatestPaidOrderForMAC(r.Context(), mac); o != nil {
			receiptOrderNo = o.OrderNo
		}
	}
	a.render(w, "success.html", map[string]any{
		"MAC":            mac,
		"Row":            m,
		"ReceiptOrderNo": receiptOrderNo,
	})
}

// /api/pay/qr?order_no=... — returns the QR as PNG so the browser <img> can show it.
//
// The QR payload comes from the order row, NOT from the URL — pre-v0.97
// we accepted ?payload=... directly which made this endpoint an open QR
// encoder for anyone holding any valid order_no (e.g. stamp a phishing
// URL into a QR served from our domain). Now we read o.QRPayload, which
// was stored at /api/pay/create time.
func (a *App) handlePayQR(w http.ResponseWriter, r *http.Request) {
	orderNo := r.URL.Query().Get("order_no")
	if orderNo == "" {
		http.Error(w, "missing order_no", http.StatusBadRequest)
		return
	}
	o, err := a.DB.GetOrder(r.Context(), orderNo)
	if err != nil || o == nil {
		http.Error(w, "order not found", http.StatusNotFound)
		return
	}
	// Mid-upgrade safety net: a pending order created by an old binary
	// won't have qr_payload populated. The /api/pay/create response in
	// new-server clients carries the QR payload directly so the page can
	// render client-side; this fallback path 404s cleanly rather than
	// echoing a URL-supplied string.
	if o.QRPayload == "" {
		http.Error(w, "qr unavailable for this order", http.StatusNotFound)
		return
	}
	code, err := qr.Encode(o.QRPayload, qr.M)
	if err != nil {
		http.Error(w, "qr encode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	img := code.Image()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		http.Error(w, "png encode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// --- helpers ---

// render executes the named template into a bytes.Buffer first, then copies
// the buffer to w only on success. This matters because ExecuteTemplate may
// emit some bytes before erroring out (e.g. on a typo'd struct field
// halfway through a table). With a direct ResponseWriter the user got
//
//	HTTP 200 + "<table>...<td>month</td><td>internal\n"
//
// — partial HTML, an implicit 200 from the first Write, and the failed
// http.Error(500) silently downgraded to a Write of "internal\n" (plus
// "superfluous WriteHeader" log spam). Buffering means template errors
// always produce a clean 500 with no leaked partial output.
//
// Headers are set after Execute succeeds so that on error the user gets
// the text/plain content-type that http.Error provides.
func (a *App) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := a.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
