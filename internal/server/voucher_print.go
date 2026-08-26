package server

import (
	"bytes"
	"image/png"
	"net/http"
	"strings"

	"router-billing/internal/voucher"

	"rsc.io/qr"
)

// GET /admin/vouchers/print?batch=...
// Renders printable cards (8 per A4). Each card has the 4-4-4 code + a QR
// that opens /redeem?code=... on the router's portal IP.
func (a *App) handleAdminVouchersPrint(w http.ResponseWriter, r *http.Request) {
	batch := r.URL.Query().Get("batch")
	list, err := a.DB.ListVouchers(r.Context(), batch, 1000)
	if err != nil {
		http.Error(w, "db", http.StatusInternalServerError)
		return
	}
	// Only print usable ones (not redeemed/revoked/expired).
	var usable []map[string]string
	portal := a.Cfg.PortalBase()
	for _, v := range list {
		if v.Revoked || v.RedeemedAt != nil {
			continue
		}
		usable = append(usable, map[string]string{
			"Code":   v.Code,
			"Pretty": voucher.Pretty(v.Code),
			"Days":   itoa(v.Days),
			"Batch":  v.Batch,
			"QRPath": "/admin/vouchers/print/qr?code=" + v.Code,
		})
	}
	a.render(w, "admin_vouchers_print.html", map[string]any{
		"Vouchers": usable,
		"Batch":    batch,
		"Portal":   portal,
		"Count":    len(usable),
	})
}

// GET /admin/vouchers/print/qr?code=XXXXX → PNG of a QR pointing at /redeem
func (a *App) handleAdminVouchersPrintQR(w http.ResponseWriter, r *http.Request) {
	code := voucher.Canon(r.URL.Query().Get("code"))
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	payload := a.Cfg.PortalBase() + "/redeem?code=" + code
	c, err := qr.Encode(payload, qr.M)
	if err != nil {
		http.Error(w, "qr: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, c.Image()); err != nil {
		http.Error(w, "png: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	// no-store, NOT "public": the PNG encodes a full unredeemed voucher
	// code (bearer value — anyone holding it gets the paid days). "public"
	// explicitly invited shared proxy caches to store an authenticated
	// admin response, and left the codes sitting in browser disk cache
	// after the admin walks away from a shared machine.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func itoa(n int) string {
	// tiny shim to avoid pulling strconv just for one call inside templates
	var b strings.Builder
	if n == 0 {
		return "0"
	}
	if n < 0 {
		b.WriteByte('-')
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	b.Write(digits)
	return b.String()
}
