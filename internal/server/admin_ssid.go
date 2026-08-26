package server

import (
	"bytes"
	"image/png"
	"net/http"
	"strings"

	"rsc.io/qr"

	"router-billing/internal/config"
)

// SSID join QR follows the de-facto Wi-Fi QR convention:
//
//	WIFI:T:<auth>;S:<ssid>;P:<password>;H:<hidden>;;
//
// nopassword → T:nopass, omit P
//
// Most modern phones recognize it from the camera.
func wifiQRPayload(ssid, password string, hidden bool) string {
	var b strings.Builder
	b.WriteString("WIFI:")
	if password == "" {
		b.WriteString("T:nopass;S:")
		b.WriteString(escapeWifi(ssid))
		b.WriteString(";")
	} else {
		b.WriteString("T:WPA;S:")
		b.WriteString(escapeWifi(ssid))
		b.WriteString(";P:")
		b.WriteString(escapeWifi(password))
		b.WriteString(";")
	}
	if hidden {
		b.WriteString("H:true;")
	}
	b.WriteString(";")
	return b.String()
}

func escapeWifi(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `;`, `\;`, `,`, `\,`, `"`, `\"`, `:`, `\:`)
	return r.Replace(s)
}

type ssidCard struct {
	Title       string
	SSID        string
	HasPassword bool
	Password    string
	Tip         string
	QRPath      string
}

// GET /admin/ssid-cards — printable cards: scan-to-join QR for each SSID.
func (a *App) handleAdminSSIDCards(w http.ResponseWriter, r *http.Request) {
	info := a.effectiveSSIDs()
	// Free SSID is now the friends + management WiFi (WPA2-encrypted).
	// Render its key on the card so the admin can hand the printed slip
	// to family/staff without typing the password manually.
	freeCard := ssidCard{
		Title:  "熟人 / 管理 WiFi（加密）",
		SSID:   info.Free,
		Tip:    "信任的人才连这个 · 管理员也用这个进 /admin",
		QRPath: "/admin/ssid-cards/qr?card=free",
	}
	if info.FreeKey != "" {
		freeCard.HasPassword = true
		freeCard.Password = info.FreeKey
	}
	cards := []ssidCard{
		freeCard,
		{
			Title:  "付费 WiFi（开放，扫码付）",
			SSID:   info.Paid,
			Tip:    "客户连这个 · 浏览器自动跳付费页",
			QRPath: "/admin/ssid-cards/qr?card=paid",
		},
	}
	if info.PaidKey != "" {
		cards = append(cards, ssidCard{
			Title:       "VIP 付费 WiFi（加密）",
			SSID:        info.PaidSecure,
			HasPassword: true,
			Password:    info.PaidKey,
			Tip:         "VIP 客户：已付费设备 + 知道密码才能连",
			QRPath:      "/admin/ssid-cards/qr?card=secure",
		})
	}

	// Portal QR for the user dashboard
	portal := a.Cfg.PortalBase() + "/user/login"
	cards = append(cards, ssidCard{
		Title:  "已注册账号？扫码登录",
		SSID:   portal,
		Tip:    "在已有任意网络下扫码进入账号管理",
		QRPath: "/admin/ssid-cards/qr?card=portal",
	})

	a.render(w, "admin_ssid_cards.html", a.adminCtx(r, "ssid-cards", map[string]any{
		"Cards":  cards,
		"Portal": portal,
	}))
}

// effectiveSSIDs is the config SSID block with the documented defaults
// applied — shared by the cards page and the QR endpoint so both render
// the same names.
func (a *App) effectiveSSIDs() config.SSIDInfo {
	info := a.Cfg.SSIDs
	if info.Free == "" {
		info.Free = "Free_WiFi"
	}
	if info.Paid == "" {
		info.Paid = "Paid_WiFi"
	}
	if info.PaidSecure == "" {
		info.PaidSecure = "Paid_Secure_WiFi"
	}
	return info
}

// GET /admin/ssid-cards/qr?card=free|paid|secure|portal  → PNG
//
// The payload is resolved server-side from config. The previous shape
// (?ssid=&password= / ?url=) had three problems for the price of one
// endpoint: the WiFi passphrase rode in a GET query string (browser
// history, any intermediary access logs), the PNG was served with
// `Cache-Control: public` so a shared cache could store an
// authenticated admin response containing that passphrase, and free
// ssid/url parameters made it an open QR encoder on our origin for any
// admin-session CSRF-less GET (phishing-aid, same class as the v0.103
// /api/pay/qr fix).
func (a *App) handleAdminSSIDCardQR(w http.ResponseWriter, r *http.Request) {
	info := a.effectiveSSIDs()
	var payload string
	switch r.URL.Query().Get("card") {
	case "free":
		payload = wifiQRPayload(info.Free, info.FreeKey, false)
	case "paid":
		payload = wifiQRPayload(info.Paid, "", false)
	case "secure":
		payload = wifiQRPayload(info.PaidSecure, info.PaidKey, false)
	case "portal":
		payload = a.Cfg.PortalBase() + "/user/login"
	default:
		http.Error(w, "unknown card", http.StatusBadRequest)
		return
	}
	code, err := qr.Encode(payload, qr.M)
	if err != nil {
		http.Error(w, "qr: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, code.Image()); err != nil {
		http.Error(w, "png: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	// The free/secure PNGs encode live WiFi passphrases — never cacheable
	// beyond the private browser session (same rationale as the v0.112
	// voucher-QR fix).
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}
