package server

import (
	"bytes"
	"fmt"
	"image/png"
	"net/http"
	"strings"

	"rsc.io/qr"
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
	// Free SSID is now the friends + management WiFi (WPA2-encrypted).
	// Render its key on the card so the admin can hand the printed slip
	// to family/staff without typing the password manually.
	freeCard := ssidCard{
		Title:  "熟人 / 管理 WiFi（加密）",
		SSID:   info.Free,
		Tip:    "信任的人才连这个 · 管理员也用这个进 /admin",
		QRPath: fmt.Sprintf("/admin/ssid-cards/qr?ssid=%s", urlQ(info.Free)),
	}
	if info.FreeKey != "" {
		freeCard.HasPassword = true
		freeCard.Password = info.FreeKey
		freeCard.QRPath = fmt.Sprintf("/admin/ssid-cards/qr?ssid=%s&password=%s",
			urlQ(info.Free), urlQ(info.FreeKey))
	}
	cards := []ssidCard{
		freeCard,
		{
			Title:  "付费 WiFi（开放，扫码付）",
			SSID:   info.Paid,
			Tip:    "客户连这个 · 浏览器自动跳付费页",
			QRPath: fmt.Sprintf("/admin/ssid-cards/qr?ssid=%s", urlQ(info.Paid)),
		},
	}
	if info.PaidKey != "" {
		cards = append(cards, ssidCard{
			Title:       "VIP 付费 WiFi（加密）",
			SSID:        info.PaidSecure,
			HasPassword: true,
			Password:    info.PaidKey,
			Tip:         "VIP 客户：已付费设备 + 知道密码才能连",
			QRPath: fmt.Sprintf("/admin/ssid-cards/qr?ssid=%s&password=%s",
				urlQ(info.PaidSecure), urlQ(info.PaidKey)),
		})
	}

	// Portal QR for the user dashboard
	portal := a.Cfg.PortalBase() + "/user/login"
	cards = append(cards, ssidCard{
		Title:  "已注册账号？扫码登录",
		SSID:   portal,
		Tip:    "在已有任意网络下扫码进入账号管理",
		QRPath: "/admin/ssid-cards/qr?url=" + urlQ(portal),
	})

	a.render(w, "admin_ssid_cards.html", a.adminCtx(r, "ssid-cards", map[string]any{
		"Cards":  cards,
		"Portal": portal,
	}))
}

// GET /admin/ssid-cards/qr?ssid=...&password=...  → PNG
// or  /admin/ssid-cards/qr?url=...
func (a *App) handleAdminSSIDCardQR(w http.ResponseWriter, r *http.Request) {
	var payload string
	if u := r.URL.Query().Get("url"); u != "" {
		payload = u
	} else {
		ssid := r.URL.Query().Get("ssid")
		if ssid == "" {
			http.Error(w, "missing ssid or url", http.StatusBadRequest)
			return
		}
		payload = wifiQRPayload(ssid, r.URL.Query().Get("password"), false)
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
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(buf.Bytes())
}

func urlQ(s string) string {
	return (&urlEscaper{s}).String()
}

type urlEscaper struct{ s string }

func (e *urlEscaper) String() string {
	// minimal escape; enough for SSID/password embedded in our own URL
	var b strings.Builder
	for _, r := range e.s {
		switch r {
		case '&', '?', '#', '=', ' ', '+', '%':
			b.WriteString(fmt.Sprintf("%%%02X", r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
