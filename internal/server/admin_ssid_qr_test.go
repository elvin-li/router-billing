package server

import (
	"strings"
	"testing"
)

// Regression (v0.113): /admin/ssid-cards/qr resolved its payload from
// ?ssid=&password= / ?url= query parameters and served the PNG with
// `Cache-Control: public`. That put the WiFi passphrase in GET query
// strings (history, access logs), let shared caches store an
// authenticated response containing it, and made the endpoint an open
// QR encoder on our origin. The payload now comes from config via an
// enum ?card= parameter and the PNG is no-store.
func TestAdminSSIDCardQRServerSidePayloadNoStore(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, body := do(t, h, "GET", "/admin/ssid-cards/qr?card=paid", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("card=paid: %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("content-type = %q", ct)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (PNG can embed WiFi passphrases)", cc)
	}
	if !strings.HasPrefix(body, "\x89PNG") {
		t.Error("response is not a PNG")
	}

	// The portal card renders too.
	res, _ = do(t, h, "GET", "/admin/ssid-cards/qr?card=portal", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("card=portal: %d", res.StatusCode)
	}

	// Arbitrary payloads are rejected — no open QR encoder.
	for _, q := range []string{
		"url=https://evil.example/phish",
		"ssid=Evil_WiFi&password=stolen",
		"card=nope",
		"",
	} {
		res, _ := do(t, h, "GET", "/admin/ssid-cards/qr?"+q, nil, jar)
		if res.StatusCode != 400 {
			t.Errorf("query %q: got %d, want 400", q, res.StatusCode)
		}
	}
}

// The printable cards page must reference only the enum QR paths — a
// regression back to ?password= would put the passphrase in every access
// log line the <img> fetch produces.
func TestAdminSSIDCardsPageUsesEnumQRPaths(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)

	res, body := do(t, h, "GET", "/admin/ssid-cards", nil, jar)
	if res.StatusCode != 200 {
		t.Fatalf("ssid-cards: %d", res.StatusCode)
	}
	if strings.Contains(body, "password=") {
		t.Error("cards page embeds a password= query parameter")
	}
	if !strings.Contains(body, "/admin/ssid-cards/qr?card=") {
		t.Error("cards page should reference the enum QR endpoint")
	}
}
