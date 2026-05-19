package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPIMACGetHappyPath(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	u, _ := app.DB.CreateUser(ctx, "13800390001", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:22:01", "phone", 30, &u.ID)
	now := time.Now().UTC()
	_, _ = app.DB.Exec(ctx, `INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen)
		VALUES ('AA:BB:CC:00:22:01', '192.168.5.30', 'support-phone', ?, ?)`, now.Add(-1*time.Hour), now)
	_, _ = app.DB.Exec(ctx, `INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, paid_at, created_at)
		VALUES ('MAC-GET-1', 'AA:BB:CC:00:22:01', 'm', 30, 500, 'paid', 'wechat', ?, ?, ?)`, u.ID, now, now)
	app.DB.Audit(ctx, "admin", "grant", "AA:BB:CC:00:22:01", "days=30 via=ui")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs/get?mac=AA:BB:CC:00:22:01", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Mac struct {
			Mac string `json:"mac"`
		} `json:"mac"`
		Owner struct {
			Phone       string `json:"phone"`
			TOTPEnabled bool   `json:"totp_enabled"`
		} `json:"owner"`
		Sighting struct {
			Hostname string `json:"hostname"`
		} `json:"sighting"`
		Orders []struct {
			OrderNo string `json:"order_no"`
		} `json:"orders"`
		Audit []struct {
			Action string `json:"action"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Mac.Mac != "AA:BB:CC:00:22:01" {
		t.Errorf("mac echo wrong: %q", resp.Mac.Mac)
	}
	if resp.Owner.Phone != "13800390001" {
		t.Errorf("owner phone wrong: %q", resp.Owner.Phone)
	}
	if resp.Sighting.Hostname != "support-phone" {
		t.Errorf("sighting hostname wrong: %q", resp.Sighting.Hostname)
	}
	if len(resp.Orders) == 0 || resp.Orders[0].OrderNo != "MAC-GET-1" {
		t.Errorf("orders missing: %+v", resp.Orders)
	}
	auditFound := false
	for _, a := range resp.Audit {
		if a.Action == "grant" {
			auditFound = true
		}
	}
	if !auditFound {
		t.Error("audit timeline missing grant row")
	}
}

func TestAPIMACGetNormalizesInput(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:22:02", "phone", 30, nil)
	h := app.Routes()
	// Lowercase + dashes should normalize to the canonical row.
	rr := apiReq(t, h, "GET", "/api/admin/macs/get?mac=aa-bb-cc-00-22-02", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAPIMACGetMissingParam(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs/get", "rb_w", "")
	if rr.Code != 400 {
		t.Errorf("missing mac should be 400; got %d", rr.Code)
	}
}

func TestAPIMACGetBadMAC400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs/get?mac=NOT-A-MAC", "rb_w", "")
	if rr.Code != 400 {
		t.Errorf("bad mac should be 400; got %d", rr.Code)
	}
}

func TestAPIMACGetNotFound(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs/get?mac=AA:BB:CC:DD:EE:00", "rb_w", "")
	if rr.Code != 404 {
		t.Errorf("missing mac should be 404; got %d", rr.Code)
	}
}

// Anti-leak red-line: owner field must not include password_hash/totp_secret.
func TestAPIMACGetNoSensitiveOwnerFields(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800390009", "super-secret-hash")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:22:09", "phone", 30, &u.ID)
	_, _ = app.DB.Exec(ctx, `UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP' WHERE id = ?`, u.ID)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/macs/get?mac=AA:BB:CC:00:22:09", "rb_w", "")
	body := rr.Body.String()
	for _, banned := range []string{"password_hash", "super-secret-hash", "totp_secret", "JBSWY3DPEHPK3PXP"} {
		if strings.Contains(body, banned) {
			t.Errorf("response leaks %q: %s", banned, body)
		}
	}
}
