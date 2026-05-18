package server

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"router-billing/internal/models"
)

func TestAdminMACRevokeSetsBlockedStatus(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:E0:01", "before-revoke", 30, nil); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/macs/revoke",
		url.Values{"_csrf": {csrf}, "mac": {"AA:BB:CC:DD:E0:01"}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}

	m, _ := app.DB.GetMAC(ctx, "AA:BB:CC:DD:E0:01")
	if m == nil {
		t.Fatal("MAC row should still exist after revoke")
	}
	if m.Status != models.MACBlocked {
		t.Errorf("status = %s; want blocked", m.Status)
	}
}

func TestAdminMACRevokeIsAudited(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:E0:02", "", 30, nil)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	do(t, h, "POST", "/admin/macs/revoke",
		url.Values{"_csrf": {csrf}, "mac": {"AA:BB:CC:DD:E0:02"}}, jar)

	entries, _ := app.DB.ListAudit(ctx, 50)
	found := false
	for _, e := range entries {
		if e.Action == "revoke" && e.Target == "AA:BB:CC:DD:E0:02" {
			found = true
		}
	}
	if !found {
		t.Error("revoke should create audit entry")
	}
}

func TestAdminMACRevokeRejectsInvalidMAC(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/macs/revoke",
		url.Values{"_csrf": {csrf}, "mac": {"not-a-mac"}}, jar)
	if !strings.Contains(res.Header.Get("Location"), "invalid_mac") {
		t.Errorf("bad mac should err=invalid_mac; got %s", res.Header.Get("Location"))
	}
}

func TestAdminMACsListHidesRevokeForBlocked(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:DD:E0:03", "", 30, nil)
	// Mark as blocked directly.
	if err := app.DB.SetMACStatus(ctx, "AA:BB:CC:DD:E0:03", models.MACBlocked); err != nil {
		t.Fatal(err)
	}

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/macs?q=E0:03", nil, jar)
	// The 封禁 button is only shown when status != blocked.
	rowStart := strings.Index(body, "AA:BB:CC:DD:E0:03")
	if rowStart < 0 {
		t.Fatal("page missing the blocked MAC")
	}
	// Look at the slice from this MAC through the next 1000 chars — should
	// be the row's action buttons. Should NOT contain a revoke form.
	slice := body[rowStart:]
	if end := strings.Index(slice, "</tr>"); end > 0 {
		slice = slice[:end]
	}
	if strings.Contains(slice, `action="/admin/macs/revoke"`) {
		t.Error("revoke form should be hidden for already-blocked MAC")
	}
}
