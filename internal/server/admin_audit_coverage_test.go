package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestAdminMACExtendIsAudited(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	// Seed a MAC.
	if _, err := app.DB.UpsertMAC(context.Background(), "AA:BB:CC:DD:EE:99", "test", 30, nil); err != nil {
		t.Fatal(err)
	}

	res, _ := do(t, h, "POST", "/admin/macs/extend",
		url.Values{
			"_csrf": {csrf},
			"mac":   {"AA:BB:CC:DD:EE:99"},
			"days":  {"30"},
		}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("extend: %d", res.StatusCode)
	}

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "extend" && e.Target == "AA:BB:CC:DD:EE:99" {
			found = true
			if !strings.Contains(e.Detail, "days=30") {
				t.Errorf("audit detail should include days=30; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("admin/macs/extend should create an audit entry")
	}
}

func TestAdminFirewallResyncIsAudited(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := loginAdmin(t, h)
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/admin/resync",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("resync: %d", res.StatusCode)
	}

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "firewall_resync" {
			found = true
			if !strings.Contains(e.Detail, "ip=") {
				t.Errorf("audit should include IP; got %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("/admin/resync should create a firewall_resync audit entry")
	}
}
