package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// User detail should surface MAC notes inline for each device the user
// owns, so support gets the customer context one-screen.
func TestAdminUserDetailShowsMACNotesInline(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800420001", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:2A:01", "phone", 30, &u.ID)
	_ = app.DB.SetMACNotes(ctx, "AA:BB:CC:00:2A:01", "VIP — escalate any issue")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:2A:02", "no-notes", 30, &u.ID)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/users/detail?id="+strconv.FormatInt(u.ID, 10), nil, jar)

	if !strings.Contains(body, "VIP — escalate any issue") {
		t.Error("MAC notes should appear inline on user detail")
	}
	if !strings.Contains(body, "📝") {
		t.Error("notes marker missing")
	}
}

// User detail MAC cells now link to /admin/macs/detail (cross-link parity).
func TestAdminUserDetailMACLinksToDetailPage(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800420002", "h")
	_, _ = app.DB.UpsertMAC(ctx, "AA:BB:CC:00:2A:05", "linked", 30, &u.ID)
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/users/detail?id="+strconv.FormatInt(u.ID, 10), nil, jar)
	if !strings.Contains(body, "/admin/macs/detail?mac=AA:BB:CC:00:2A:05") &&
		!strings.Contains(body, "/admin/macs/detail?mac=AA%3aBB%3aCC%3a00%3a2A%3a05") &&
		!strings.Contains(body, "/admin/macs/detail?mac=AA%3ABB%3ACC%3A00%3A2A%3A05") {
		t.Error("MAC cells should link to /admin/macs/detail")
	}
}
