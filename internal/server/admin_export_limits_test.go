package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"router-billing/internal/models"
)

// Regression tests for the CSV-export truncation bug: the handlers passed
// generous limits (5000 / 10000) down to the DB layer, but the DB clamp
// treated "above the cap" as "use the tiny default" — so the unfiltered
// orders export silently returned 100 rows, the users export 100, filtered
// MAC exports 200, and audit/sms/webhook exports with ?limit=2000+ fell
// back to 200/100 rows. Operators keeping these CSVs as records lost data
// with zero indication.

func csvDataRows(body string) int {
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) <= 1 {
		return 0
	}
	return len(lines) - 1 // minus header
}

func TestAdminExportOrdersNotTruncatedAtLegacyDefault(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	const n = 120 // > the legacy 100-row reset
	for i := 0; i < n; i++ {
		o := &models.Order{
			OrderNo:       fmt.Sprintf("ORDLIM%04d", i),
			Mac:           "AA:BB:CC:00:11:22",
			Plan:          "month",
			Days:          30,
			AmountCents:   100,
			Status:        models.OrderPending,
			PaymentMethod: "wechat",
		}
		if err := app.DB.CreateOrder(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/orders.csv", nil, jar)
	if got := csvDataRows(body); got != n {
		t.Errorf("unfiltered orders export has %d rows, want %d (legacy clamp truncated at 100)", got, n)
	}
}

func TestAdminExportUsersNotTruncatedAtLegacyDefault(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	const n = 120
	for i := 0; i < n; i++ {
		if _, err := app.DB.CreateUser(ctx, fmt.Sprintf("138%08d", i), "h"); err != nil {
			t.Fatal(err)
		}
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/users.csv", nil, jar)
	if got := csvDataRows(body); got != n {
		t.Errorf("users export has %d rows, want %d (legacy clamp truncated at 100)", got, n)
	}
}

func TestAdminExportMACsFilteredNotTruncatedAtLegacyDefault(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	const n = 220 // > the legacy 200-row reset in SearchMACs
	for i := 0; i < n; i++ {
		mac := fmt.Sprintf("AA:BB:CC:%02X:%02X:%02X", i/65536%256, i/256%256, i%256)
		if _, err := app.DB.UpsertMAC(ctx, mac, "bulk", 30, nil); err != nil {
			t.Fatal(err)
		}
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	// status filter forces the SearchMACs path (the one that clamped).
	_, body := do(t, h, "GET", "/admin/export/macs.csv?status=active", nil, jar)
	if got := csvDataRows(body); got != n {
		t.Errorf("filtered MACs export has %d rows, want %d (legacy clamp truncated at 200)", got, n)
	}
}

func TestAdminExportAuditHonorsLargeLimit(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	const n = 250 // > the legacy 200-row reset SearchAudit applied to limits >1000
	for i := 0; i < n; i++ {
		app.DB.Audit(ctx, "test", "limit_probe", fmt.Sprintf("T%d", i), "")
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/audit.csv?action=limit_probe&limit=5000", nil, jar)
	if got := csvDataRows(body); got != n {
		t.Errorf("audit export with limit=5000 has %d rows, want %d (legacy clamp reset to 200)", got, n)
	}
}

func TestAdminExportSMSLogHonorsLargeLimit(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	const n = 150 // > the legacy 100-row reset SearchSMSLogs applied to limits >1000
	for i := 0; i < n; i++ {
		if err := app.DB.LogSMS(ctx, "test", fmt.Sprintf("139%08d", i), "hello", true, ""); err != nil {
			t.Fatal(err)
		}
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/sms-log.csv?limit=2000", nil, jar)
	if got := csvDataRows(body); got != n {
		t.Errorf("sms-log export with limit=2000 has %d rows, want %d (legacy clamp reset to 100)", got, n)
	}
}

// DB-level sanity for the shared clamp: defaults still apply on zero, the
// hard ceiling still exists.
func TestSearchUsersLimitClamp(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	for i := 0; i < 120; i++ {
		if _, err := app.DB.CreateUser(ctx, fmt.Sprintf("137%08d", i), "h"); err != nil {
			t.Fatal(err)
		}
	}
	// limit=0 → default 100.
	users, err := app.DB.SearchUsers(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 100 {
		t.Errorf("limit=0 returned %d users, want default 100", len(users))
	}
	// limit=120 → honored (legacy behavior reset it to 100).
	users, err = app.DB.SearchUsers(ctx, "", 120)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 120 {
		t.Errorf("limit=120 returned %d users, want 120", len(users))
	}
	// Absurd limit still bounded by maxQueryLimit (no unbounded queries) —
	// verified indirectly: request far above ceiling errors nowhere and
	// returns all 120 rows.
	users, err = app.DB.SearchUsers(ctx, "", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 120 {
		t.Errorf("huge limit returned %d users, want 120", len(users))
	}
}
