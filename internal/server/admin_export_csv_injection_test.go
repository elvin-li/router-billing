package server

import (
	"context"
	"encoding/csv"
	"strings"
	"testing"
)

// v0.106: cells beginning with a formula trigger must be neutralized so
// opening an export in Excel / LibreOffice can't execute a payload planted
// by an end user (MAC labels are user-settable via /user/macs/label).
func TestCSVCellNeutralizesFormulas(t *testing.T) {
	cases := map[string]string{
		`=HYPERLINK("http://evil","x")`: `'=HYPERLINK("http://evil","x")`,
		`+cmd`:                          `'+cmd`,
		`-2+3`:                          `'-2+3`,
		`@SUM(A1)`:                      `'@SUM(A1)`,
		"\tpayload":                     "'\tpayload",
		"\rpayload":                     "'\rpayload",
		`  =behind-spaces`:              `'  =behind-spaces`,
		// Benign values pass through untouched.
		`office tablet`:        `office tablet`,
		`AA:BB:CC:DD:EE:FF`:    `AA:BB:CC:DD:EE:FF`,
		`2026-01-02T03:04:05Z`: `2026-01-02T03:04:05Z`,
		`50% off promo`:        `50% off promo`,
		``:                     ``,
	}
	for in, want := range cases {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

// End to end: a hostile user-set MAC label must come back escaped in
// /admin/export/macs.csv.
func TestAdminExportMACsEscapesFormulaLabel(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if _, err := app.DB.UpsertMAC(ctx, "AA:BB:CC:00:31:01", `=HYPERLINK("http://evil","click")`, 30, nil); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/macs.csv", nil, jar)

	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v", err)
	}
	found := false
	for _, row := range rows[1:] {
		if row[0] != "AA:BB:CC:00:31:01" {
			continue
		}
		found = true
		if !strings.HasPrefix(row[1], "'=") {
			t.Errorf("label cell must be formula-escaped; got %q", row[1])
		}
	}
	if !found {
		t.Fatal("seeded MAC missing from export")
	}
}

// Audit detail carries user text too (labels, notes); the audit export
// must escape every text column.
func TestAdminExportAuditEscapesFormulaDetail(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin", "manual_note", "=EVIL-TARGET", `=cmd|'/c calc'!A0`)

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/audit.csv", nil, jar)

	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v", err)
	}
	found := false
	for _, row := range rows[1:] {
		if row[3] != "manual_note" {
			continue
		}
		found = true
		if !strings.HasPrefix(row[4], "'=") {
			t.Errorf("target cell must be formula-escaped; got %q", row[4])
		}
		if !strings.HasPrefix(row[5], "'=") {
			t.Errorf("detail cell must be formula-escaped; got %q", row[5])
		}
	}
	if !found {
		t.Fatal("seeded audit row missing from export")
	}
}

// SMS messages are free text (and error strings come from the provider) —
// both must be escaped in the sms-log export.
func TestAdminExportSMSLogEscapesFormulaMessage(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	if err := app.DB.LogSMS(ctx, "test-provider", "13800140001", "@SUM(1+9)*cmd", false, "-2+3+cmd"); err != nil {
		t.Fatal(err)
	}
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/export/sms-log.csv", nil, jar)

	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("export is not valid CSV: %v", err)
	}
	found := false
	for _, row := range rows[1:] {
		if row[3] != "13800140001" {
			continue
		}
		found = true
		if !strings.HasPrefix(row[4], "'@") {
			t.Errorf("message cell must be formula-escaped; got %q", row[4])
		}
		if !strings.HasPrefix(row[6], "'-") {
			t.Errorf("error_msg cell must be formula-escaped; got %q", row[6])
		}
	}
	if !found {
		t.Fatal("seeded SMS log row missing from export")
	}
}
