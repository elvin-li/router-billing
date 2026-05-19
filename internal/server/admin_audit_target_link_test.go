package server

import (
	"context"
	"strings"
	"testing"
)

func TestAuditTargetHrefShapes(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"AA:BB:CC:DD:EE:FF", "/admin/macs/detail?mac=AA:BB:CC:DD:EE:FF"},
		{"aa-bb-cc-dd-ee-ff", "/admin/macs/detail?mac=AA:BB:CC:DD:EE:FF"}, // normalized
		{"ORD-12345", "/admin/orders/detail?order_no=ORD-12345"},
		{"ord-12345", "/admin/orders/detail?order_no=ord-12345"},
		{"13800138000", "/admin/sms-log?phone=13800138000"},
		{"", ""},
		{"random text", ""},
		{"not-a-mac-or-order", ""},
		// 11-digit starts-with-1 is intentionally treated as a phone — Chinese
		// mobile numbers all match this pattern. Non-Chinese-prefix numbers
		// (10-digit, or starting with 2-9) don't.
		{"12345678901", "/admin/sms-log?phone=12345678901"},
		{"23456789012", ""}, // starts with 2 → not phone shape
		{"1234567890", ""},  // 10 digits, not 11
	}
	for _, c := range cases {
		t.Run(c.target, func(t *testing.T) {
			got := auditTargetHref(c.target)
			if got != c.want {
				t.Errorf("auditTargetHref(%q) = %q, want %q", c.target, got, c.want)
			}
		})
	}
}

// Audit page renders the target as a link for shapes we recognize.
func TestAdminAuditPageLinksTargets(t *testing.T) {
	app := setupTestApp(t)
	ctx := contextForTest()
	app.DB.Audit(ctx, "admin", "grant", "AA:BB:CC:00:2B:01", "")
	app.DB.Audit(ctx, "admin", "order_paid", "ORD-LINK-1", "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/audit", nil, jar)

	// MAC target link present.
	if !strings.Contains(body, `href="/admin/macs/detail?mac=AA:BB:CC:00:2B:01"`) &&
		!strings.Contains(body, `href="/admin/macs/detail?mac=AA%3aBB%3aCC%3a00%3a2B%3a01"`) {
		t.Error("MAC target should be linked to its detail page")
	}
	// Order target link present.
	if !strings.Contains(body, `href="/admin/orders/detail?order_no=ORD-LINK-1"`) {
		t.Error("order target should be linked to its detail page")
	}
}

func contextForTest() context.Context { return context.Background() }
