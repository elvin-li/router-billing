package db

import (
	"context"
	"path/filepath"
	"testing"
)

// v0.125: the user portal activity feed moved from an un-indexable
// substring SearchAudit filter to an exact-actor lookup. Equivalence
// check: both actor forms match, other users' rows never leak in.
func TestListAuditForUserPhone(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()

	d.Audit(ctx, "user:13800000001", "login", "", "ip=10.0.0.1")
	d.Audit(ctx, "user-attempt:13800000001", "login_failed", "", "ip=10.0.0.2")
	d.Audit(ctx, "user:13800000002", "login", "", "ip=10.0.0.3")
	d.Audit(ctx, "admin", "mac_granted", "AA:BB:CC:00:00:01", "phone=13800000001")
	d.Audit(ctx, "user:13800000001", "password_change", "", "")

	got, err := d.ListAuditForUserPhone(ctx, "13800000001", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rows (login, login_failed, password_change); got %d: %+v", len(got), got)
	}
	// Newest first.
	if got[0].Action != "password_change" {
		t.Errorf("expected newest-first ordering; got first action %q", got[0].Action)
	}
	for _, e := range got {
		if e.Actor != "user:13800000001" && e.Actor != "user-attempt:13800000001" {
			t.Errorf("leaked foreign actor row: %+v", e)
		}
	}
	// Limit respected.
	got, err = d.ListAuditForUserPhone(ctx, "13800000001", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("limit 2 should return 2 rows; got %d", len(got))
	}
}
