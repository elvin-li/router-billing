package db

import (
	"context"
	"testing"
	"time"
)

// TestCreateVouchersBulkAllSucceed — happy path. N unique codes go in via
// the bulk path; every entry returns true; every code is queryable.
func TestCreateVouchersBulkAllSucceed(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	specs := []VoucherSpec{
		{Code: "BULK0000001A", Days: 30, Label: "a", Batch: "B1"},
		{Code: "BULK0000002B", Days: 30, Label: "b", Batch: "B1"},
		{Code: "BULK0000003C", Days: 90, Label: "c", Batch: "B1"},
	}
	results, err := d.CreateVouchersBulk(ctx, specs)
	if err != nil {
		t.Fatalf("CreateVouchersBulk: %v", err)
	}
	if len(results) != len(specs) {
		t.Fatalf("results len = %d, want %d", len(results), len(specs))
	}
	for i, ok := range results {
		if !ok {
			t.Errorf("specs[%d] (%s) failed", i, specs[i].Code)
		}
		v, err := d.GetVoucher(ctx, specs[i].Code)
		if err != nil || v == nil {
			t.Errorf("specs[%d] (%s) not in DB after bulk: err=%v", i, specs[i].Code, err)
		}
	}
}

// TestCreateVouchersBulkPartialDuplicates pins SQLite's stmt-level error
// behavior: a UNIQUE collision rolls back JUST the failing INSERT, not
// the whole transaction. So a 5-row import where rows 1 and 3 collide
// with existing codes still inserts rows 0, 2, 4 and reports per-row
// failure for 1, 3.
//
// This is the load-bearing semantic of the v0.97 bulk-import speedup —
// without it, one bad-paste in the middle of a 1000-row import would
// silently lose every row after it.
func TestCreateVouchersBulkPartialDuplicates(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	// Pre-seed two codes; the bulk call below will collide with them.
	if _, err := d.CreateVoucher(ctx, "DUPDUP000001", 30, "", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateVoucher(ctx, "DUPDUP000003", 30, "", "", nil); err != nil {
		t.Fatal(err)
	}

	specs := []VoucherSpec{
		{Code: "FRESH0000000", Days: 30, Batch: "BX"},
		{Code: "DUPDUP000001", Days: 30, Batch: "BX"}, // dup
		{Code: "FRESH0000002", Days: 30, Batch: "BX"},
		{Code: "DUPDUP000003", Days: 30, Batch: "BX"}, // dup
		{Code: "FRESH0000004", Days: 30, Batch: "BX"},
	}
	results, err := d.CreateVouchersBulk(ctx, specs)
	if err != nil {
		t.Fatalf("CreateVouchersBulk: %v", err)
	}
	want := []bool{true, false, true, false, true}
	for i := range want {
		if results[i] != want[i] {
			t.Errorf("results[%d] = %v, want %v (%s)", i, results[i], want[i], specs[i].Code)
		}
	}

	// Each FRESH* must be retrievable, each DUP* must still be the
	// pre-seeded row (not overwritten).
	for _, code := range []string{"FRESH0000000", "FRESH0000002", "FRESH0000004"} {
		v, _ := d.GetVoucher(ctx, code)
		if v == nil {
			t.Errorf("%s missing after bulk", code)
		} else if v.Batch != "BX" {
			t.Errorf("%s batch = %q, want BX (the bulk insert) — looks like row didn't land", code, v.Batch)
		}
	}
	for _, code := range []string{"DUPDUP000001", "DUPDUP000003"} {
		v, _ := d.GetVoucher(ctx, code)
		if v == nil {
			t.Errorf("%s missing — pre-seed row was clobbered", code)
		} else if v.Batch != "" {
			t.Errorf("%s batch = %q, want empty — pre-seed row was overwritten", code, v.Batch)
		}
	}
}

// TestCreateVouchersBulkEmpty — defensive: zero-spec call must not error
// and not start a transaction at all (see early return in the impl).
func TestCreateVouchersBulkEmpty(t *testing.T) {
	d := openTestDB(t)
	results, err := d.CreateVouchersBulk(context.Background(), nil)
	if err != nil {
		t.Errorf("empty bulk should not error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results len = %d, want 0", len(results))
	}
}

// TestCreateVouchersBulkExpiresAt round-trips a non-nil expires_at
// pointer — easy to drop on the floor when copying spec into the
// prepared statement.
func TestCreateVouchersBulkExpiresAt(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	exp := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	specs := []VoucherSpec{
		{Code: "EXP000000001", Days: 30, ExpiresAt: &exp},
		{Code: "NOEXP0000001", Days: 30}, // nil expires_at
	}
	if _, err := d.CreateVouchersBulk(ctx, specs); err != nil {
		t.Fatal(err)
	}

	v, _ := d.GetVoucher(ctx, "EXP000000001")
	if v == nil || v.ExpiresAt == nil {
		t.Fatalf("expires_at not stored: v=%+v", v)
	}
	if !v.ExpiresAt.Equal(exp) {
		t.Errorf("expires_at = %v, want %v", v.ExpiresAt, exp)
	}

	v2, _ := d.GetVoucher(ctx, "NOEXP0000001")
	if v2 == nil {
		t.Fatal("NOEXP row missing")
	}
	if v2.ExpiresAt != nil {
		t.Errorf("nil-expires spec should leave column NULL; got %v", v2.ExpiresAt)
	}
}
