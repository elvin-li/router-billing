package db

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"router-billing/internal/models"
)

// --- v0.107 regressions: SQLite date() can't parse Go-written timestamps ---

// modernc.org/sqlite stores time.Time as "2006-01-02 15:04:05.999 +0000 UTC",
// which SQLite's date()/datetime() functions return NULL for. Any predicate
// built on date(<go-written column>) therefore silently matches nothing.

func TestSnapshotTodayCountsPaidOrders(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	o := &models.Order{
		OrderNo: "SNAP-1", Mac: "AA:BB:CC:DD:EE:01", Plan: "month",
		Days: 30, AmountCents: 1500, Status: models.OrderPending, PaymentMethod: "wechat",
	}
	if err := d.CreateOrder(ctx, o); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.MarkOrderPaid(ctx, "SNAP-1", "trade-1"); err != nil {
		t.Fatal(err)
	}

	if err := d.SnapshotToday(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := d.ListStatsDaily(ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 stats row, got %d", len(rows))
	}
	// Pre-fix: date(paid_at) = date('now') was NULL for Go-written paid_at,
	// so paid_orders was permanently 0.
	if rows[0].PaidOrders != 1 {
		t.Errorf("PaidOrders = %d, want 1 (date(paid_at) regression)", rows[0].PaidOrders)
	}
}

func TestAttentionCountsFailedOrdersToday(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	o := &models.Order{
		OrderNo: "ATTN-1", Mac: "AA:BB:CC:DD:EE:02", Plan: "month",
		Days: 30, AmountCents: 1500, Status: models.OrderPending, PaymentMethod: "alipay",
	}
	if err := d.CreateOrder(ctx, o); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CancelPendingOrder(ctx, "ATTN-1"); err != nil {
		t.Fatal(err)
	}

	a, err := d.Attention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Pre-fix: date(created_at) = date('now') was NULL for Go-written
	// created_at, so FailedToday was permanently 0.
	if a.FailedToday != 1 {
		t.Errorf("FailedToday = %d, want 1 (date(created_at) regression)", a.FailedToday)
	}
}

// --- v0.107: ExpireDueMACs is one atomic UPDATE ... RETURNING ---

func TestExpireDueMACsReportsExactlyFlipped(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	// One already past expiry, one still active.
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:01", "stale", -1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:02", "fresh", 30, nil); err != nil {
		t.Fatal(err)
	}

	expired, err := d.ExpireDueMACs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0] != "AA:BB:CC:00:00:01" {
		t.Fatalf("expired = %v, want exactly the stale MAC", expired)
	}
	m, _ := d.GetMAC(ctx, "AA:BB:CC:00:00:01")
	if m.Status != models.MACExpired {
		t.Errorf("status = %s, want expired", m.Status)
	}
	m2, _ := d.GetMAC(ctx, "AA:BB:CC:00:00:02")
	if m2.Status != models.MACActive {
		t.Errorf("fresh MAC flipped to %s", m2.Status)
	}

	// Second sweep must be a no-op (row already expired, not re-reported).
	expired, err = d.ExpireDueMACs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 0 {
		t.Errorf("second sweep re-reported %v", expired)
	}
}

// TestExpireDueMACsConcurrentNoDuplicates pins the claim semantics: when
// several sweeps race, each due MAC is reported by EXACTLY one of them.
// Pre-fix (SELECT list, then blanket UPDATE as separate statements) two
// concurrent sweeps could both SELECT the same MAC and both report it —
// double revoke webhooks — and a MAC flipped between the statements was
// never reported at all.
func TestExpireDueMACsConcurrentNoDuplicates(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	macs := []string{
		"AA:BB:CC:11:00:01", "AA:BB:CC:11:00:02", "AA:BB:CC:11:00:03",
		"AA:BB:CC:11:00:04", "AA:BB:CC:11:00:05", "AA:BB:CC:11:00:06",
	}
	for _, m := range macs {
		if _, err := d.UpsertMAC(ctx, m, "due", -1, nil); err != nil {
			t.Fatal(err)
		}
	}

	const sweeps = 8
	results := make([][]string, sweeps)
	var wg sync.WaitGroup
	for i := 0; i < sweeps; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := d.ExpireDueMACs(ctx)
			if err != nil {
				t.Errorf("sweep %d: %v", i, err)
				return
			}
			results[i] = got
		}(i)
	}
	wg.Wait()

	seen := map[string]int{}
	for _, r := range results {
		for _, m := range r {
			seen[m]++
		}
	}
	for _, m := range macs {
		if seen[m] != 1 {
			t.Errorf("MAC %s reported %d times, want exactly 1", m, seen[m])
		}
	}
	if len(seen) != len(macs) {
		t.Errorf("reported %d distinct MACs, want %d", len(seen), len(macs))
	}
}

// --- v0.107: ClearUserTOTP is one transaction ---

func TestClearUserTOTPWipesCodesAndTrustedDevices(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	u, err := d.CreateUser(ctx, "13800138010", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetUserTOTPPending(ctx, u.ID, "SECRETBASE32"); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfirmUserTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.ReplaceBackupCodes(ctx, u.ID, []string{"h1", "h2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTrustedDevice(ctx, u.ID, "trust-tok", "Chrome", time.Hour); err != nil {
		t.Fatal(err)
	}

	if err := d.ClearUserTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}

	got, _ := d.GetUser(ctx, u.ID)
	if got.TOTPSecret != "" || got.TOTPPending != "" {
		t.Errorf("TOTP not cleared: secret=%q pending=%q", got.TOTPSecret, got.TOTPPending)
	}
	codes, _ := d.ListBackupCodes(ctx, u.ID)
	if len(codes) != 0 {
		t.Errorf("%d backup codes survived", len(codes))
	}
	devs, _ := d.ListTrustedDevices(ctx, u.ID)
	if len(devs) != 0 {
		t.Errorf("%d trusted devices survived — they'd bypass the next enrollment", len(devs))
	}
}

// --- v0.107: SuspendUser / DeleteUser session cleanup is transactional ---

func TestSuspendUserDropsSessionsAtomically(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	u, err := d.CreateUser(ctx, "13800138011", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CreateSession(ctx, "sess-suspend-1", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateSession(ctx, "sess-admin-1", "admin", "root", nil, time.Hour); err != nil {
		t.Fatal(err)
	}

	if err := d.SuspendUser(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.GetSession(ctx, "sess-suspend-1"); s != nil {
		t.Error("suspended user's session survived")
	}
	if s, _ := d.GetSession(ctx, "sess-admin-1"); s == nil {
		t.Error("admin session was collateral damage")
	}

	// Unsuspending must NOT touch sessions.
	if err := d.CreateSession(ctx, "sess-suspend-2", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.SuspendUser(ctx, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.GetSession(ctx, "sess-suspend-2"); s == nil {
		t.Error("unsuspend deleted the user's session")
	}
}

func TestDeleteUserDropsSessions(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	u, err := d.CreateUser(ctx, "13800138012", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CreateSession(ctx, "sess-del-1", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.GetSession(ctx, "sess-del-1"); s != nil {
		t.Error("deleted user's session survived")
	}
	if got, _ := d.GetUser(ctx, u.ID); got != nil {
		t.Error("user row survived")
	}
}

// --- v0.107: BumpPasswordResetAttempts is a single UPDATE ... RETURNING ---

func TestBumpPasswordResetAttemptsConcurrentDistinct(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	u, err := d.CreateUser(ctx, "13800138013", "hash")
	if err != nil {
		t.Fatal(err)
	}
	r, err := d.CreatePasswordReset(ctx, u.ID, "code-hash", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	const n = 10
	got := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := d.BumpPasswordResetAttempts(ctx, r.ID)
			if err != nil {
				t.Errorf("bump %d: %v", i, err)
				return
			}
			got[i] = v
		}(i)
	}
	wg.Wait()

	// Every bump must observe a distinct post-increment value 1..n.
	// Pre-fix (UPDATE then separate SELECT) two racers could read the
	// same value, under-counting attempts against the brute-force cap.
	seen := map[int]bool{}
	for _, v := range got {
		if v < 1 || v > n {
			t.Errorf("returned attempts %d out of range 1..%d", v, n)
		}
		if seen[v] {
			t.Errorf("attempts value %d returned twice", v)
		}
		seen[v] = true
	}
	row, err := d.GetActivePasswordReset(ctx, u.ID)
	if err != nil || row == nil {
		t.Fatalf("reset row gone: %v", err)
	}
	if row.Attempts != n {
		t.Errorf("final attempts = %d, want %d", row.Attempts, n)
	}
}

func TestBumpPasswordResetAttemptsMissingRow(t *testing.T) {
	d := openTestDB(t)
	if _, err := d.BumpPasswordResetAttempts(context.Background(), 99999); err == nil {
		t.Error("expected error for missing reset row")
	}
}

// --- v0.107: migration idempotency incl. new indexes ---

func TestMigrationIdempotentAndIndexesPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reopen.db")

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	// Re-open simulates the every-startup migration on an existing DB.
	d, err = Open(path)
	if err != nil {
		t.Fatalf("second Open (migration re-run): %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	for _, idx := range []string{"idx_sessions_user", "idx_audit_action_target"} {
		var n int
		if err := d.conn.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("index %s missing after migration", idx)
		}
	}
}
