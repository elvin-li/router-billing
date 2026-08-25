package backup

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-billing/internal/db"
)

func TestCopyFileAtomic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	dst := filepath.Join(dir, "dst.db")
	contents := []byte("SQLite format 3\x00 fake")
	if err := os.WriteFile(src, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(contents) {
		t.Errorf("dst contents mismatch")
	}
	// .tmp file should be gone (rename completed).
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp left behind")
	}
	// Mode should be 0o600 (private).
	info, _ := os.Stat(dst)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v; want 0o600", info.Mode().Perm())
	}
}

func TestCopyFileMissingSource(t *testing.T) {
	dir := t.TempDir()
	err := copyFile(filepath.Join(dir, "nope.db"), filepath.Join(dir, "x.db"))
	if err == nil {
		t.Error("expected error on missing source")
	}
}

// pruneTestRotator builds N backup files spread across the cutoff with
// per-file mtimes set so we can verify retention precisely.
func TestPruneRespectsRetainDays(t *testing.T) {
	dir := t.TempDir()
	r := &Rotator{Dir: dir, RetainDays: 3}

	now := time.Now()
	cases := []struct {
		name string
		age  time.Duration
	}{
		{"billing-1.db", 10 * 24 * time.Hour},   // old → should prune
		{"billing-2.db", 5 * 24 * time.Hour},    // old → should prune (over retain)
		{"billing-3.db", 4 * 24 * time.Hour},    // old → kept if among latest 3
		{"billing-4.db", 2 * 24 * time.Hour},    // fresh
		{"billing-5.db", 1 * 24 * time.Hour},    // fresh
		{"billing-6.db", 6 * time.Hour},         // fresh (latest)
		{"random-file.db", 30 * 24 * time.Hour}, // wrong prefix → ignored
	}
	for _, c := range cases {
		p := filepath.Join(dir, c.name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(-c.age)
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}

	r.prune()

	survivors, _ := os.ReadDir(dir)
	have := map[string]bool{}
	for _, e := range survivors {
		have[e.Name()] = true
	}
	// Wrong-prefix file must survive (not touched by prune).
	if !have["random-file.db"] {
		t.Error("non-prefixed file should not be touched")
	}
	// Latest 3 must survive.
	for _, n := range []string{"billing-4.db", "billing-5.db", "billing-6.db"} {
		if !have[n] {
			t.Errorf("expected %s to survive", n)
		}
	}
	// billing-3.db is older than cutoff (3 days) BUT prune keeps the latest
	// RetainDays (3) by file count too — billing-3 is the 4th-latest so
	// it's a prune candidate. Verify it's gone.
	if have["billing-3.db"] {
		t.Error("billing-3.db (4th latest) should have been pruned")
	}
	if have["billing-1.db"] || have["billing-2.db"] {
		t.Error("billing-1/2 (older than cutoff) should be gone")
	}
}

func TestPruneAlwaysKeepsLatestEvenIfOld(t *testing.T) {
	dir := t.TempDir()
	r := &Rotator{Dir: dir, RetainDays: 1}

	// Single very-old file. Even though it's older than cutoff, the keep-N
	// floor (≥1) means it should survive.
	p := filepath.Join(dir, "billing-old.db")
	os.WriteFile(p, []byte("x"), 0o600)
	old := time.Now().AddDate(0, 0, -100)
	os.Chtimes(p, old, old)

	r.prune()

	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Error("the only file should be kept (RetainDays >=1)")
	}
}

func TestSnapshotProducesConsistentBackup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "billing.db")
	dbx, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbx.Close() })
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := dbx.Exec(ctx,
			`INSERT INTO audit_log (actor, action, target, detail) VALUES ('t','snap','x','row')`); err != nil {
			t.Fatal(err)
		}
	}

	r := &Rotator{DB: dbx, DBPath: dbPath, Dir: filepath.Join(dir, "backups"), RetainDays: 7}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(r.Dir, "billing-test.db")
	if err := r.snapshot(ctx, dst); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// No .tmp left behind.
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Error(".tmp left behind after successful snapshot")
	}
	// Backups hold password hashes — must be private.
	if info, err := os.Stat(dst); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %v (err=%v); want 0600", info.Mode().Perm(), err)
	}

	// The snapshot must be a valid, complete database on its own —
	// openable, integrity-clean, and carrying the rows.
	bk, err := sql.Open("sqlite", dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bk.Close() })
	var integrity string
	if err := bk.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		t.Fatalf("integrity_check: %v", err)
	}
	if !strings.EqualFold(integrity, "ok") {
		t.Errorf("integrity_check = %q; want ok", integrity)
	}
	var n int
	if err := bk.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='snap'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("backup has %d seeded rows; want 5", n)
	}
}

func TestOncePrunesEvenWhenSnapshotFails(t *testing.T) {
	// A full flash partition fails the snapshot — but prune must still run
	// so old backups are freed and the NEXT attempt can succeed. Simulate
	// total snapshot failure with a closed DB handle + missing source file.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "billing.db")
	dbx, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	dbx.Close()       // VACUUM INTO + checkpoint both error
	os.Remove(dbPath) // fallback copy errors too
	backups := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backups, 0o755); err != nil {
		t.Fatal(err)
	}

	old := time.Now().AddDate(0, 0, -10)
	for _, name := range []string{"billing-a.db", "billing-b.db", "billing-c.db"} {
		p := filepath.Join(backups, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	r := &Rotator{DB: dbx, DBPath: dbPath, Dir: backups, RetainDays: 1}
	r.once(context.Background())

	entries, _ := os.ReadDir(backups)
	var remaining []string
	for _, e := range entries {
		remaining = append(remaining, e.Name())
	}
	// RetainDays=1 → keep the single newest, prune the two older ones —
	// even though the snapshot itself failed.
	if len(remaining) != 1 {
		t.Errorf("expected prune to run despite snapshot failure; %d files remain: %v",
			len(remaining), remaining)
	}
}

func TestPruneRemovesStaleTmpFiles(t *testing.T) {
	dir := t.TempDir()
	r := &Rotator{Dir: dir, RetainDays: 7}

	stale := filepath.Join(dir, "billing-20260101-000000.db.tmp")
	fresh := filepath.Join(dir, "billing-20260825-060000.db.tmp")
	for _, p := range []string{stale, fresh} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatal(err)
	}

	r.prune()

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale .tmp from an interrupted snapshot should be removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("fresh .tmp (snapshot possibly in progress) must be kept")
	}
}

func TestRotatorRunDisabledNoOp(t *testing.T) {
	// Run() should immediately return when Enabled=false.
	r := &Rotator{Enabled: false}
	done := make(chan struct{})
	go func() {
		r.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run() hung when Enabled=false")
	}
}
