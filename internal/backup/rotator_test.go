package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
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
