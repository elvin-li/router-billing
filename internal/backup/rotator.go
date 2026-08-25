// Package backup runs daily SQLite snapshots and prunes old ones.
package backup

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"router-billing/internal/db"
)

type Rotator struct {
	DB         *db.DB
	DBPath     string        // /var/lib/router-billing/billing.db
	Dir        string        // /var/lib/router-billing/backups
	RetainDays int           // 7
	Interval   time.Duration // 24h
	Enabled    bool
}

func (r *Rotator) Run(ctx context.Context) {
	if !r.Enabled {
		return
	}
	if r.Dir == "" {
		r.Dir = filepath.Join(filepath.Dir(r.DBPath), "backups")
	}
	if r.RetainDays <= 0 {
		r.RetainDays = 7
	}
	if r.Interval <= 0 {
		r.Interval = 24 * time.Hour
	}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		log.Printf("backup: mkdir %s: %v (disabled)", r.Dir, err)
		return
	}
	log.Printf("backup: rotator on (dir=%s retain=%dd interval=%s)", r.Dir, r.RetainDays, r.Interval)

	// Initial backup so a freshly-installed router has at least one snapshot.
	r.once(ctx)

	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.once(ctx)
		}
	}
}

func (r *Rotator) once(ctx context.Context) {
	dst := filepath.Join(r.Dir, fmt.Sprintf("billing-%s.db", time.Now().Format("20060102-150405")))
	if err := r.snapshot(ctx, dst); err != nil {
		log.Printf("backup: %v", err)
		return
	}
	log.Printf("backup: wrote %s", dst)
	r.prune()
}

// snapshot prefers `VACUUM INTO` — SQLite takes the copy inside a read
// transaction, so the result is consistent even while writers are active,
// and it compacts free pages as a bonus. The old checkpoint+file-copy path
// stays as a fallback (e.g. target filesystem quirks): it is safe only when
// no write lands between the checkpoint and the copy, which is almost
// always true on a router but not guaranteed.
func (r *Rotator) snapshot(ctx context.Context, dst string) error {
	tmp := dst + ".tmp"
	_ = os.Remove(tmp) // VACUUM INTO refuses to overwrite an existing file
	if _, err := r.DB.Exec(ctx, "VACUUM INTO ?", tmp); err == nil {
		if err := os.Chmod(tmp, 0o600); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("chmod snapshot: %w", err)
		}
		if err := syncFile(tmp); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("fsync snapshot: %w", err)
		}
		return os.Rename(tmp, dst)
	} else {
		log.Printf("backup: vacuum-into failed (%v); falling back to file copy", err)
		_ = os.Remove(tmp)
	}
	if _, err := r.DB.Exec(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		log.Printf("backup: checkpoint failed: %v", err)
	}
	if err := copyFile(r.DBPath, dst); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

func (r *Rotator) prune() {
	cutoff := time.Now().AddDate(0, 0, -r.RetainDays)
	entries, err := os.ReadDir(r.Dir)
	if err != nil {
		return
	}
	type item struct {
		path string
		mod  time.Time
	}
	var items []item
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "billing-") || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, item{filepath.Join(r.Dir, e.Name()), info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mod.Before(items[j].mod) })
	// Always keep the latest N≥1, even if older than cutoff.
	keep := r.RetainDays
	if keep < 1 {
		keep = 1
	}
	for i, it := range items {
		drop := it.mod.Before(cutoff) && len(items)-i > keep
		if drop {
			if err := os.Remove(it.path); err != nil {
				log.Printf("backup: prune %s: %v", it.path, err)
			} else {
				log.Printf("backup: pruned %s", it.path)
			}
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	// fsync before rename: routers lose power routinely, and a rename that
	// lands before the data blocks would leave a "complete-looking" backup
	// full of zero pages — worse than no backup at all.
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
