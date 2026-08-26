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
		log.Printf("backup: snapshot: %v", err)
	} else {
		log.Printf("backup: wrote %s", dst)
	}
	// Prune even when the snapshot failed. The common failure mode is a
	// full flash partition — and skipping prune on failure (pre-v0.108
	// behavior) meant a full disk could never be freed by the rotator, so
	// every subsequent backup failed too: wedged until manual cleanup.
	r.prune()
}

// snapshot writes one consistent copy of the DB to dst.
//
// Preferred path is `VACUUM INTO`, which produces a transactionally
// consistent snapshot even while other goroutines write. The previous
// checkpoint-then-io.Copy approach copied the live DB file byte-by-byte:
// any write landing mid-copy (order paid, session created, audit row)
// could tear pages and silently corrupt the backup — the one file ops
// would reach for after losing the primary.
//
// Falls back to checkpoint+copy only if VACUUM INTO itself errors (e.g.
// an old SQLite build), so backups keep flowing either way.
func (r *Rotator) snapshot(ctx context.Context, dst string) error {
	tmp := dst + ".tmp"
	_ = os.Remove(tmp) // VACUUM INTO refuses to overwrite an existing file
	_, verr := r.DB.Exec(ctx, "VACUUM INTO ?", tmp)
	if verr == nil {
		// Backups carry password hashes + payment data: clamp to 0600
		// like the primary DB (VACUUM INTO creates with the umask).
		_ = os.Chmod(tmp, 0o600)
		// fsync before the rename publishes the file under its final
		// name. VACUUM INTO writes the target with synchronous=OFF (it
		// relies on the caller to make the result durable), so on the
		// delayed-allocation filesystems routers use (ext4, f2fs) a
		// power cut after the rename could leave a zero-length or
		// partial "backup" wearing a valid snapshot name — the copyFile
		// fallback below has fsynced for exactly this reason since
		// v0.108.
		if err := syncFile(tmp); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("fsync snapshot: %w", err)
		}
		return os.Rename(tmp, dst)
	}
	// A canceled context (shutdown mid-snapshot) is not a reason to fall
	// back: the checkpoint below would also fail on the dead ctx, and
	// copyFile would then duplicate the raw DB file WITHOUT a WAL
	// checkpoint — exactly the torn/stale copy VACUUM INTO exists to
	// prevent. Abort; the next scheduled pass will produce a real one.
	if ctx.Err() != nil {
		_ = os.Remove(tmp)
		return verr
	}
	log.Printf("backup: vacuum into failed (%v); falling back to checkpoint+copy", verr)
	_ = os.Remove(tmp)
	if _, err := r.DB.Exec(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		log.Printf("backup: checkpoint failed: %v", err)
	}
	return copyFile(r.DBPath, dst)
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
		// Orphaned .tmp from an interrupted snapshot (crash / power cut /
		// disk full mid-write). The .db filter below skips them, so they
		// used to accumulate forever and eat flash. A healthy snapshot
		// holds its .tmp for well under a minute — anything older than an
		// hour is garbage.
		if strings.HasPrefix(e.Name(), "billing-") && strings.HasSuffix(e.Name(), ".db.tmp") {
			if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
				p := filepath.Join(r.Dir, e.Name())
				if err := os.Remove(p); err == nil {
					log.Printf("backup: removed stale temp file %s", p)
				}
			}
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

// syncFile fsyncs an already-written file by path (used for the VACUUM
// INTO output, which SQLite hands us without any durability guarantee).
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
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
	// Flush to stable storage BEFORE the rename makes the file visible
	// under the final name. Without the fsync, a power cut shortly after
	// the rename could leave a zero-length or partially-written "backup"
	// on filesystems with delayed allocation (ext4, f2fs — i.e. routers):
	// the name says snapshot, the content says garbage.
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp) // don't leak the partial file on a failed flush
		return err
	}
	return os.Rename(tmp, dst)
}
