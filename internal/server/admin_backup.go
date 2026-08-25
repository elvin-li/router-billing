package server

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// openProbeDB opens the path as a read-only SQLite database for schema probing.
// Distinct from the App's *db.DB so the probe doesn't race with the live pool.
//
// We use `?mode=ro&immutable=1` so SQLite doesn't try to create a WAL/SHM next
// to the file (which can fail in tmpdirs and trigger VNODE errors on macOS).
func openProbeDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1", path)
	return sql.Open("sqlite", dsn)
}

// GET /admin/backup — checkpoints the WAL and streams the SQLite file.
//
// SQLite in WAL mode keeps recent writes in a sidecar -wal file. Issuing
// `PRAGMA wal_checkpoint(TRUNCATE)` flushes everything back into the main file
// so the byte copy is self-consistent.
func (a *App) handleAdminBackup(w http.ResponseWriter, r *http.Request) {
	a.streamBackup(w, r, "admin", clientIP(r))
}

// GET /api/admin/backup  Bearer <write-token>
//
// Programmatic equivalent of /admin/backup. Streams the SQLite file
// after a WAL checkpoint. Useful for off-router backup automation:
// nightly `curl -O -H "Authorization: Bearer $RB_TOKEN" .../api/admin/backup`.
//
// Read-only tokens are REJECTED (403) even though the method is GET.
// The raw DB file contains password hashes, TOTP secrets, full unredeemed
// voucher codes, and SMS message bodies (session and trusted-device
// tokens are stored hashed since v0.113, but the rest stands) — the
// material every
// JSON read endpoint strips (apiUserSummary, apiVoucher code prefix,
// apiSession without token). A read-only token that can download the
// backup would be a full-scope token in disguise, so the route is gated
// by requireAPITokenPrivileged. Restore still goes through
// /admin/backup/restore (cookie + CSRF).
//
// Audit row: `backup` with size + via=api.
func (a *App) handleAPIBackup(w http.ResponseWriter, r *http.Request, actor string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	a.streamBackup(w, r, actor, clientIP(r))
}

// streamBackup is the shared body — consistent snapshot + stream + audit row.
// `actor` distinguishes UI ("admin") from API (Bearer label) in audit.
//
// The snapshot goes through `VACUUM INTO` for the same reason the nightly
// rotator does (v0.109): checkpoint-then-copy reads the LIVE database file
// byte-by-byte, so any write landing mid-download (order paid, session
// created, audit row) can tear pages and silently corrupt the very file an
// operator will reach for after losing the primary. Only if VACUUM INTO
// itself errors (ancient SQLite) do we fall back to checkpoint+copy.
func (a *App) streamBackup(w http.ResponseWriter, r *http.Request, actor, ip string) {
	snap := filepath.Join(filepath.Dir(a.Cfg.DBPath),
		fmt.Sprintf(".download-%s.db.tmp", time.Now().Format("20060102-150405.000000000")))
	_ = os.Remove(snap) // VACUUM INTO refuses to overwrite
	path := snap
	if _, verr := a.DB.Exec(r.Context(), "VACUUM INTO ?", snap); verr != nil {
		log.Printf("backup: vacuum into failed (%v); falling back to checkpoint+copy", verr)
		_ = os.Remove(snap)
		path = a.Cfg.DBPath
		if _, err := a.DB.Exec(r.Context(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			log.Printf("backup: checkpoint failed: %v", err)
		}
	} else {
		defer os.Remove(snap)
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "open db: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	stamp := time.Now().Format("20060102-150405")
	w.Header().Set("Content-Type", "application/x-sqlite3")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="billing-%s.db"`, stamp))
	if st != nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	}
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("backup: copy: %v", err)
	}
	via := "ui"
	if strings.HasPrefix(actor, "api:") {
		via = "api"
	}
	size := int64(0)
	if st != nil {
		size = st.Size()
	}
	a.DB.Audit(r.Context(), actor, "backup", "",
		fmt.Sprintf("size=%d via=%s ip=%s", size, via, ip))
}

// POST /admin/backup/restore — accept an uploaded *.db, validate, stage it as
// `<dbpath>.pending-restore`, and tell the admin to restart. main.go's
// MaybeApplyPendingRestore() picks it up at next boot and atomically swaps.
//
// Two-phase design avoids closing the live DB out from under in-flight
// requests. If the admin reconsiders, they can `rm <dbpath>.pending-restore`
// before restarting.
//
// SAFETY:
//   - Reject anything that's not SQLite-3 (magic header + open via sqlite3).
//   - Reject if `macs` table is missing (probably wrong DB).
//   - Live DB stays untouched until restart.
func (a *App) handleAdminBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/health", http.StatusSeeOther)
		return
	}
	// Cap upload at 256 MB; SQLite billing DB should be a few MB at most.
	r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "upload too large or malformed", http.StatusBadRequest)
		return
	}
	file, hdr, err := r.FormFile("backup")
	if err != nil {
		http.Error(w, "missing field: backup", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Stream to a temp file beside the real DB (same volume → atomic rename).
	dir := filepath.Dir(a.Cfg.DBPath)
	tmp, err := os.CreateTemp(dir, ".restore-*.db.upload")
	if err != nil {
		http.Error(w, "tempfile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpPath) }

	if _, err := io.Copy(tmp, file); err != nil {
		cleanup()
		http.Error(w, "write: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		http.Error(w, "fsync: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmp.Close()

	// Validate: SQLite magic header + has macs table.
	if err := validateSQLiteFile(tmpPath); err != nil {
		os.Remove(tmpPath)
		http.Error(w, "validation: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Stage as `.pending-restore` (same volume → atomic). main picks it up on next boot.
	pending := a.Cfg.DBPath + ".pending-restore"
	if err := os.Rename(tmpPath, pending); err != nil {
		cleanup()
		http.Error(w, "stage: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("restore: staged %s (%d B) as %s — admin must restart to apply",
		hdr.Filename, hdr.Size, pending)
	a.DB.Audit(r.Context(), "admin", "restore_staged", hdr.Filename,
		fmt.Sprintf("size=%d", hdr.Size))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset=utf-8>
<title>restore staged</title><style>body{font-family:-apple-system,sans-serif;max-width:560px;margin:60px auto;padding:0 20px;line-height:1.6;color:#0f172a}code{background:#f1f5f9;padding:1px 6px;border-radius:4px}</style>
</head><body>
<h1>✓ 备份已上传，等待重启切换</h1>
<p>已暂存为：<code>%s</code>（%d 字节）</p>
<p>当前服务仍在用旧 DB，所有请求照常工作。</p>
<p style="background:#fef3c7;padding:12px 16px;border-radius:8px;">
要正式生效，<strong>在路由器上执行</strong>：
<br><br><code>/etc/init.d/router-billing restart</code><br><br>
重启时会自动把旧 DB 备份到 <code>%s.before-restore-YYYYMMDD-HHMMSS</code>，再切到新文件。
</p>
<p>反悔？删掉暂存文件即可恢复原状：<br><code>rm %s</code></p>
<p><a href="/admin/health">← 返回</a></p>
</body></html>`, pending, hdr.Size, a.Cfg.DBPath, pending)
}

// MaybeApplyPendingRestore runs once at startup. If <dbPath>.pending-restore
// exists, it's swapped into place atomically and the old DB is renamed to
// `<dbPath>.before-restore-<stamp>`. Errors return early without touching
// the live DB. Safe to call before db.Open().
func MaybeApplyPendingRestore(dbPath string) error {
	pending := dbPath + ".pending-restore"
	st, err := os.Stat(pending)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if st.Size() < 16 {
		os.Remove(pending)
		return fmt.Errorf("pending-restore too small (%d B); removed", st.Size())
	}
	if err := validateSQLiteFile(pending); err != nil {
		os.Remove(pending)
		return fmt.Errorf("pending-restore failed validation: %w; removed", err)
	}
	stamp := time.Now().Format("20060102-150405")
	rollback := dbPath + ".before-restore-" + stamp
	// Move current DB out of the way (if it exists).
	if _, err := os.Stat(dbPath); err == nil {
		if err := os.Rename(dbPath, rollback); err != nil {
			return fmt.Errorf("rollback rename: %w", err)
		}
		// Stale WAL/SHM from old DB shouldn't be re-applied to new file.
		_ = os.Rename(dbPath+"-wal", rollback+"-wal")
		_ = os.Rename(dbPath+"-shm", rollback+"-shm")
	}
	if err := os.Rename(pending, dbPath); err != nil {
		// Try to restore the original; absent that, leave operator a clear
		// trail in both filenames.
		_ = os.Rename(rollback, dbPath)
		return fmt.Errorf("apply rename: %w", err)
	}
	log.Printf("restore: applied %s; old kept at %s", dbPath, rollback)
	return nil
}

// validateSQLiteFile checks the SQLite magic header + that the `macs` table
// exists (so we don't restore something totally unrelated by accident).
func validateSQLiteFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	// SQLite 3 magic: "SQLite format 3\x00"
	if string(hdr) != "SQLite format 3\x00" {
		return fmt.Errorf("not a SQLite 3 database (bad magic)")
	}
	// Open with sqlite driver and probe for our schema.
	probe, err := openProbeDB(path)
	if err != nil {
		return fmt.Errorf("open probe: %w", err)
	}
	defer probe.Close()
	var n int
	row := probe.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='macs'`)
	if err := row.Scan(&n); err != nil {
		return fmt.Errorf("schema probe: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("uploaded file has no `macs` table — not a router-billing DB")
	}
	return nil
}
