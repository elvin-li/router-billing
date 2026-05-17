package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// GET /admin/backup — checkpoints the WAL and streams the SQLite file.
//
// SQLite in WAL mode keeps recent writes in a sidecar -wal file. Issuing
// `PRAGMA wal_checkpoint(TRUNCATE)` flushes everything back into the main file
// so the byte copy is self-consistent.
func (a *App) handleAdminBackup(w http.ResponseWriter, r *http.Request) {
	// Best-effort checkpoint; ignore error (corrupt-WAL scenario is rare and
	// streaming an uncheckpointed file is still typically usable).
	if _, err := a.DB.Exec(r.Context(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		log.Printf("backup: checkpoint failed: %v", err)
	}

	f, err := os.Open(a.Cfg.DBPath)
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
	a.DB.Audit(r.Context(), "admin", "backup", "", fmt.Sprintf("size=%d", st.Size()))
}
