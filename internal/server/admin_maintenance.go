package server

import (
	"net/http"
	"os"
)

// GET /admin/maintenance — backup download, restore upload, and pending-restore status.
func (a *App) handleAdminMaintenance(w http.ResponseWriter, r *http.Request) {
	pending := a.Cfg.DBPath + ".pending-restore"
	pendingSize := uint64(0)
	if st, err := os.Stat(pending); err == nil {
		pendingSize = uint64(st.Size())
	}
	dbSize := uint64(0)
	if st, err := os.Stat(a.Cfg.DBPath); err == nil {
		dbSize = uint64(st.Size())
	}
	a.render(w, "admin_maintenance.html", a.adminCtx(r, "maintenance", map[string]any{
		"DBPath":         a.Cfg.DBPath,
		"DBSize":         dbSize,
		"PendingPath":    pending,
		"PendingSize":    pendingSize,
		"BackupDir":      a.Cfg.Backup.Dir,
		"BackupEnabled":  a.Cfg.Backup.Enabled,
		"BackupRetain":   a.Cfg.Backup.RetainDays,
	}))
}
