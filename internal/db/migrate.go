package db

import (
	"database/sql"
	"fmt"
)

// runMigrations brings an existing database up to the current schema.
// Idempotent — safe to run on every startup.
//
// Strategy:
//  1. Apply schema.sql (only creates missing tables/indexes).
//  2. For each column we may have added in a newer version, ALTER TABLE if absent.
//  3. One-off backfills (e.g., copy old sessions.username into sessions.subject).
func runMigrations(d *sql.DB) error {
	if _, err := d.Exec(schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}

	columns := []struct{ table, name, def string }{
		{"macs", "user_id", "INTEGER"},
		{"orders", "user_id", "INTEGER"},
		{"orders", "last_queried_at", "DATETIME"},
		{"sessions", "kind", "TEXT NOT NULL DEFAULT 'admin'"},
		{"sessions", "subject", "TEXT NOT NULL DEFAULT ''"},
		{"sessions", "user_id", "INTEGER"},
		{"users", "suspended", "INTEGER NOT NULL DEFAULT 0"},
		{"macs", "schedule_json", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, c := range columns {
		if err := addColumnIfMissing(d, c.table, c.name, c.def); err != nil {
			return fmt.Errorf("alter %s.%s: %w", c.table, c.name, err)
		}
	}

	// Backfill: older sessions had a `username` column; copy it into subject.
	if columnExists(d, "sessions", "username") {
		if _, err := d.Exec(`UPDATE sessions SET subject = username WHERE subject IS NULL OR subject = ''`); err != nil {
			return fmt.Errorf("backfill sessions.subject: %w", err)
		}
	}
	return nil
}

func columnExists(d *sql.DB, table, column string) bool {
	rows, err := d.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == column {
			return true
		}
	}
	return false
}

func addColumnIfMissing(d *sql.DB, table, column, def string) error {
	if columnExists(d, table, column) {
		return nil
	}
	_, err := d.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, def))
	return err
}
