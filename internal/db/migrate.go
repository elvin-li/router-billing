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
		// v0.103: store upstream PSP QR payload on the order so /api/pay/qr
		// no longer trusts the URL-supplied `payload=` parameter (open
		// QR-encoder vector). Existing pending orders won't have it
		// populated; they'll either get re-queried & finalized, or
		// auto-canceled by the stale-pending sweep.
		{"orders", "qr_payload", "TEXT NOT NULL DEFAULT ''"},
		{"sessions", "kind", "TEXT NOT NULL DEFAULT 'admin'"},
		{"sessions", "subject", "TEXT NOT NULL DEFAULT ''"},
		{"sessions", "user_id", "INTEGER"},
		{"users", "suspended", "INTEGER NOT NULL DEFAULT 0"},
		{"users", "totp_secret", "TEXT NOT NULL DEFAULT ''"},
		{"users", "totp_pending", "TEXT NOT NULL DEFAULT ''"},
		{"users", "notify_expiry", "INTEGER NOT NULL DEFAULT 1"},
		{"macs", "schedule_json", "TEXT NOT NULL DEFAULT ''"},
		// v0.82: per-MAC free-text notes — distinct from label which is
		// short. Lets support attach context like "customer's work tablet,
		// expected high traffic" without overloading the label.
		{"macs", "notes", "TEXT NOT NULL DEFAULT ''"},
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

	if err := migrateSessionTokensToHashes(d); err != nil {
		return fmt.Errorf("hash session tokens: %w", err)
	}
	return nil
}

// Schema versions tracked via PRAGMA user_version. Needed for the token-
// hashing migrations because raw tokens and SHA-256 hashes are both 64-char
// hex — indistinguishable by format.
const (
	// v0.113: sessions.token rewritten from raw cookie values to SHA-256.
	schemaVersionSessionHashes = 1
	// v0.113: user_trusted_devices.token likewise rewritten to SHA-256.
	schemaVersionTrustedDeviceHashes = 2
)

// migrateSessionTokensToHashes rewrites stored session and trusted-device
// tokens to their SHA-256 hashes, in one transaction per table, exactly
// once. Cookies on client devices hold the raw token and keep working:
// lookups hash the cookie value before comparing, so live sessions and
// trusted devices survive the upgrade with no forced re-login.
func migrateSessionTokensToHashes(d *sql.DB) error {
	var version int
	if err := d.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version < schemaVersionSessionHashes {
		if err := hashTokenColumn(d, "sessions", schemaVersionSessionHashes); err != nil {
			return err
		}
	}
	if version < schemaVersionTrustedDeviceHashes {
		if err := hashTokenColumn(d, "user_trusted_devices", schemaVersionTrustedDeviceHashes); err != nil {
			return err
		}
	}
	return nil
}

// hashTokenColumn rewrites every value in <table>.token to HashToken(value)
// and bumps PRAGMA user_version to `version`, all in one transaction.
func hashTokenColumn(d *sql.DB, table string, version int) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`SELECT token FROM ` + table) //nolint:gosec // table is a compile-time constant
	if err != nil {
		return err
	}
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		tokens = append(tokens, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range tokens {
		if _, err := tx.Exec(`UPDATE `+table+` SET token = ? WHERE token = ?`, //nolint:gosec // G202: table is a compile-time constant
			HashToken(t), t); err != nil {
			return err
		}
	}
	// PRAGMA doesn't support placeholders; the value is a trusted constant.
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return err
	}
	return tx.Commit()
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
