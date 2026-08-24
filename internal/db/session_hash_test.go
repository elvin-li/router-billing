package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Sessions must be stored hashed: a stolen DB file or backup must not yield
// replayable cookies.
func TestCreateSessionStoresHashNotPlaintext(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	raw := "raw-cookie-token-1"
	if err := d.CreateSession(ctx, raw, "admin", "admin", nil, time.Hour); err != nil {
		t.Fatal(err)
	}

	var stored string
	if err := d.conn.QueryRowContext(ctx, `SELECT token FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == raw {
		t.Fatal("session token stored in plaintext")
	}
	if want := HashToken(raw); stored != want {
		t.Fatalf("stored %q, want SHA-256 hash %q", stored, want)
	}

	// Lookup by raw token works; lookup by the stored hash must NOT — the
	// hash alone (e.g. from a leaked backup) is not a usable credential.
	if s, err := d.GetSession(ctx, raw); err != nil || s == nil {
		t.Fatalf("GetSession(raw) = %v, %v; want hit", s, err)
	}
	if s, err := d.GetSession(ctx, stored); err != nil || s != nil {
		t.Fatalf("GetSession(hash) = %v, %v; want miss", s, err)
	}
}

func TestDeleteSessionByRawAndByHash(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if err := d.CreateSession(ctx, "tok-a", "admin", "admin", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateSession(ctx, "tok-b", "admin", "admin", nil, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Logout path: delete by raw token.
	if err := d.DeleteSession(ctx, "tok-a"); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.GetSession(ctx, "tok-a"); s != nil {
		t.Fatal("tok-a should be gone after DeleteSession(raw)")
	}

	// Admin sessions page path: delete by the listed hash.
	if err := d.DeleteSessionByHash(ctx, HashToken("tok-b")); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.GetSession(ctx, "tok-b"); s != nil {
		t.Fatal("tok-b should be gone after DeleteSessionByHash")
	}
}

func TestKeepExceptHelpersHashTheKeepToken(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if err := d.CreateSession(ctx, "admin-keep", "admin", "a1", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateSession(ctx, "admin-kill", "admin", "a2", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	n, err := d.DeleteAllAdminSessionsExcept(ctx, "admin-keep")
	if err != nil || n != 1 {
		t.Fatalf("DeleteAllAdminSessionsExcept = %d, %v; want 1, nil", n, err)
	}
	if s, _ := d.GetSession(ctx, "admin-keep"); s == nil {
		t.Fatal("keep session must survive")
	}

	u, err := d.CreateUser(ctx, "13800150000", "h")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CreateSession(ctx, "user-keep", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateSession(ctx, "user-kill", "user", u.Phone, &u.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	n, err = d.DeleteUserSessionsExcept(ctx, u.ID, "user-keep")
	if err != nil || n != 1 {
		t.Fatalf("DeleteUserSessionsExcept = %d, %v; want 1, nil", n, err)
	}
	if s, _ := d.GetSession(ctx, "user-keep"); s == nil {
		t.Fatal("keep session must survive")
	}
}

// Upgrading a database that still holds plaintext tokens (pre-v0.97) must
// rewrite them to hashes WITHOUT invalidating the cookies clients hold.
func TestMigrationHashesLegacyPlaintextTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")
	ctx := context.Background()

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-hashing database: plaintext token row + user_version 0.
	raw := "legacy-plaintext-token"
	if _, err := d.conn.ExecContext(ctx,
		`INSERT INTO sessions (token, kind, subject, expires_at) VALUES (?, 'admin', 'admin', ?)`,
		raw, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-open: migration should hash the plaintext row exactly once.
	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	var stored string
	if err := d.conn.QueryRowContext(ctx, `SELECT token FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != HashToken(raw) {
		t.Fatalf("legacy token not hashed: %q", stored)
	}
	// The client's original cookie still resolves — no forced re-login.
	if s, err := d.GetSession(ctx, raw); err != nil || s == nil || s.Kind != "admin" {
		t.Fatalf("legacy cookie must survive migration; got %v, %v", s, err)
	}

	var version int
	if err := d.conn.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version < schemaVersionSessionHashes {
		t.Fatalf("user_version = %d, want >= %d", version, schemaVersionSessionHashes)
	}

	// Idempotence: a second migration pass must not double-hash. Re-opening
	// again leaves the stored value unchanged.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := d.GetSession(ctx, raw); err != nil || s == nil {
		t.Fatalf("cookie must survive repeated startups; got %v, %v", s, err)
	}
}
