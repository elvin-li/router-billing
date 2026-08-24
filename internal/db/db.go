package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"router-billing/internal/models"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type DB struct {
	conn *sql.DB
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir db dir: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)", path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite serializes writes; WAL gives us cheap reads
	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	// SECURITY: DB file contains bcrypt password hashes (admin + users) and
	// payment data. Clamp it down to owner-only — by default sqlite creates
	// with the process umask (often 0644). Safe to chmod unconditionally:
	// no-op when already 0600.
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(f); err == nil {
			_ = os.Chmod(f, 0o600)
		}
	}
	if err := runMigrations(conn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{conn: conn}, nil
}

func (d *DB) Close() error { return d.conn.Close() }

// Exec is a low-level escape hatch for one-off DDL/PRAGMA work (e.g. backup
// checkpoint). Prefer the typed methods elsewhere in this package.
func (d *DB) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.conn.ExecContext(ctx, query, args...)
}

// ---------- MAC ----------

const macCols = `id, mac, label, status, expires_at, user_id, schedule_json, notes, created_at, updated_at`

func scanMAC(row interface{ Scan(...any) error }) (*models.MAC, error) {
	var m models.MAC
	var userID sql.NullInt64
	if err := row.Scan(&m.ID, &m.Mac, &m.Label, &m.Status, &m.ExpiresAt, &userID, &m.ScheduleJSON, &m.Notes, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, err
	}
	if userID.Valid {
		v := userID.Int64
		m.UserID = &v
	}
	return &m, nil
}

// SetMACNotes writes free-text support notes onto a MAC row. v0.82.
// Caller should length-cap to a reasonable size before calling.
func (d *DB) SetMACNotes(ctx context.Context, mac, notes string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE macs SET notes = ?, updated_at = ? WHERE mac = ?`,
		notes, time.Now().UTC(), mac)
	return err
}

// SetMACSchedule writes the schedule JSON onto the MAC row. Pass "" to clear.
func (d *DB) SetMACSchedule(ctx context.Context, mac, scheduleJSON string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE macs SET schedule_json = ?, updated_at = CURRENT_TIMESTAMP WHERE mac = ?`,
		scheduleJSON, mac)
	return err
}

func (d *DB) ListMACs(ctx context.Context) ([]models.MAC, error) {
	return d.queryMACs(ctx, `SELECT `+macCols+` FROM macs ORDER BY expires_at DESC`)
}

// ListExpiringMACsWithoutRecentReminder returns active MACs that:
//   - have a user_id (so we have a phone to text),
//   - their user has notify_expiry = 1 (default; user can opt out),
//   - expire within `withinDays` from now (but haven't expired yet),
//   - haven't received an expiry_reminder audit entry in the last 22 hours
//     (so a daily loop never double-texts the same user).
//
// 22h instead of 24h gives the cron loop +/-1h slack — it's fine if a
// reminder lands at 09:00 one day and 08:58 the next.
func (d *DB) ListExpiringMACsWithoutRecentReminder(ctx context.Context, withinDays int) ([]models.MAC, error) {
	if withinDays <= 0 {
		withinDays = 3
	}
	rows, err := d.conn.QueryContext(ctx, `
		SELECT `+macCols+` FROM macs m
		WHERE m.status='active'
		  AND m.user_id IS NOT NULL
		  AND EXISTS (SELECT 1 FROM users u WHERE u.id = m.user_id AND u.notify_expiry = 1)
		  AND m.expires_at > CURRENT_TIMESTAMP
		  AND m.expires_at < datetime('now','+'||?||' days')
		  AND NOT EXISTS (
		    SELECT 1 FROM audit_log a
		    WHERE a.action = 'expiry_reminder'
		      AND a.target = m.mac
		      AND a.at >= datetime('now','-22 hours')
		  )
		ORDER BY m.expires_at ASC
		LIMIT 200`, withinDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.MAC
	for rows.Next() {
		m, err := scanMAC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// SearchMACs returns MACs where MAC or label contains q (case-insensitive
// LIKE). When q is empty, behaves like ListMACs. status (if non-empty)
// restricts to that exact status. limit defaults to 200, capped at 1000.
func (d *DB) SearchMACs(ctx context.Context, q, status string, limit int) ([]models.MAC, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var sb strings.Builder
	sb.WriteString(`SELECT ` + macCols + ` FROM macs WHERE 1=1`)
	args := []any{}
	if q != "" {
		// SQLite LIKE is case-insensitive for ASCII by default.
		sb.WriteString(` AND (mac LIKE ? OR label LIKE ?)`)
		pat := "%" + q + "%"
		args = append(args, pat, pat)
	}
	if status != "" {
		sb.WriteString(` AND status = ?`)
		args = append(args, status)
	}
	sb.WriteString(` ORDER BY expires_at DESC LIMIT ?`)
	args = append(args, limit)
	return d.queryMACs(ctx, sb.String(), args...)
}

func (d *DB) ListActiveMACs(ctx context.Context) ([]models.MAC, error) {
	return d.queryMACs(ctx, `SELECT `+macCols+` FROM macs WHERE status = 'active' AND expires_at > CURRENT_TIMESTAMP`)
}

func (d *DB) ListMACsForUser(ctx context.Context, userID int64) ([]models.MAC, error) {
	return d.queryMACs(ctx, `SELECT `+macCols+` FROM macs WHERE user_id = ? ORDER BY expires_at DESC`, userID)
}

func (d *DB) queryMACs(ctx context.Context, q string, args ...any) ([]models.MAC, error) {
	rows, err := d.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.MAC
	for rows.Next() {
		m, err := scanMAC(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (d *DB) GetMAC(ctx context.Context, mac string) (*models.MAC, error) {
	row := d.conn.QueryRowContext(ctx, `SELECT `+macCols+` FROM macs WHERE mac = ?`, mac)
	m, err := scanMAC(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

// UpsertMAC adds new MAC or extends existing one's expiry. Returns the post-state.
// If existing MAC is still active, new expiry = current_expiry + days.
// Otherwise new expiry = now + days. userID nil keeps the existing owner (or null).
func (d *DB) UpsertMAC(ctx context.Context, mac, label string, days int, userID *int64) (*models.MAC, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	existing, err := getMACTx(ctx, tx, mac)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var newExpiry time.Time
	if existing != nil && existing.ExpiresAt.After(now) && existing.Status == models.MACActive {
		newExpiry = existing.ExpiresAt.AddDate(0, 0, days)
	} else {
		newExpiry = now.AddDate(0, 0, days)
	}
	if existing == nil {
		var uid sql.NullInt64
		if userID != nil {
			uid = sql.NullInt64{Int64: *userID, Valid: true}
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO macs (mac, label, status, expires_at, user_id, created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?, ?)`,
			mac, label, newExpiry, uid, now, now)
	} else {
		newLabel := existing.Label
		if label != "" {
			newLabel = label
		}
		if userID != nil {
			_, err = tx.ExecContext(ctx,
				`UPDATE macs SET label = ?, status = 'active', expires_at = ?, user_id = ?, updated_at = ? WHERE mac = ?`,
				newLabel, newExpiry, *userID, now, mac)
		} else {
			_, err = tx.ExecContext(ctx,
				`UPDATE macs SET label = ?, status = 'active', expires_at = ?, updated_at = ? WHERE mac = ?`,
				newLabel, newExpiry, now, mac)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetMAC(ctx, mac)
}

func getMACTx(ctx context.Context, tx *sql.Tx, mac string) (*models.MAC, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+macCols+` FROM macs WHERE mac = ?`, mac)
	m, err := scanMAC(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (d *DB) DeleteMAC(ctx context.Context, mac string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM macs WHERE mac = ?`, mac)
	return err
}

func (d *DB) SetMACStatus(ctx context.Context, mac string, status models.MACStatus) error {
	_, err := d.conn.ExecContext(ctx, `UPDATE macs SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE mac = ?`, status, mac)
	return err
}

// SetMACLabel updates only the label. Used by /user/macs/label so a user can
// rename their own devices without changing expiry/status.
func (d *DB) SetMACLabel(ctx context.Context, mac, label string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE macs SET label = ?, updated_at = CURRENT_TIMESTAMP WHERE mac = ?`,
		label, mac)
	return err
}

// ReplaceMAC atomically transfers a user's active MAC to a new MAC. The old MAC
// is deleted from DB. Returns the new MAC row.
func (d *DB) ReplaceMAC(ctx context.Context, userID int64, oldMac, newMac, label string) (*models.MAC, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	old, err := getMACTx(ctx, tx, oldMac)
	if err != nil {
		return nil, err
	}
	if old == nil || old.UserID == nil || *old.UserID != userID {
		return nil, fmt.Errorf("MAC %s 不属于当前用户", oldMac)
	}
	if old.Status != models.MACActive || old.ExpiresAt.Before(time.Now().UTC()) {
		return nil, fmt.Errorf("MAC %s 已过期，无法转移", oldMac)
	}
	conflict, err := getMACTx(ctx, tx, newMac)
	if err != nil {
		return nil, err
	}
	if conflict != nil {
		return nil, fmt.Errorf("MAC %s 已被使用", newMac)
	}
	newExpiry := old.ExpiresAt
	if label == "" {
		label = old.Label
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM macs WHERE mac = ?`, oldMac); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO macs (mac, label, status, expires_at, user_id, created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?, ?)`,
		newMac, label, newExpiry, userID, now, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetMAC(ctx, newMac)
}

// ExpireDueMACs marks expired MACs and returns the ones newly expired.
// SELECT + UPDATE run in one transaction so the returned list is exactly
// the set of rows the UPDATE flipped — a MAC crossing the expiry boundary
// between the two statements can neither be missed by the caller's
// firewall revoke nor flipped without being reported.
func (d *DB) ExpireDueMACs(ctx context.Context) ([]string, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT mac FROM macs WHERE status = 'active' AND expires_at <= CURRENT_TIMESTAMP`)
	if err != nil {
		return nil, err
	}
	var expired []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			rows.Close()
			return nil, err
		}
		expired = append(expired, m)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(expired) == 0 {
		return nil, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE macs SET status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE status = 'active' AND expires_at <= CURRENT_TIMESTAMP`); err != nil {
		return nil, err
	}
	return expired, tx.Commit()
}

// ---------- Orders ----------

const orderCols = `id, order_no, mac, plan, days, amount_cents, status, payment_method, trade_no, user_id, last_queried_at, paid_at, created_at`

func scanOrder(row interface{ Scan(...any) error }) (*models.Order, error) {
	var o models.Order
	var userID sql.NullInt64
	var lastQ, paidAt sql.NullTime
	if err := row.Scan(&o.ID, &o.OrderNo, &o.Mac, &o.Plan, &o.Days, &o.AmountCents, &o.Status,
		&o.PaymentMethod, &o.TradeNo, &userID, &lastQ, &paidAt, &o.CreatedAt); err != nil {
		return nil, err
	}
	if userID.Valid {
		v := userID.Int64
		o.UserID = &v
	}
	if lastQ.Valid {
		t := lastQ.Time
		o.LastQueriedAt = &t
	}
	if paidAt.Valid {
		t := paidAt.Time
		o.PaidAt = &t
	}
	return &o, nil
}

func (d *DB) CreateOrder(ctx context.Context, o *models.Order) error {
	var uid sql.NullInt64
	if o.UserID != nil {
		uid = sql.NullInt64{Int64: *o.UserID, Valid: true}
	}
	res, err := d.conn.ExecContext(ctx,
		`INSERT INTO orders (order_no, mac, plan, days, amount_cents, status, payment_method, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.OrderNo, o.Mac, o.Plan, o.Days, o.AmountCents, o.Status, o.PaymentMethod, uid, time.Now().UTC())
	if err != nil {
		return err
	}
	id, _ := res.LastInsertId()
	o.ID = id
	return nil
}

func (d *DB) GetOrder(ctx context.Context, orderNo string) (*models.Order, error) {
	row := d.conn.QueryRowContext(ctx, `SELECT `+orderCols+` FROM orders WHERE order_no = ?`, orderNo)
	o, err := scanOrder(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (d *DB) ListOrders(ctx context.Context, limit int) ([]models.Order, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return d.queryOrders(ctx, `SELECT `+orderCols+` FROM orders ORDER BY created_at DESC LIMIT ?`, limit)
}

// OrderFilter is the optional filter set passed to SearchOrdersFiltered.
// Empty/zero fields are ignored.
type OrderFilter struct {
	Q      string // matches order_no / mac / trade_no via LIKE
	Status string // exact match on status column
	Since  string // YYYY-MM-DD UTC; only orders created on/after this date
	Until  string // YYYY-MM-DD UTC; only orders created on/before this date
	UserID int64  // 0 = no filter; non-zero filters to exactly that user_id
	Limit  int    // default 200, cap 1000
}

// SearchOrders is the legacy 3-arg shim — kept so existing callers don't
// break. New code should use SearchOrdersFiltered for date-range support.
func (d *DB) SearchOrders(ctx context.Context, q, status string, limit int) ([]models.Order, error) {
	return d.SearchOrdersFiltered(ctx, OrderFilter{Q: q, Status: status, Limit: limit})
}

// SearchOrdersFiltered returns orders matching any combination of substring,
// status, and a created_at date range. Date strings use YYYY-MM-DD shape
// (matches the HTML date-input format) interpreted in UTC.
func (d *DB) SearchOrdersFiltered(ctx context.Context, f OrderFilter) ([]models.Order, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var sb strings.Builder
	sb.WriteString(`SELECT ` + orderCols + ` FROM orders WHERE 1=1`)
	args := []any{}
	if f.Q != "" {
		sb.WriteString(` AND (order_no LIKE ? OR mac LIKE ? OR trade_no LIKE ?)`)
		pat := "%" + f.Q + "%"
		args = append(args, pat, pat, pat)
	}
	if f.Status != "" {
		sb.WriteString(` AND status = ?`)
		args = append(args, f.Status)
	}
	if f.Since != "" {
		sb.WriteString(` AND created_at >= datetime(?,'start of day')`)
		args = append(args, f.Since)
	}
	if f.Until != "" {
		// < start of NEXT day so the until date is inclusive.
		sb.WriteString(` AND created_at < datetime(?,'start of day','+1 day')`)
		args = append(args, f.Until)
	}
	if f.UserID > 0 {
		sb.WriteString(` AND user_id = ?`)
		args = append(args, f.UserID)
	}
	sb.WriteString(` ORDER BY created_at DESC LIMIT ?`)
	args = append(args, limit)
	return d.queryOrders(ctx, sb.String(), args...)
}

func (d *DB) ListOrdersForUser(ctx context.Context, userID int64, limit int) ([]models.Order, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	return d.queryOrders(ctx, `SELECT `+orderCols+` FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`, userID, limit)
}

// ListPendingOrdersToPoll returns pending orders older than `staleAfter` since
// last upstream query — these are candidates for our fallback poller.
func (d *DB) ListPendingOrdersToPoll(ctx context.Context, staleAfter time.Duration, maxAge time.Duration, limit int) ([]models.Order, error) {
	cutoffStale := time.Now().UTC().Add(-staleAfter)
	cutoffAge := time.Now().UTC().Add(-maxAge)
	q := `SELECT ` + orderCols + ` FROM orders
	      WHERE status = 'pending'
	        AND created_at > ?
	        AND (last_queried_at IS NULL OR last_queried_at < ?)
	      ORDER BY created_at DESC
	      LIMIT ?`
	return d.queryOrders(ctx, q, cutoffAge, cutoffStale, limit)
}

func (d *DB) MarkOrderQueried(ctx context.Context, orderNo string) error {
	_, err := d.conn.ExecContext(ctx, `UPDATE orders SET last_queried_at = ? WHERE order_no = ?`, time.Now().UTC(), orderNo)
	return err
}

func (d *DB) queryOrders(ctx context.Context, q string, args ...any) ([]models.Order, error) {
	rows, err := d.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Order
	for rows.Next() {
		o, err := scanOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

// MarkOrderPaid sets status=paid atomically; returns (transitioned, order, err).
// Idempotent — re-calling for an already-paid order returns transitioned=false.
func (d *DB) MarkOrderPaid(ctx context.Context, orderNo, tradeNo string) (bool, *models.Order, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return false, nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `SELECT `+orderCols+` FROM orders WHERE order_no = ?`, orderNo)
	o, err := scanOrder(row)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil, fmt.Errorf("order %s not found", orderNo)
	}
	if err != nil {
		return false, nil, err
	}
	if o.Status == models.OrderPaid {
		return false, o, nil
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE orders SET status = 'paid', trade_no = ?, paid_at = ? WHERE order_no = ?`, tradeNo, now, orderNo); err != nil {
		return false, nil, err
	}
	if err := tx.Commit(); err != nil {
		return false, nil, err
	}
	o.Status = models.OrderPaid
	o.TradeNo = tradeNo
	o.PaidAt = &now
	return true, o, nil
}

// MarkOrderRefunded transitions a paid order to refunded and rolls back the
// MAC's expires_at by the order's `days` value. If the rollback puts
// expires_at in the past, the MAC's status flips to expired so the firewall
// reconciler revokes the entry on the next pass.
//
// Returns the rolled-back MAC row (or nil if the order's MAC no longer
// exists). Only `paid` orders can be refunded — calling for any other
// status returns an error so the admin gets a clear signal.
//
// All steps run in one transaction so a crash mid-refund either does the
// whole thing or none of it.
func (d *DB) MarkOrderRefunded(ctx context.Context, orderNo, reason string) (*models.MAC, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `SELECT `+orderCols+` FROM orders WHERE order_no = ?`, orderNo)
	o, err := scanOrder(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("order %s not found", orderNo)
	}
	if err != nil {
		return nil, err
	}
	if o.Status != models.OrderPaid {
		return nil, fmt.Errorf("order %s is %s, only paid orders can be refunded", orderNo, o.Status)
	}

	now := time.Now().UTC()
	// Record the refund reason in the order's trade_no append OR a dedicated
	// column — but adding a column for one-off use is wasteful. Append to
	// trade_no with a separator so the original gateway ID survives.
	newTradeNo := o.TradeNo
	if reason != "" {
		if newTradeNo != "" {
			newTradeNo += " | "
		}
		newTradeNo += "refund: " + reason
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE orders SET status = 'refunded', trade_no = ? WHERE order_no = ?`,
		newTradeNo, orderNo); err != nil {
		return nil, err
	}

	// Roll back the MAC's expires_at by `days`. If the MAC is gone (deleted
	// manually) we silently succeed — the order refund still stands.
	macRow := tx.QueryRowContext(ctx,
		`SELECT id, mac, label, status, expires_at, user_id, schedule_json, notes, created_at, updated_at
		 FROM macs WHERE mac = ?`, o.Mac)
	var m models.MAC
	var uid sql.NullInt64
	err = macRow.Scan(&m.ID, &m.Mac, &m.Label, &m.Status, &m.ExpiresAt, &uid, &m.ScheduleJSON, &m.Notes, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if uid.Valid {
		v := uid.Int64
		m.UserID = &v
	}

	newExpiry := m.ExpiresAt.Add(-time.Duration(o.Days) * 24 * time.Hour)
	newStatus := m.Status
	if !newExpiry.After(now) {
		newStatus = models.MACExpired
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE macs SET expires_at = ?, status = ?, updated_at = ? WHERE id = ?`,
		newExpiry, string(newStatus), now, m.ID); err != nil {
		return nil, err
	}
	m.ExpiresAt = newExpiry
	m.Status = newStatus
	m.UpdatedAt = now

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &m, nil
}

// CancelPendingOrder transitions a `pending` order to `failed`. Used by the
// programmatic /api/admin/orders/cancel endpoint (v0.52) for cleanup
// automation that wants to retire stuck orders (gateway didn't respond,
// customer abandoned, etc.) without waiting for them to drift to `expired`
// on their own.
//
// Atomic — uses UPDATE WHERE status='pending' so a race that just paid
// the order can't accidentally lose the payment. Returns:
//   - the order row + nil on success
//   - nil + sql.ErrNoRows if order_no doesn't exist
//   - nil + fmt-wrapped status error if the order isn't pending
func (d *DB) CancelPendingOrder(ctx context.Context, orderNo string) (*models.Order, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `SELECT `+orderCols+` FROM orders WHERE order_no = ?`, orderNo)
	o, err := scanOrder(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	if o.Status != models.OrderPending {
		return nil, fmt.Errorf("order %s is %s, only pending orders can be canceled", orderNo, o.Status)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE orders SET status = 'failed' WHERE order_no = ? AND status = 'pending'`, orderNo)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Lost a race — somebody else transitioned the order in between
		// our SELECT and our UPDATE. Surface as a conflict.
		return nil, fmt.Errorf("order %s no longer pending (raced)", orderNo)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	o.Status = models.OrderFailed
	return o, nil
}

// CancelStalePendingOrders flips every order with status='pending' AND
// created_at older than `olderThan` to status='failed' in one statement.
// Returns the number of rows that flipped.
//
// Used by v0.55's /api/admin/orders/cancel-stale endpoint for periodic
// cleanup automation: cron polls hourly with older_than_hours=24 to keep
// the pending backlog small. Atomic (single UPDATE) so a payment that
// arrives mid-sweep either wins (status moves to paid before our UPDATE
// touches it) or loses (we already set it to failed and the payment
// handler logs the conflict). The status='pending' guard in the WHERE
// makes the race outcome correct either way.
func (d *DB) CancelStalePendingOrders(ctx context.Context, olderThan time.Duration) (int, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("olderThan must be > 0")
	}
	cutoff := time.Now().UTC().Add(-olderThan)
	res, err := d.conn.ExecContext(ctx,
		`UPDATE orders SET status = 'failed' WHERE status = 'pending' AND created_at < ?`,
		cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ---------- Sessions ----------

func (d *DB) CreateSession(ctx context.Context, token, kind, subject string, userID *int64, ttl time.Duration) error {
	var uid sql.NullInt64
	if userID != nil {
		uid = sql.NullInt64{Int64: *userID, Valid: true}
	}
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO sessions (token, kind, subject, user_id, expires_at) VALUES (?, ?, ?, ?, ?)`,
		token, kind, subject, uid, time.Now().UTC().Add(ttl))
	return err
}

type SessionRow struct {
	Kind    string
	Subject string
	UserID  *int64
}

func (d *DB) GetSession(ctx context.Context, token string) (*SessionRow, error) {
	row := d.conn.QueryRowContext(ctx,
		`SELECT kind, subject, user_id FROM sessions WHERE token = ? AND expires_at > CURRENT_TIMESTAMP`, token)
	var s SessionRow
	var uid sql.NullInt64
	err := row.Scan(&s.Kind, &s.Subject, &uid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if uid.Valid {
		v := uid.Int64
		s.UserID = &v
	}
	return &s, nil
}

func (d *DB) DeleteSession(ctx context.Context, token string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// DeleteSessionsByUserID purges every session belonging to a given user.
// Called by handleAdminUserSuspend so a suspended user is logged out
// immediately, not whenever their current session expires.
func (d *DB) DeleteSessionsByUserID(ctx context.Context, userID int64) (int64, error) {
	res, err := d.conn.ExecContext(ctx,
		`DELETE FROM sessions WHERE kind = 'user' AND user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SessionRecord is one row of the live-sessions list used by /admin/sessions.
type SessionRecord struct {
	Token     string // server-side primary key — shown truncated in UI
	Kind      string // "admin" | "user"
	Subject   string // username for admin, phone for user
	UserID    *int64 // present for kind=user
	ExpiresAt time.Time
	IsCurrent bool // filled by the handler, not from SQL
}

// ListActiveSessions returns every unexpired session. Sort: most-recently-
// expiring last (so the soon-to-die ones surface first).
func (d *DB) ListActiveSessions(ctx context.Context, limit int) ([]SessionRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.conn.QueryContext(ctx, `
		SELECT token, kind, subject, user_id, expires_at
		FROM sessions
		WHERE expires_at > CURRENT_TIMESTAMP
		ORDER BY expires_at ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRecord
	for rows.Next() {
		var s SessionRecord
		var uid sql.NullInt64
		if err := rows.Scan(&s.Token, &s.Kind, &s.Subject, &uid, &s.ExpiresAt); err != nil {
			return nil, err
		}
		if uid.Valid {
			v := uid.Int64
			s.UserID = &v
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListSessionsForUser returns every non-expired session belonging to userID.
// Sorted by expires_at ascending so the soonest-to-die appears first — same
// convention as ListActiveSessions, helpful for "review my sessions" pages.
func (d *DB) ListSessionsForUser(ctx context.Context, userID int64) ([]SessionRecord, error) {
	rows, err := d.conn.QueryContext(ctx, `
		SELECT token, kind, subject, user_id, expires_at
		FROM sessions
		WHERE kind = 'user' AND user_id = ? AND expires_at > CURRENT_TIMESTAMP
		ORDER BY expires_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRecord
	for rows.Next() {
		var s SessionRecord
		var uid sql.NullInt64
		if err := rows.Scan(&s.Token, &s.Kind, &s.Subject, &uid, &s.ExpiresAt); err != nil {
			return nil, err
		}
		if uid.Valid {
			v := uid.Int64
			s.UserID = &v
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteAllAdminSessionsExcept logs out every admin session except `keep`.
// Useful for "I lost my laptop" — keep current cookie alive, kill the rest.
// Returns the number of sessions deleted.
func (d *DB) DeleteAllAdminSessionsExcept(ctx context.Context, keep string) (int64, error) {
	res, err := d.conn.ExecContext(ctx,
		`DELETE FROM sessions WHERE kind = 'admin' AND token != ?`, keep)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteAllUserSessions wipes every user session unconditionally. Use sparingly
// — this signs out EVERY user, including those who aren't compromised. Meant
// for emergency response to a confirmed breach.
func (d *DB) DeleteAllUserSessions(ctx context.Context) (int64, error) {
	res, err := d.conn.ExecContext(ctx,
		`DELETE FROM sessions WHERE kind = 'user'`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteUserSessionsExcept is the user equivalent — logs out every session
// belonging to userID except `keep`, used by "sign me out of all other
// devices". Returns the number of sessions deleted.
func (d *DB) DeleteUserSessionsExcept(ctx context.Context, userID int64, keep string) (int64, error) {
	res, err := d.conn.ExecContext(ctx,
		`DELETE FROM sessions WHERE kind = 'user' AND user_id = ? AND token != ?`,
		userID, keep)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CountUserSessions returns the number of non-expired sessions for userID.
// Cheaper than fetching ListActiveSessions just to count.
func (d *DB) CountUserSessions(ctx context.Context, userID int64) (int, error) {
	var n int
	err := d.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions
		 WHERE kind = 'user' AND user_id = ? AND expires_at > CURRENT_TIMESTAMP`,
		userID).Scan(&n)
	return n, err
}

func (d *DB) PurgeExpiredSessions(ctx context.Context) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP`)
	return err
}

// ---------- Users ----------

func (d *DB) CreateUser(ctx context.Context, phone, passwordHash string) (*models.User, error) {
	now := time.Now().UTC()
	res, err := d.conn.ExecContext(ctx,
		`INSERT INTO users (phone, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		phone, passwordHash, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	// Schema default sets notify_expiry = 1; mirror that in the returned
	// struct so callers don't see a zero-value mismatch.
	return &models.User{
		ID:           id,
		Phone:        phone,
		PasswordHash: passwordHash,
		NotifyExpiry: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// userColumns is the canonical SELECT list — extend here when adding columns.
const userColumns = "id, phone, password_hash, suspended, totp_secret, totp_pending, notify_expiry, created_at, updated_at"

func scanUserRow(row interface{ Scan(...any) error }) (*models.User, error) {
	var u models.User
	var susp, notify int
	err := row.Scan(&u.ID, &u.Phone, &u.PasswordHash, &susp, &u.TOTPSecret, &u.TOTPPending, &notify, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.Suspended = susp != 0
	u.NotifyExpiry = notify != 0
	return &u, nil
}

func (d *DB) GetUserByPhone(ctx context.Context, phone string) (*models.User, error) {
	row := d.conn.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE phone = ?`, phone)
	u, err := scanUserRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (d *DB) GetUser(ctx context.Context, id int64) (*models.User, error) {
	row := d.conn.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	u, err := scanUserRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (d *DB) UpdateUserPassword(ctx context.Context, userID int64, passwordHash string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		passwordHash, time.Now().UTC(), userID)
	return err
}

// SetUserNotifyExpiry flips the per-user opt-out for the expiry-reminder
// SMS loop. Default is on; user toggles via /user/notifications.
func (d *DB) SetUserNotifyExpiry(ctx context.Context, userID int64, on bool) error {
	v := 0
	if on {
		v = 1
	}
	_, err := d.conn.ExecContext(ctx,
		`UPDATE users SET notify_expiry = ?, updated_at = ? WHERE id = ?`,
		v, time.Now().UTC(), userID)
	return err
}

// SetUserTOTPPending stashes a not-yet-confirmed base32 secret. Overwrites any
// prior pending so re-clicking "enable" gives a fresh QR.
func (d *DB) SetUserTOTPPending(ctx context.Context, userID int64, secret string) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE users SET totp_pending = ?, updated_at = ? WHERE id = ?`,
		secret, time.Now().UTC(), userID)
	return err
}

// ConfirmUserTOTP promotes the pending secret to live, clearing the pending
// slot. Caller should verify the code first.
func (d *DB) ConfirmUserTOTP(ctx context.Context, userID int64) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE users SET totp_secret = totp_pending, totp_pending = '', updated_at = ?
		 WHERE id = ? AND totp_pending != ''`,
		time.Now().UTC(), userID)
	return err
}

// ClearUserTOTP turns 2FA off and wipes any half-enrolled pending secret.
// Also clears backup codes AND trusted devices so a future enrollment
// starts from a clean slate — and so an admin reset doesn't leave behind
// trust-tokens that would bypass the next enrollment.
func (d *DB) ClearUserTOTP(ctx context.Context, userID int64) error {
	if _, err := d.conn.ExecContext(ctx,
		`UPDATE users SET totp_secret = '', totp_pending = '', updated_at = ? WHERE id = ?`,
		time.Now().UTC(), userID); err != nil {
		return err
	}
	if err := d.ClearBackupCodes(ctx, userID); err != nil {
		return err
	}
	return d.DeleteAllTrustedDevices(ctx, userID)
}

func (d *DB) ListUsers(ctx context.Context, limit int) ([]models.User, error) {
	return d.SearchUsers(ctx, "", limit)
}

// SearchUsers returns users whose phone CONTAINS the query string.
func (d *DB) SearchUsers(ctx context.Context, q string, limit int) ([]models.User, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if q == "" {
		rows, err = d.conn.QueryContext(ctx,
			`SELECT `+userColumns+` FROM users ORDER BY created_at DESC LIMIT ?`, limit)
	} else {
		rows, err = d.conn.QueryContext(ctx,
			`SELECT `+userColumns+` FROM users WHERE phone LIKE ? ORDER BY created_at DESC LIMIT ?`,
			"%"+q+"%", limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.User
	for rows.Next() {
		u, err := scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (d *DB) SuspendUser(ctx context.Context, id int64, suspended bool) error {
	v := 0
	if suspended {
		v = 1
	}
	_, err := d.conn.ExecContext(ctx,
		`UPDATE users SET suspended = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, v, id)
	if err == nil && suspended {
		// also drop the user's active sessions so a suspended user can't keep using the app
		_, _ = d.conn.ExecContext(ctx, `DELETE FROM sessions WHERE kind='user' AND user_id = ?`, id)
	}
	return err
}

// DeleteUser removes a user. macs.user_id / orders.user_id are SET NULL by FK.
func (d *DB) DeleteUser(ctx context.Context, id int64) error {
	_, _ = d.conn.ExecContext(ctx, `DELETE FROM sessions WHERE kind='user' AND user_id = ?`, id)
	_, err := d.conn.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// ---------- TOTP Trusted devices ----------

// CreateTrustedDevice records a new "remember this browser" entry. Token
// must be a high-entropy random string the caller will also stuff into a
// cookie.
func (d *DB) CreateTrustedDevice(ctx context.Context, userID int64, token, label string, ttl time.Duration) (*models.TrustedDevice, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)
	res, err := d.conn.ExecContext(ctx,
		`INSERT INTO user_trusted_devices (user_id, token, label, expires_at, last_seen, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		userID, token, label, exp, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &models.TrustedDevice{
		ID: id, UserID: userID, Token: token, Label: label,
		ExpiresAt: exp, LastSeen: now, CreatedAt: now,
	}, nil
}

// GetTrustedDevice looks up by raw token, returning nil if missing/expired.
// On hit it also bumps last_seen so the /user/2fa page shows fresh data.
func (d *DB) GetTrustedDevice(ctx context.Context, token string) (*models.TrustedDevice, error) {
	if token == "" {
		return nil, nil
	}
	row := d.conn.QueryRowContext(ctx,
		`SELECT id, user_id, token, label, expires_at, last_seen, created_at
		 FROM user_trusted_devices WHERE token = ? AND expires_at > ?`,
		token, time.Now().UTC())
	var t models.TrustedDevice
	err := row.Scan(&t.ID, &t.UserID, &t.Token, &t.Label, &t.ExpiresAt, &t.LastSeen, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Bump last_seen — best effort; failure shouldn't block login.
	_, _ = d.conn.ExecContext(ctx,
		`UPDATE user_trusted_devices SET last_seen = ? WHERE id = ?`,
		time.Now().UTC(), t.ID)
	return &t, nil
}

// ListTrustedDevices returns every device row for userID (including expired
// — the UI shows them separately). Newest first.
func (d *DB) ListTrustedDevices(ctx context.Context, userID int64) ([]models.TrustedDevice, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT id, user_id, token, label, expires_at, last_seen, created_at
		 FROM user_trusted_devices WHERE user_id = ? ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.TrustedDevice
	for rows.Next() {
		var t models.TrustedDevice
		if err := rows.Scan(&t.ID, &t.UserID, &t.Token, &t.Label, &t.ExpiresAt, &t.LastSeen, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTrustedDevice removes one row by ID — but only if it belongs to the
// given user (defense in depth against IDOR if the form is hand-crafted).
func (d *DB) DeleteTrustedDevice(ctx context.Context, userID, deviceID int64) error {
	_, err := d.conn.ExecContext(ctx,
		`DELETE FROM user_trusted_devices WHERE id = ? AND user_id = ?`,
		deviceID, userID)
	return err
}

// DeleteAllTrustedDevices nukes every row for userID. Called from
// ClearUserTOTP so disabling 2FA / admin-reset also wipes trust.
func (d *DB) DeleteAllTrustedDevices(ctx context.Context, userID int64) error {
	_, err := d.conn.ExecContext(ctx,
		`DELETE FROM user_trusted_devices WHERE user_id = ?`, userID)
	return err
}

// PurgeExpiredTrustedDevices sweeps stale rows. Cheap to run from a janitor.
func (d *DB) PurgeExpiredTrustedDevices(ctx context.Context) error {
	_, err := d.conn.ExecContext(ctx,
		`DELETE FROM user_trusted_devices WHERE expires_at <= ?`, time.Now().UTC())
	return err
}

// ---------- TOTP Backup codes ----------

// ReplaceBackupCodes wipes any prior codes for userID and inserts fresh
// bcrypt-hashed codes in one transaction. Order of `hashes` is preserved
// so callers can correlate with the original plaintexts they're displaying.
func (d *DB) ReplaceBackupCodes(ctx context.Context, userID int64, hashes []string) error {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_backup_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)`,
			userID, h, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListBackupCodes returns every row for userID (both used and unused), newest
// last. Used by the /user/2fa page to show "N remaining".
func (d *DB) ListBackupCodes(ctx context.Context, userID int64) ([]models.BackupCode, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT id, user_id, code_hash, used_at, created_at FROM user_backup_codes
		 WHERE user_id = ? ORDER BY id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.BackupCode
	for rows.Next() {
		var b models.BackupCode
		var used sql.NullTime
		if err := rows.Scan(&b.ID, &b.UserID, &b.CodeHash, &used, &b.CreatedAt); err != nil {
			return nil, err
		}
		if used.Valid {
			t := used.Time
			b.UsedAt = &t
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// UnusedBackupCodes returns rows where used_at IS NULL. Used during verify.
func (d *DB) UnusedBackupCodes(ctx context.Context, userID int64) ([]models.BackupCode, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT id, user_id, code_hash, used_at, created_at FROM user_backup_codes
		 WHERE user_id = ? AND used_at IS NULL ORDER BY id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.BackupCode
	for rows.Next() {
		var b models.BackupCode
		var used sql.NullTime
		if err := rows.Scan(&b.ID, &b.UserID, &b.CodeHash, &used, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// MarkBackupCodeUsed flips used_at on a specific row. Idempotent.
func (d *DB) MarkBackupCodeUsed(ctx context.Context, id int64) error {
	_, err := d.conn.ExecContext(ctx,
		`UPDATE user_backup_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		time.Now().UTC(), id)
	return err
}

// ClearBackupCodes wipes every row for userID. Called from ClearUserTOTP so
// disabling 2FA also cleans up backup codes.
func (d *DB) ClearBackupCodes(ctx context.Context, userID int64) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM user_backup_codes WHERE user_id = ?`, userID)
	return err
}

// ---------- Password resets (SMS forgot-password) ----------

// CreatePasswordReset stores a fresh reset row for userID. Any prior pending
// reset for the same user is deleted so codes don't accumulate. The caller
// supplies a bcrypt hash of the actual code — the plaintext is only ever in
// the SMS body.
func (d *DB) CreatePasswordReset(ctx context.Context, userID int64, codeHash string, ttl time.Duration) (*models.PasswordReset, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO password_resets (user_id, code_hash, attempts, expires_at, created_at) VALUES (?, ?, 0, ?, ?)`,
		userID, codeHash, exp, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &models.PasswordReset{ID: id, UserID: userID, CodeHash: codeHash, ExpiresAt: exp, CreatedAt: now}, nil
}

// GetActivePasswordReset returns the unexpired reset row for userID, or nil.
// Expired rows are filtered out (the verify handler treats them as "no row").
func (d *DB) GetActivePasswordReset(ctx context.Context, userID int64) (*models.PasswordReset, error) {
	row := d.conn.QueryRowContext(ctx,
		`SELECT id, user_id, code_hash, attempts, expires_at, created_at
		 FROM password_resets WHERE user_id = ? AND expires_at > ? ORDER BY id DESC LIMIT 1`,
		userID, time.Now().UTC())
	var r models.PasswordReset
	err := row.Scan(&r.ID, &r.UserID, &r.CodeHash, &r.Attempts, &r.ExpiresAt, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// BumpPasswordResetAttempts atomically increments attempts. Returns the new
// count so the caller can decide to expire the code (>= maxAttempts) and
// audit-log the failure.
func (d *DB) BumpPasswordResetAttempts(ctx context.Context, id int64) (int, error) {
	if _, err := d.conn.ExecContext(ctx,
		`UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?`, id); err != nil {
		return 0, err
	}
	var n int
	if err := d.conn.QueryRowContext(ctx, `SELECT attempts FROM password_resets WHERE id = ?`, id).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// DeletePasswordReset removes the row by primary key. Used on success and
// when the attempt cap is reached.
func (d *DB) DeletePasswordReset(ctx context.Context, id int64) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM password_resets WHERE id = ?`, id)
	return err
}

// PurgeExpiredPasswordResets sweeps stale rows. Cheap to run from a janitor.
func (d *DB) PurgeExpiredPasswordResets(ctx context.Context) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM password_resets WHERE expires_at <= ?`, time.Now().UTC())
	return err
}

// ---------- Sightings ----------

func (d *DB) UpsertSighting(ctx context.Context, mac, ip, hostname string) error {
	now := time.Now().UTC()
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO device_sightings (mac, last_ip, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(mac) DO UPDATE SET
		   last_ip = excluded.last_ip,
		   hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE device_sightings.hostname END,
		   last_seen = excluded.last_seen`,
		mac, ip, hostname, now, now)
	return err
}

// GetSightingForMAC returns the latest sighting row for a single MAC, or
// nil if the network detector has never seen it. Used by the v0.48 MAC
// detail page (v0.73) to show "last online: 2 hours ago at 192.168.5.42".
func (d *DB) GetSightingForMAC(ctx context.Context, mac string) (*models.Sighting, error) {
	row := d.conn.QueryRowContext(ctx,
		`SELECT mac, last_ip, hostname, first_seen, last_seen FROM device_sightings WHERE mac = ?`,
		mac)
	var s models.Sighting
	err := row.Scan(&s.MAC, &s.LastIP, &s.Hostname, &s.FirstSeen, &s.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (d *DB) ListRecentSightings(ctx context.Context, since time.Duration) ([]models.Sighting, error) {
	cutoff := time.Now().UTC().Add(-since)
	rows, err := d.conn.QueryContext(ctx,
		`SELECT mac, last_ip, hostname, first_seen, last_seen FROM device_sightings WHERE last_seen > ? ORDER BY last_seen DESC`,
		cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Sighting
	for rows.Next() {
		var s models.Sighting
		if err := rows.Scan(&s.MAC, &s.LastIP, &s.Hostname, &s.FirstSeen, &s.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) PurgeOldSightings(ctx context.Context, olderThan time.Duration) error {
	cutoff := time.Now().UTC().Add(-olderThan)
	_, err := d.conn.ExecContext(ctx, `DELETE FROM device_sightings WHERE last_seen < ?`, cutoff)
	return err
}

// ---------- Stats ----------

type Stats struct {
	Total        int
	Active       int
	Expired      int
	RevenueCents int
	Users        int
}

func (d *DB) Stats(ctx context.Context) (Stats, error) {
	var s Stats
	queries := []struct {
		q   string
		out *int
	}{
		{`SELECT COUNT(*) FROM macs`, &s.Total},
		{`SELECT COUNT(*) FROM macs WHERE status='active' AND expires_at > CURRENT_TIMESTAMP`, &s.Active},
		{`SELECT COUNT(*) FROM macs WHERE status IN ('expired','blocked') OR expires_at <= CURRENT_TIMESTAMP`, &s.Expired},
		{`SELECT COALESCE(SUM(amount_cents),0) FROM orders WHERE status='paid'`, &s.RevenueCents},
		{`SELECT COUNT(*) FROM users`, &s.Users},
	}
	for _, q := range queries {
		if err := d.conn.QueryRowContext(ctx, q.q).Scan(q.out); err != nil {
			return s, err
		}
	}
	return s, nil
}

// AdminDigestStats is the count set the daily admin-digest SMS embeds.
// Yesterday's revenue (00:00 yesterday UTC .. 00:00 today UTC) + today's
// failed-order count + count of MACs expiring within the next 3 days.
type AdminDigestStats struct {
	YesterdayRevenueCents int
	YesterdayPaidOrders   int
	ExpiringWithin3Days   int
	FailedOrdersToday     int
}

func (d *DB) AdminDigestStats(ctx context.Context) (AdminDigestStats, error) {
	var s AdminDigestStats
	queries := []struct {
		q   string
		out *int
	}{
		{`SELECT COALESCE(SUM(amount_cents),0) FROM orders
		   WHERE status='paid'
		     AND paid_at >= datetime('now','start of day','-1 day')
		     AND paid_at <  datetime('now','start of day')`, &s.YesterdayRevenueCents},
		{`SELECT COUNT(*) FROM orders
		   WHERE status='paid'
		     AND paid_at >= datetime('now','start of day','-1 day')
		     AND paid_at <  datetime('now','start of day')`, &s.YesterdayPaidOrders},
		{`SELECT COUNT(*) FROM macs
		   WHERE status='active'
		     AND expires_at > CURRENT_TIMESTAMP
		     AND expires_at < datetime('now','+3 days')`, &s.ExpiringWithin3Days},
		{`SELECT COUNT(*) FROM orders
		   WHERE status='failed'
		     AND created_at >= datetime('now','start of day')`, &s.FailedOrdersToday},
	}
	for _, q := range queries {
		if err := d.conn.QueryRowContext(ctx, q.q).Scan(q.out); err != nil {
			return s, err
		}
	}
	return s, nil
}

// DashboardSnapshot is a roll-up tailored for /admin/dashboard. Fits in
// one SQL round-trip per stat so the page renders fast even on a low-end
// router. All counts are best-effort — errors are returned but the
// caller decides whether to swallow them.
type DashboardSnapshot struct {
	TodayRevenueCents   int
	TodayPaidOrders     int
	TodayNewUsers       int
	TodayNewMACs        int
	Week7RevenueCents   int
	Week7PaidOrders     int
	Month30RevenueCents int // last 30 days
	Month30PaidOrders   int
	Month30NewUsers     int
	// Previous-period counters for month-over-month delta. The window is
	// days -60 .. -30 from now, exclusive of the current Month30 window so
	// no double-counting. Used by /admin/dashboard to render "+12% vs
	// prev 30d" pills next to the Month30* values.
	PrevMonth30RevenueCents int
	PrevMonth30PaidOrders   int
	PrevMonth30NewUsers     int
	ActiveSessions          int
}

func (d *DB) DashboardSnapshot(ctx context.Context) (DashboardSnapshot, error) {
	var s DashboardSnapshot
	// Use datetime comparisons against start-of-day so the format that
	// modernc.org/sqlite writes for time.Time (RFC3339-ish with timezone
	// offset) isn't tripped up by the date() function's expectation of a
	// plain YYYY-MM-DD prefix.
	queries := []struct {
		q   string
		out *int
	}{
		{`SELECT COALESCE(SUM(amount_cents),0) FROM orders WHERE status='paid' AND paid_at >= datetime('now','start of day')`, &s.TodayRevenueCents},
		{`SELECT COUNT(*) FROM orders WHERE status='paid' AND paid_at >= datetime('now','start of day')`, &s.TodayPaidOrders},
		{`SELECT COUNT(*) FROM users WHERE created_at >= datetime('now','start of day')`, &s.TodayNewUsers},
		{`SELECT COUNT(*) FROM macs WHERE created_at >= datetime('now','start of day')`, &s.TodayNewMACs},
		{`SELECT COALESCE(SUM(amount_cents),0) FROM orders WHERE status='paid' AND paid_at >= datetime('now','-7 days')`, &s.Week7RevenueCents},
		{`SELECT COUNT(*) FROM orders WHERE status='paid' AND paid_at >= datetime('now','-7 days')`, &s.Week7PaidOrders},
		{`SELECT COALESCE(SUM(amount_cents),0) FROM orders WHERE status='paid' AND paid_at >= datetime('now','-30 days')`, &s.Month30RevenueCents},
		{`SELECT COUNT(*) FROM orders WHERE status='paid' AND paid_at >= datetime('now','-30 days')`, &s.Month30PaidOrders},
		{`SELECT COUNT(*) FROM users WHERE created_at >= datetime('now','-30 days')`, &s.Month30NewUsers},
		// Previous-period window: -60d .. -30d. Exclusive on the upper
		// edge so the current Month30 window doesn't overlap. SQLite's
		// `datetime('now','-30 days')` is the boundary both windows share.
		{`SELECT COALESCE(SUM(amount_cents),0) FROM orders WHERE status='paid' AND paid_at >= datetime('now','-60 days') AND paid_at < datetime('now','-30 days')`, &s.PrevMonth30RevenueCents},
		{`SELECT COUNT(*) FROM orders WHERE status='paid' AND paid_at >= datetime('now','-60 days') AND paid_at < datetime('now','-30 days')`, &s.PrevMonth30PaidOrders},
		{`SELECT COUNT(*) FROM users WHERE created_at >= datetime('now','-60 days') AND created_at < datetime('now','-30 days')`, &s.PrevMonth30NewUsers},
		{`SELECT COUNT(*) FROM sessions WHERE expires_at > CURRENT_TIMESTAMP`, &s.ActiveSessions},
	}
	for _, q := range queries {
		if err := d.conn.QueryRowContext(ctx, q.q).Scan(q.out); err != nil {
			return s, err
		}
	}
	return s, nil
}

// AttentionCounts surfaces things admin should probably look at.
// Empty counts → green; non-zero → render highlighted in the dashboard.
type AttentionCounts struct {
	ExpiringSoon   int // active MACs whose expiry is < 7 days from now
	StalePending   int // orders still pending after 10 min
	SuspendedUsers int
	FailedToday    int // orders with status='failed' created today
	// v0.59 additions: observability tables. Non-zero means the operator
	// should look at /admin/sms-log or /admin/webhook-log respectively.
	SMSFailures24h     int // sms_log rows with success=0 in the last 24h
	WebhookFailures24h int // webhook_deliveries rows with success=0 in the last 24h
}

func (d *DB) Attention(ctx context.Context) (AttentionCounts, error) {
	var a AttentionCounts
	queries := []struct {
		q   string
		out *int
	}{
		{`SELECT COUNT(*) FROM macs WHERE status='active' AND expires_at > CURRENT_TIMESTAMP AND expires_at < datetime('now','+7 days')`, &a.ExpiringSoon},
		{`SELECT COUNT(*) FROM orders WHERE status='pending' AND created_at < datetime('now','-10 minutes')`, &a.StalePending},
		{`SELECT COUNT(*) FROM users WHERE suspended = 1`, &a.SuspendedUsers},
		{`SELECT COUNT(*) FROM orders WHERE status='failed' AND date(created_at) = date('now')`, &a.FailedToday},
		// v0.59: 24h failure windows on the observability tables. Use
		// sent_at since CURRENT_TIMESTAMP is what the DEFAULT computes —
		// matches what the rows actually carry.
		{`SELECT COUNT(*) FROM sms_log WHERE success = 0 AND sent_at >= datetime('now','-1 day')`, &a.SMSFailures24h},
		{`SELECT COUNT(*) FROM webhook_deliveries WHERE success = 0 AND sent_at >= datetime('now','-1 day')`, &a.WebhookFailures24h},
	}
	for _, q := range queries {
		if err := d.conn.QueryRowContext(ctx, q.q).Scan(q.out); err != nil {
			return a, err
		}
	}
	return a, nil
}

// Total returns the sum of all attention counts (for the badge in the navbar).
// v0.59 NOTE: deliberately leaves the SMS/Webhook failure counters out of
// the total — they're observability noise that shouldn't drive the
// nav-bar red dot. The dashboard renders them as their own dedicated chips.
func (a AttentionCounts) Total() int {
	return a.ExpiringSoon + a.StalePending + a.SuspendedUsers + a.FailedToday
}

// PlanSales is per-plan revenue + order count over an inclusive day range.
type PlanSales struct {
	Plan        string
	OrdersCount int
	TotalCents  int
}

// PlanSalesSince returns sales aggregated by plan for the last N days
// (paid orders only). Used by the admin dashboard chart.
func (d *DB) PlanSalesSince(ctx context.Context, days int) ([]PlanSales, error) {
	if days <= 0 || days > 3650 {
		days = 30
	}
	rows, err := d.conn.QueryContext(ctx,
		`SELECT plan, COUNT(*), COALESCE(SUM(amount_cents),0)
		 FROM orders
		 WHERE status='paid' AND paid_at > datetime('now','-' || ? || ' days')
		 GROUP BY plan
		 ORDER BY SUM(amount_cents) DESC`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlanSales
	for rows.Next() {
		var p PlanSales
		if err := rows.Scan(&p.Plan, &p.OrdersCount, &p.TotalCents); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------- Vouchers ----------

const voucherCols = `id, code, days, label, batch, expires_at, redeemed_at, redeemed_by_mac, redeemed_user_id, revoked, created_at`

func scanVoucher(row interface{ Scan(...any) error }) (*models.Voucher, error) {
	var v models.Voucher
	var expiresAt, redeemedAt sql.NullTime
	var redeemedByMac sql.NullString
	var redeemedUserID sql.NullInt64
	var revoked int
	if err := row.Scan(&v.ID, &v.Code, &v.Days, &v.Label, &v.Batch,
		&expiresAt, &redeemedAt, &redeemedByMac, &redeemedUserID, &revoked, &v.CreatedAt); err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		v.ExpiresAt = &t
	}
	if redeemedAt.Valid {
		t := redeemedAt.Time
		v.RedeemedAt = &t
	}
	if redeemedByMac.Valid {
		v.RedeemedByMac = redeemedByMac.String
	}
	if redeemedUserID.Valid {
		uid := redeemedUserID.Int64
		v.RedeemedUserID = &uid
	}
	v.Revoked = revoked != 0
	return &v, nil
}

// CreateVoucher inserts one voucher. Returns ErrVoucherExists on duplicate code.
func (d *DB) CreateVoucher(ctx context.Context, code string, days int, label, batch string, expiresAt *time.Time) (*models.Voucher, error) {
	var expr any
	if expiresAt != nil {
		expr = *expiresAt
	}
	res, err := d.conn.ExecContext(ctx,
		`INSERT INTO vouchers (code, days, label, batch, expires_at) VALUES (?, ?, ?, ?, ?)`,
		code, days, label, batch, expr)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &models.Voucher{ID: id, Code: code, Days: days, Label: label, Batch: batch, ExpiresAt: expiresAt}, nil
}

func (d *DB) GetVoucher(ctx context.Context, code string) (*models.Voucher, error) {
	row := d.conn.QueryRowContext(ctx, `SELECT `+voucherCols+` FROM vouchers WHERE code = ?`, code)
	v, err := scanVoucher(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (d *DB) ListVouchers(ctx context.Context, batch string, limit int) ([]models.Voucher, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	q := `SELECT ` + voucherCols + ` FROM vouchers`
	args := []any{}
	if batch != "" {
		q += ` WHERE batch = ?`
		args = append(args, batch)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := d.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Voucher
	for rows.Next() {
		v, err := scanVoucher(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// VoucherBatchStat is one row in the /admin/vouchers batch-summary table.
// Each batch label tracks how many vouchers it holds, how many are still
// usable, how many got redeemed (with total revenue if a price were set —
// vouchers don't track price today, only days).
type VoucherBatchStat struct {
	Batch    string
	Total    int
	Unused   int
	Redeemed int
	Revoked  int
	Expired  int       // expiresAt in the past AND not redeemed/revoked
	Created  time.Time // earliest CreatedAt in the batch
}

// VoucherBatchStats aggregates vouchers by batch name. A NULL/empty batch
// label still appears as a row labeled "(no batch)" so admins can spot
// vouchers that escaped a labeled generation.
func (d *DB) VoucherBatchStats(ctx context.Context) ([]VoucherBatchStat, error) {
	rows, err := d.conn.QueryContext(ctx, `
		SELECT
		  COALESCE(NULLIF(batch, ''), '(no batch)') AS b,
		  COUNT(*),
		  SUM(CASE WHEN redeemed_at IS NULL AND revoked = 0 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) THEN 1 ELSE 0 END),
		  SUM(CASE WHEN redeemed_at IS NOT NULL THEN 1 ELSE 0 END),
		  SUM(CASE WHEN revoked = 1 THEN 1 ELSE 0 END),
		  SUM(CASE WHEN redeemed_at IS NULL AND revoked = 0 AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP THEN 1 ELSE 0 END),
		  MIN(created_at)
		FROM vouchers
		GROUP BY b
		ORDER BY MIN(created_at) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VoucherBatchStat
	for rows.Next() {
		var s VoucherBatchStat
		// MIN(created_at) comes back as a TEXT in modernc.org/sqlite even
		// though the column is DATETIME (aggregate-function quirk). Scan as
		// string then parse the canonical sqlite layout.
		var createdStr string
		if err := rows.Scan(&s.Batch, &s.Total, &s.Unused, &s.Redeemed, &s.Revoked, &s.Expired, &createdStr); err != nil {
			return nil, err
		}
		// modernc.org/sqlite writes time.Time as RFC3339 with a +00:00
		// offset. Try the canonical layouts in order.
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05-07:00",
			"2006-01-02 15:04:05",
		} {
			if t, err := time.Parse(layout, createdStr); err == nil {
				s.Created = t
				break
			}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) RevokeVoucher(ctx context.Context, code string) error {
	_, err := d.conn.ExecContext(ctx, `UPDATE vouchers SET revoked = 1 WHERE code = ? AND redeemed_at IS NULL`, code)
	return err
}

// RevokeVoucherBatch marks every still-usable voucher in `batch` as revoked.
// Already-redeemed vouchers are left alone (revoking those would lie about
// real usage). Already-revoked rows are no-ops thanks to `revoked = 0` in the
// WHERE. Returns the number of rows that flipped to revoked — useful for
// audit trails and the admin flash message.
//
// Pass the empty string to revoke unbatched ("(no batch)" in the UI)
// vouchers — the query treats NULL and "" the same way as VoucherBatchStats
// does for consistency.
func (d *DB) RevokeVoucherBatch(ctx context.Context, batch string) (int, error) {
	res, err := d.conn.ExecContext(ctx, `
		UPDATE vouchers
		   SET revoked = 1
		 WHERE redeemed_at IS NULL
		   AND revoked = 0
		   AND COALESCE(NULLIF(batch, ''), '') = ?`, batch)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// RedeemVoucher atomically marks a voucher consumed. Returns the voucher row
// on success; on already-redeemed/revoked/expired returns a typed error.
func (d *DB) RedeemVoucher(ctx context.Context, code, mac string, userID *int64) (*models.Voucher, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `SELECT `+voucherCols+` FROM vouchers WHERE code = ?`, code)
	v, err := scanVoucher(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVoucherNotFound
	}
	if err != nil {
		return nil, err
	}
	if v.Revoked {
		return nil, ErrVoucherRevoked
	}
	if v.RedeemedAt != nil {
		return nil, ErrVoucherUsed
	}
	if v.ExpiresAt != nil && v.ExpiresAt.Before(time.Now().UTC()) {
		return nil, ErrVoucherExpired
	}
	now := time.Now().UTC()
	var uid any
	if userID != nil {
		uid = *userID
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE vouchers SET redeemed_at = ?, redeemed_by_mac = ?, redeemed_user_id = ? WHERE code = ?`,
		now, mac, uid, code); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	v.RedeemedAt = &now
	v.RedeemedByMac = mac
	v.RedeemedUserID = userID
	return v, nil
}

// Voucher errors.
var (
	ErrVoucherNotFound = errors.New("充值码不存在")
	ErrVoucherUsed     = errors.New("充值码已使用")
	ErrVoucherRevoked  = errors.New("充值码已作废")
	ErrVoucherExpired  = errors.New("充值码已过期")
)

// ---------- Stats history ----------

func (d *DB) UpsertStatsDaily(ctx context.Context, day string, s Stats) error {
	now := time.Now().UTC()
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO stats_daily (day, mac_total, mac_active, users_total, revenue_cents, paid_orders, snapshot_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(day) DO UPDATE SET
		   mac_total = excluded.mac_total,
		   mac_active = excluded.mac_active,
		   users_total = excluded.users_total,
		   revenue_cents = excluded.revenue_cents,
		   paid_orders = excluded.paid_orders,
		   snapshot_at = excluded.snapshot_at`,
		day, s.Total, s.Active, s.Users, s.RevenueCents, 0, now)
	return err
}

// SnapshotToday computes current stats and upserts a row for today (UTC).
func (d *DB) SnapshotToday(ctx context.Context) error {
	s, err := d.Stats(ctx)
	if err != nil {
		return err
	}
	// paid_orders for today
	var paidToday int
	_ = d.conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM orders WHERE status='paid' AND date(paid_at) = date('now')`).Scan(&paidToday)
	day := time.Now().UTC().Format("2006-01-02")
	now := time.Now().UTC()
	_, err = d.conn.ExecContext(ctx,
		`INSERT INTO stats_daily (day, mac_total, mac_active, users_total, revenue_cents, paid_orders, snapshot_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(day) DO UPDATE SET
		   mac_total = excluded.mac_total,
		   mac_active = excluded.mac_active,
		   users_total = excluded.users_total,
		   revenue_cents = excluded.revenue_cents,
		   paid_orders = excluded.paid_orders,
		   snapshot_at = excluded.snapshot_at`,
		day, s.Total, s.Active, s.Users, s.RevenueCents, paidToday, now)
	return err
}

func (d *DB) ListStatsDaily(ctx context.Context, days int) ([]models.StatsDaily, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	rows, err := d.conn.QueryContext(ctx,
		`SELECT day, mac_total, mac_active, users_total, revenue_cents, paid_orders, snapshot_at
		 FROM stats_daily WHERE day >= ? ORDER BY day ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.StatsDaily
	for rows.Next() {
		var s models.StatsDaily
		if err := rows.Scan(&s.Day, &s.MacTotal, &s.MacActive, &s.UsersTotal, &s.RevenueCents, &s.PaidOrders, &s.SnapshotAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---------- Plans (DB overlay) ----------

func (d *DB) ListPlans(ctx context.Context) ([]models.Plan, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT plan_key, label, days, price_cents, sort_order, enabled, updated_at FROM plans ORDER BY sort_order, days`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Plan
	for rows.Next() {
		var p models.Plan
		var enabled int
		if err := rows.Scan(&p.Key, &p.Label, &p.Days, &p.PriceCents, &p.SortOrder, &enabled, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) UpsertPlan(ctx context.Context, p models.Plan) error {
	en := 0
	if p.Enabled {
		en = 1
	}
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO plans (plan_key, label, days, price_cents, sort_order, enabled, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(plan_key) DO UPDATE SET
		   label = excluded.label, days = excluded.days, price_cents = excluded.price_cents,
		   sort_order = excluded.sort_order, enabled = excluded.enabled, updated_at = CURRENT_TIMESTAMP`,
		p.Key, p.Label, p.Days, p.PriceCents, p.SortOrder, en)
	return err
}

func (d *DB) DeletePlan(ctx context.Context, key string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM plans WHERE plan_key = ?`, key)
	return err
}

func (d *DB) CountPlans(ctx context.Context) (int, error) {
	var n int
	err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM plans`).Scan(&n)
	return n, err
}

// ---------- Audit log ----------

type AuditEntry struct {
	ID     int64
	At     time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

func (d *DB) Audit(ctx context.Context, actor, action, target, detail string) {
	_, _ = d.conn.ExecContext(ctx,
		`INSERT INTO audit_log (actor, action, target, detail) VALUES (?, ?, ?, ?)`,
		actor, action, target, detail)
}

func (d *DB) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	return d.SearchAudit(ctx, AuditFilter{Limit: limit})
}

// CountAudit returns the total number of audit_log rows. Useful for the
// "you're at N / cap" indicator on /admin/audit.
func (d *DB) CountAudit(ctx context.Context) (int, error) {
	var n int
	err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}

// AuditFilter restricts which entries SearchAudit returns. Empty fields are
// ignored. Time strings should be YYYY-MM-DD; mismatched/empty = no bound.
type AuditFilter struct {
	Actor  string // substring (LIKE %s%)
	Action string // exact match
	Target string // substring
	Q      string // substring on detail (v0.54)
	Since  string // YYYY-MM-DD (inclusive)
	Until  string // YYYY-MM-DD (inclusive)
	Limit  int
}

func (d *DB) SearchAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	var sb strings.Builder
	sb.WriteString(`SELECT id, at, actor, action, target, detail FROM audit_log WHERE 1=1`)
	args := []any{}
	if f.Actor != "" {
		sb.WriteString(` AND actor LIKE ?`)
		args = append(args, "%"+f.Actor+"%")
	}
	if f.Action != "" {
		sb.WriteString(` AND action = ?`)
		args = append(args, f.Action)
	}
	if f.Target != "" {
		sb.WriteString(` AND target LIKE ?`)
		args = append(args, "%"+f.Target+"%")
	}
	if f.Q != "" {
		sb.WriteString(` AND detail LIKE ?`)
		args = append(args, "%"+f.Q+"%")
	}
	if f.Since != "" {
		sb.WriteString(` AND date(at) >= date(?)`)
		args = append(args, f.Since)
	}
	if f.Until != "" {
		sb.WriteString(` AND date(at) <= date(?)`)
		args = append(args, f.Until)
	}
	sb.WriteString(` ORDER BY id DESC LIMIT ?`)
	args = append(args, f.Limit)

	rows, err := d.conn.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DistinctAuditActions returns the unique actions present in the log (for
// populating the filter dropdown).
func (d *DB) DistinctAuditActions(ctx context.Context) ([]string, error) {
	rows, err := d.conn.QueryContext(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AuditActionTotal is one row of "this action happened N times in the
// window." Returned by CountAuditActionsByDate.
type AuditActionTotal struct {
	Action string
	Count  int
}

// CountAuditActionsByDate returns the action-counts in the given window.
// Empty Since/Until strings mean "no bound." Useful for ops dashboards
// answering "how many grants vs revokes vs logins this week?"
func (d *DB) CountAuditActionsByDate(ctx context.Context, since, until string) ([]AuditActionTotal, error) {
	var sb strings.Builder
	sb.WriteString(`SELECT action, COUNT(*) FROM audit_log WHERE 1=1`)
	args := []any{}
	if since != "" {
		sb.WriteString(` AND date(at) >= date(?)`)
		args = append(args, since)
	}
	if until != "" {
		sb.WriteString(` AND date(at) <= date(?)`)
		args = append(args, until)
	}
	sb.WriteString(` GROUP BY action ORDER BY COUNT(*) DESC, action`)
	rows, err := d.conn.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditActionTotal
	for rows.Next() {
		var t AuditActionTotal
		if err := rows.Scan(&t.Action, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DistinctAuditActors returns the unique actors present in the log,
// sorted. Used by the /admin/audit page's actor input as a datalist
// autocomplete source so operators don't have to remember the exact
// "user:13800138000" vs "admin:foo" formatting.
//
// Capped at 500 to keep the dropdown manageable on installs with a
// long history (each registered user can show up as their own actor).
func (d *DB) DistinctAuditActors(ctx context.Context) ([]string, error) {
	rows, err := d.conn.QueryContext(ctx, `SELECT DISTINCT actor FROM audit_log ORDER BY actor LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) PurgeAuditLog(ctx context.Context, keep int) error {
	if keep <= 0 {
		keep = 10000
	}
	_, err := d.conn.ExecContext(ctx,
		`DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)`, keep)
	return err
}

// SMSLogEntry is one row in sms_log. Returned by RecentSMSLogs.
type SMSLogEntry struct {
	ID       int64
	SentAt   time.Time
	Provider string
	Phone    string
	Message  string
	Success  bool
	ErrorMsg string
}

// LogSMS writes one row to sms_log. The caller should normally go through
// App.SendSMS which handles both delivery + logging in one place — but
// LogSMS itself is exposed so a future provider that batches sends can
// log multiple rows from one call.
//
// Best-effort: a write error is swallowed (logged on stderr at the call
// site) since failing to log shouldn't reverse a successful (or failed)
// real-world send. Returns an error so callers that DO care can act.
func (d *DB) LogSMS(ctx context.Context, provider, phone, message string, success bool, errMsg string) error {
	successInt := 0
	if success {
		successInt = 1
	}
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO sms_log (provider, phone, message, success, error_msg) VALUES (?, ?, ?, ?, ?)`,
		provider, phone, message, successInt, errMsg)
	return err
}

// SMSLogFilter restricts which rows SearchSMSLogs returns. Empty/zero
// fields are ignored.
type SMSLogFilter struct {
	Phone      string // exact match
	OnlyFailed bool   // success = 0
	Since      string // YYYY-MM-DD (inclusive)
	Until      string // YYYY-MM-DD (inclusive)
	Limit      int    // default 100, cap 1000
}

// RecentSMSLogs is the zero-filter shortcut — keeps the v0.43 caller call
// site small.
func (d *DB) RecentSMSLogs(ctx context.Context, limit int) ([]SMSLogEntry, error) {
	return d.SearchSMSLogs(ctx, SMSLogFilter{Limit: limit})
}

// SearchSMSLogs returns rows newest-first matching the optional filter.
func (d *DB) SearchSMSLogs(ctx context.Context, f SMSLogFilter) ([]SMSLogEntry, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var sb strings.Builder
	sb.WriteString(`SELECT id, sent_at, provider, phone, message, success, error_msg FROM sms_log WHERE 1=1`)
	args := []any{}
	if f.Phone != "" {
		sb.WriteString(` AND phone = ?`)
		args = append(args, f.Phone)
	}
	if f.OnlyFailed {
		sb.WriteString(` AND success = 0`)
	}
	if f.Since != "" {
		sb.WriteString(` AND sent_at >= datetime(?,'start of day')`)
		args = append(args, f.Since)
	}
	if f.Until != "" {
		// < start of NEXT day so the until date is inclusive.
		sb.WriteString(` AND sent_at < datetime(?,'start of day','+1 day')`)
		args = append(args, f.Until)
	}
	sb.WriteString(` ORDER BY id DESC LIMIT ?`)
	args = append(args, limit)
	rows, err := d.conn.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SMSLogEntry
	for rows.Next() {
		var e SMSLogEntry
		var sentStr string
		var success int
		if err := rows.Scan(&e.ID, &sentStr, &e.Provider, &e.Phone, &e.Message, &success, &e.ErrorMsg); err != nil {
			return nil, err
		}
		e.Success = success == 1
		// modernc.org/sqlite returns DATETIME as TEXT for some operations;
		// be permissive about the layout.
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05-07:00",
			"2006-01-02 15:04:05",
		} {
			if t, perr := time.Parse(layout, sentStr); perr == nil {
				e.SentAt = t
				break
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeSMSLog trims sms_log to the most recent `keep` rows. Matches the
// audit_log pattern + cap (default 10_000 if keep<=0).
func (d *DB) PurgeSMSLog(ctx context.Context, keep int) error {
	if keep <= 0 {
		keep = 10000
	}
	_, err := d.conn.ExecContext(ctx,
		`DELETE FROM sms_log WHERE id NOT IN (SELECT id FROM sms_log ORDER BY id DESC LIMIT ?)`, keep)
	return err
}

// WebhookDeliveryEntry is one row in webhook_deliveries — one webhook
// attempt (initial or retry) recorded after the HTTP response settles.
type WebhookDeliveryEntry struct {
	ID         int64
	SentAt     time.Time
	EventType  string
	MAC        string
	Attempt    int
	StatusCode int
	Success    bool
	DurationMs int64
	ErrorMsg   string
}

// LogWebhookDelivery writes one webhook attempt to webhook_deliveries.
// Best-effort: returns an error so callers can log it, but real production
// callers should swallow the error since persistence failures shouldn't
// reverse delivery state.
func (d *DB) LogWebhookDelivery(ctx context.Context, eventType, mac string, attempt, statusCode int, success bool, durationMs int64, errMsg string) error {
	successInt := 0
	if success {
		successInt = 1
	}
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO webhook_deliveries (event_type, mac, attempt, status_code, success, duration_ms, error_msg)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		eventType, mac, attempt, statusCode, successInt, durationMs, errMsg)
	return err
}

// WebhookDeliveryFilter restricts which rows SearchWebhookDeliveries
// returns. Empty/zero fields are ignored.
type WebhookDeliveryFilter struct {
	EventType  string // exact match
	MAC        string // exact match
	OnlyFailed bool   // success = 0
	Since      string // YYYY-MM-DD (inclusive)
	Until      string // YYYY-MM-DD (inclusive)
	Limit      int    // default 100, cap 1000
}

// RecentWebhookDeliveries is the legacy shortcut over SearchWebhookDeliveries
// kept for v0.49-era callers.
func (d *DB) RecentWebhookDeliveries(ctx context.Context, limit int, onlyFailed bool) ([]WebhookDeliveryEntry, error) {
	return d.SearchWebhookDeliveries(ctx, WebhookDeliveryFilter{
		Limit:      limit,
		OnlyFailed: onlyFailed,
	})
}

// SearchWebhookDeliveries returns rows newest-first matching the filter.
func (d *DB) SearchWebhookDeliveries(ctx context.Context, f WebhookDeliveryFilter) ([]WebhookDeliveryEntry, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var sb strings.Builder
	sb.WriteString(`SELECT id, sent_at, event_type, mac, attempt, status_code, success, duration_ms, error_msg FROM webhook_deliveries WHERE 1=1`)
	args := []any{}
	if f.EventType != "" {
		sb.WriteString(` AND event_type = ?`)
		args = append(args, f.EventType)
	}
	if f.MAC != "" {
		sb.WriteString(` AND mac = ?`)
		args = append(args, f.MAC)
	}
	if f.OnlyFailed {
		sb.WriteString(` AND success = 0`)
	}
	if f.Since != "" {
		sb.WriteString(` AND sent_at >= datetime(?,'start of day')`)
		args = append(args, f.Since)
	}
	if f.Until != "" {
		sb.WriteString(` AND sent_at < datetime(?,'start of day','+1 day')`)
		args = append(args, f.Until)
	}
	sb.WriteString(` ORDER BY id DESC LIMIT ?`)
	args = append(args, limit)
	rows, err := d.conn.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WebhookDeliveryEntry
	for rows.Next() {
		var e WebhookDeliveryEntry
		var sentStr string
		var success int
		if err := rows.Scan(&e.ID, &sentStr, &e.EventType, &e.MAC, &e.Attempt,
			&e.StatusCode, &success, &e.DurationMs, &e.ErrorMsg); err != nil {
			return nil, err
		}
		e.Success = success == 1
		for _, layout := range []string{
			time.RFC3339Nano, time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05-07:00",
			"2006-01-02 15:04:05",
		} {
			if t, perr := time.Parse(layout, sentStr); perr == nil {
				e.SentAt = t
				break
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeWebhookDeliveries trims to the most recent `keep` rows.
func (d *DB) PurgeWebhookDeliveries(ctx context.Context, keep int) error {
	if keep <= 0 {
		keep = 10000
	}
	_, err := d.conn.ExecContext(ctx,
		`DELETE FROM webhook_deliveries WHERE id NOT IN (SELECT id FROM webhook_deliveries ORDER BY id DESC LIMIT ?)`, keep)
	return err
}
