-- router-billing schema
-- Greenfield schema; existing deploys migrate via addColumnIfMissing in migrate.go.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    phone           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    suspended       INTEGER NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS macs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mac           TEXT NOT NULL UNIQUE,           -- AA:BB:CC:DD:EE:FF (uppercase)
    label         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active', -- active | expired | blocked
    expires_at    DATETIME NOT NULL,
    user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    schedule_json TEXT NOT NULL DEFAULT '',      -- optional time-of-day restriction
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_macs_expires ON macs(expires_at);
CREATE INDEX IF NOT EXISTS idx_macs_status  ON macs(status);
CREATE INDEX IF NOT EXISTS idx_macs_user    ON macs(user_id);

CREATE TABLE IF NOT EXISTS orders (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    order_no        TEXT NOT NULL UNIQUE,
    mac             TEXT NOT NULL,
    plan            TEXT NOT NULL,
    days            INTEGER NOT NULL,
    amount_cents    INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    payment_method  TEXT NOT NULL,
    trade_no        TEXT NOT NULL DEFAULT '',
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    last_queried_at DATETIME,                  -- last upstream query (for fallback polling)
    paid_at         DATETIME,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_orders_mac     ON orders(mac);
CREATE INDEX IF NOT EXISTS idx_orders_status  ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at);
CREATE INDEX IF NOT EXISTS idx_orders_user    ON orders(user_id);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT 'admin', -- admin | user
    subject     TEXT NOT NULL DEFAULT '',      -- admin username or user phone
    user_id     INTEGER,                       -- for kind=user
    expires_at  DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_kind ON sessions(kind);

-- Live device tracking — populated by sightings.Tracker.
-- Used by the admin /devices page to suggest unsubscribed MACs.
CREATE TABLE IF NOT EXISTS device_sightings (
    mac         TEXT PRIMARY KEY,
    last_ip     TEXT NOT NULL DEFAULT '',
    hostname    TEXT NOT NULL DEFAULT '',
    first_seen  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sightings_seen ON device_sightings(last_seen);

-- Vouchers (redemption codes) — admin pre-generates batches, sells offline,
-- user types code on portal to add time to their device.
CREATE TABLE IF NOT EXISTS vouchers (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    code              TEXT NOT NULL UNIQUE,           -- normalized w/o dashes
    days              INTEGER NOT NULL,
    label             TEXT NOT NULL DEFAULT '',       -- admin reference
    batch             TEXT NOT NULL DEFAULT '',
    expires_at        DATETIME,                       -- voucher itself expires (NULL = never)
    redeemed_at       DATETIME,
    redeemed_by_mac   TEXT,                           -- MAC that consumed it
    redeemed_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    revoked           INTEGER NOT NULL DEFAULT 0,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_vouchers_batch ON vouchers(batch);
CREATE INDEX IF NOT EXISTS idx_vouchers_redeemed ON vouchers(redeemed_at);

-- Daily snapshot for dashboard trend lines. Snapshotted hourly by the server;
-- only the latest row for each YYYY-MM-DD is retained per refresh.
CREATE TABLE IF NOT EXISTS stats_daily (
    day               TEXT PRIMARY KEY,               -- YYYY-MM-DD UTC
    mac_total         INTEGER NOT NULL DEFAULT 0,
    mac_active        INTEGER NOT NULL DEFAULT 0,
    users_total       INTEGER NOT NULL DEFAULT 0,
    revenue_cents     INTEGER NOT NULL DEFAULT 0,
    paid_orders       INTEGER NOT NULL DEFAULT 0,
    snapshot_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Plans (overlay over config). On startup we seed from config if empty;
-- admin can edit/add/remove via /admin/plans. If a config plan is missing
-- from the DB the server falls back to config so deletes are reversible.
CREATE TABLE IF NOT EXISTS plans (
    plan_key      TEXT PRIMARY KEY,
    label         TEXT NOT NULL,
    days          INTEGER NOT NULL,
    price_cents   INTEGER NOT NULL,
    sort_order    INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Audit log — admin/user actions (best-effort, last 10k rows).
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor       TEXT NOT NULL,    -- "admin:foo" / "user:13800138000" / "webhook:wechat"
    action      TEXT NOT NULL,    -- "grant" / "revoke" / "replace" / "login" / "pay"
    target      TEXT NOT NULL,    -- usually MAC or order_no
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);
