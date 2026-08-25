-- router-billing schema
-- Greenfield schema; existing deploys migrate via addColumnIfMissing in migrate.go.

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    phone           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    suspended       INTEGER NOT NULL DEFAULT 0,
    totp_secret     TEXT NOT NULL DEFAULT '',   -- empty = 2FA off; base32 = enrolled
    totp_pending    TEXT NOT NULL DEFAULT '',   -- base32 of a yet-to-be-confirmed enrollment
    notify_expiry   INTEGER NOT NULL DEFAULT 1, -- 1 = receive expiry-reminder SMS; 0 = opted out
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
    notes         TEXT NOT NULL DEFAULT '',      -- v0.82 free-text support context
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
-- Dashboard/stats run ~13 "status='paid' AND paid_at >= ..." aggregates per
-- page load; the composite index serves them without scanning all paid rows.
CREATE INDEX IF NOT EXISTS idx_orders_status_paid ON orders(status, paid_at);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT 'admin', -- admin | user
    subject     TEXT NOT NULL DEFAULT '',      -- admin username or user phone
    user_id     INTEGER,                       -- for kind=user
    expires_at  DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_kind ON sessions(kind);
-- Purge loop deletes by expiry every few minutes.
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

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

-- TOTP trusted devices — when a user checks "trust this device" at 2FA
-- verify, we issue a 30-day token + row here so future logins from the
-- same browser skip the 2FA challenge. Token is the raw 32-byte random
-- (base64-encoded), stored in the cookie AND as the PK here. DB dump
-- risk is real but bounded: the token alone doesn't grant access without
-- the user's password too (login still validates password first).
CREATE TABLE IF NOT EXISTS user_trusted_devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token       TEXT NOT NULL UNIQUE,
    label       TEXT NOT NULL DEFAULT '',
    expires_at  DATETIME NOT NULL,
    last_seen   DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_trusted_user    ON user_trusted_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_trusted_expires ON user_trusted_devices(expires_at);

-- TOTP backup codes — emergency single-use codes for when the user loses
-- their authenticator device. Generated 10 at enrollment + on demand;
-- bcrypt-hashed so a DB dump doesn't leak. Each row marked used_at on
-- consumption; the row is kept (not deleted) for audit but won't verify.
CREATE TABLE IF NOT EXISTS user_backup_codes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    used_at     DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_backup_user ON user_backup_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_backup_used ON user_backup_codes(used_at);

-- Password-reset codes — issued via SMS from /user/forgot-password. At most
-- one row per user; issuing a new code deletes any prior. Verified by bcrypt
-- compare so a DB dump doesn't leak in-flight codes.
CREATE TABLE IF NOT EXISTS password_resets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pwreset_user    ON password_resets(user_id);
CREATE INDEX IF NOT EXISTS idx_pwreset_expires ON password_resets(expires_at);

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
-- /admin/audit exact-match action filter + DISTINCT action dropdown; the
-- audit log is the largest table on long-running installs.
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- SMS log — every send-through-App.SendSMS records one row regardless of
-- outcome. Persistent (survives restarts) and provider-agnostic, unlike
-- the console provider's in-memory ring buffer. Trimmed by purgeLoop on
-- the same schedule as audit_log.
CREATE TABLE IF NOT EXISTS sms_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    provider   TEXT NOT NULL,                  -- "console" / "aliyun" / ...
    phone      TEXT NOT NULL,
    message    TEXT NOT NULL,
    success    INTEGER NOT NULL DEFAULT 0,     -- 1 = sent ok, 0 = failed
    error_msg  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sms_sent_at ON sms_log(sent_at);
CREATE INDEX IF NOT EXISTS idx_sms_phone   ON sms_log(phone);

-- Webhook delivery log — one row per attempt (initial + each retry) of
-- the notify.Notifier. Lets operators see "did this event ever reach the
-- downstream?" and the failure pattern (DNS error vs 5xx vs timeout)
-- without scraping stderr. Trimmed by purgeLoop on the same cap as
-- audit_log + sms_log.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type  TEXT NOT NULL,                 -- "test" / "redeem" / "order_paid" / ...
    mac         TEXT NOT NULL DEFAULT '',      -- event.MAC if any
    attempt     INTEGER NOT NULL DEFAULT 0,    -- 0=initial, 1+=retry index
    status_code INTEGER NOT NULL DEFAULT 0,    -- 0 if no HTTP response (DNS/connect fail)
    success     INTEGER NOT NULL DEFAULT 0,    -- 1 on 2xx response
    duration_ms INTEGER NOT NULL DEFAULT 0,
    error_msg   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_webhook_sent_at ON webhook_deliveries(sent_at);
CREATE INDEX IF NOT EXISTS idx_webhook_success ON webhook_deliveries(success);
