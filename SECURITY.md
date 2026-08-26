# Security

## Reporting a vulnerability

Email a description (with PoC if possible) to the maintainer via GitHub — open
a draft security advisory at
<https://github.com/elvin-li/router-billing/security/advisories/new> instead
of a public issue.

Acknowledgement target: 72 hours. Fix-or-disclose target: 14 days for
high-severity issues, 30 days for everything else.

---

## Threat model

This project authenticates and bills MAC addresses on an OpenWrt router.
Likely adversaries, in roughly decreasing severity:

| # | Adversary | Capability |
|---|-----------|------------|
| 1 | Network attacker on the **paid SSID** | Free / open WiFi, no MAC whitelist yet. May try to bypass the captive portal, spoof a paid MAC, or DoS the billing daemon. |
| 2 | Network attacker on the **encrypted Free SSID** | Knows the friends/admin password. May try to escalate to admin via stolen / weak admin credentials, brute force, CSRF. |
| 3 | A registered **user account** (phone+password) | Tries to manipulate another user's MACs, replay payments, forge vouchers, escalate to admin. |
| 4 | A **paying customer** trying to cheat | Pays once, replays the payment to extend multiple devices; tampers with order amount; reuses a voucher; bypasses MAC expiry. |
| 5 | A **lost/stolen admin device** | Active admin session cookie that needs to be invalidatable. |
| 6 | A compromised **WeChat APIv3 key** or **Alipay private key** | Out of scope but the design tries to limit blast radius (header-signature verification, idempotent finalize, audit log). |
| 7 | **Physical access** to the router | Out of scope — root on the box already wins. |

Out of scope: side-channel attacks against host RAM/CPU, hardware tampering,
network-tap attacks on Free SSID (encrypted but a determined attacker with
the password can passively decrypt).

---

## What we do (controls in place)

### Authentication
- Admin and user passwords stored as **bcrypt** hashes (cost 10).
- Admin login: `subtle.ConstantTimeCompare` to defeat timing attacks.
- Sessions are 256-bit random tokens (`crypto/rand`), stored server-side
  (DB row), referenced via `HttpOnly` + `SameSite=Lax` cookies.
- `Secure` flag set automatically when the request arrived over TLS (direct
  or via `X-Forwarded-Proto`).
- **Suspended users** are kicked out instantly: the suspend handler deletes
  all of that user's sessions, and `currentUserID` re-checks `Suspended` on
  every request as a belt-and-suspenders.
- Per-IP **and** per-username rate limit on admin login (5/5min by username,
  8/5min by IP). Defeats both single-IP brute force and IP-rotation botnets.
- Per-IP **and** per-phone rate limit on user login (8/5min IP, 5/5min phone).
- Per-IP rate limit on `/redeem` (10/10min) and `/api/pay/create` (20/min).

### Session lifecycle
- Admin session TTL: 12 hours; user TTL: 30 days.
- Logout deletes the server-side session row + clears the cookie.
- Admin suspend on a user calls `DeleteSessionsByUserID` — _no grace period_.
- Sessions purged hourly via the housekeeping loop.

### CSRF
- Double-submit cookie pattern. `rb_csrf` cookie set on first response,
  echoed back as a hidden `_csrf` form field via the `{{template "csrf" .}}`
  partial.
- Every `POST` through `requireAdmin` / `requireUser` calls `verifyCSRF`,
  which uses `subtle.ConstantTimeCompare`.
- Public endpoints intentionally without CSRF: `/redeem`, `/api/pay/create`,
  `/user/login`, `/user/register`, `/notify/wx`, `/notify/ali` —
  these don't act on an authenticated user's behalf.

### Inputs
- SQL: **all** queries are parameterized (`?` placeholders). No `fmt.Sprintf`
  into SQL anywhere in the codebase.
- HTML: rendered via Go's `html/template`, which auto-escapes by default.
- MAC addresses: normalized via regex (`models.NormalizeMAC`) before any use.
- Phone numbers: regex-validated (CN mobile format).
- Voucher codes: regex-validated against a 31-char unambiguous alphabet.
- File upload (backup restore): capped at 256 MB, validated as SQLite magic
  header + must contain `macs` table before staging.

### Payments
- Order amounts are **always** taken from the server's plan map, never from
  the client request — a tampered request can't lower the price.
- WeChat Pay v3 webhooks decrypted via AES-GCM with our APIv3 key
  (authenticated encryption — anyone without the key can't forge a body).
- WeChat platform certificate signature **also** verified (header
  `Wechatpay-Signature`) when the certs cache is populated. Soft-fails to
  AES-GCM-only auth if cert fetch fails. **TODO**: harden to fail-closed
  once cert fetching is proven reliable across our deployments.
- Alipay notifications verified via RSA2 signature against the configured
  alipay public key.
- `finalizeOrder` is idempotent: `MarkOrderPaid` is a transactional check +
  update; if the order is already `paid`, the second call returns without
  side effects (no double-grant).
- Webhook + on-demand poll funnel through the same `finalizeOrder` mutex.

### Disk
- SQLite DB chmod'd to `0600` on every Open (including WAL/SHM sidecars).
  Contains bcrypt hashes + payment trade IDs.
- DB directory created `0700`.
- WiFi keys file (`/etc/router-billing/wifi-keys.txt`) installed mode `0600`.
- Backup files written `0600` by `backup/rotator.go`.

### HTTP headers
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN` (no clickjacking)
- `Referrer-Policy: same-origin`
- `Permissions-Policy: interest-cohort=()` (opt out of FLoC)
- `Content-Security-Policy: default-src 'self'; img-src 'self' data:;
  style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self';
  frame-ancestors 'self'; base-uri 'self'`
- `Strict-Transport-Security: max-age=31536000` when behind TLS.

### Audit
- Every state-changing admin action (login, login_failed, login_suspended,
  grant, revoke, user_suspend, user_unsuspend, user_reset_password,
  user_delete, bulk_*, restore_staged, backup, voucher_batch, voucher_revoke,
  schedule_set, schedule_clear, plan_save, plan_delete, shadowsocks_uri_view)
  writes a row to `audit_log` with timestamp + actor + action + target +
  detail (now including client IP for grant/revoke/login).
- Browsable + filterable at `/admin/audit`.
- Purged after 10000 rows.

### Shadowsocks proxy (optional, OFF by default)
- The built-in Shadowsocks AEAD proxy (`internal/shadowsocks`) is disabled
  unless an explicit `shadowsocks: {enabled: true, ...}` block is present.
  `config.Load` refuses to start an enabled proxy with an empty password or
  an invalid listen address (`--check-config` catches it in CI/pre-deploy).
- **Authentication is the password** — key derived via the reference
  EVP_BytesToKey(MD5) + per-connection HKDF-SHA1 subkey. `--gen-ss-password`
  produces a 256-bit random secret; rotating = replace it and restart, which
  invalidates every previously shared `ss://` link.
- **Bind LAN-only.** The recommended (and documented everywhere) listen is
  the LAN gateway IP. Binding on the paid SSID interface would let unpaid
  clients tunnel out and bypass the captive portal, so the guidance is
  explicit in the config comments, README, and admin page. `allowed_cidrs`
  gives an in-process source-IP allowlist as defense in depth.
- **Salt replay rejection.** Reused connection salts are dropped within a
  time window (default 60s) — AEAD salt/nonce reuse is catastrophic, and a
  legitimate client never repeats one. Counted in `/metrics`.
- **Secret hygiene.** The password never appears in logs (the HTTP logger
  records only the request path), audit details, or page HTML. The admin
  `ss://` link is masked and only revealed on explicit click, which writes a
  `shadowsocks_uri_view` audit row; the QR is generated server-side so the
  secret is never carried in a query string.
- Only AEAD ciphers are offered (`chacha20-ietf-poly1305`, `aes-256-gcm`,
  `aes-128-gcm`) — the deprecated/broken stream ciphers (RC4, AES-CFB, …)
  are intentionally not implemented.

---

## v0.10.2 — Hardening pass findings

Internal review of the codebase surfaced six items. Severities are project-
relative (this isn't a public bank).

### H1 — suspended user kept active session  (FIXED)

`POST /admin/users/suspend` flipped the `users.suspended` flag but didn't
touch the `sessions` table. A user already logged in stayed authed for up to
their TTL (30 days). Worst case: admin discovers abuse, suspends the user,
the user keeps abusing for a month.

**Fix**: `DeleteSessionsByUserID(uid)` called from the suspend handler.
Belt-and-suspenders: `currentUserID()` re-loads the user on every request
and returns 0 if `Suspended` is now true.

### H2 — session state not re-checked per request  (FIXED via H1's belt)

Same root cause as H1 — fixed by the same change.

### H3 — cookies missing `Secure` flag  (FIXED)

Admin / user / CSRF cookies were set without `Secure: true`. Harmless on a
direct HTTP-only deployment, but a problem behind a TLS reverse proxy:
cookies could leak over a downgrade attack.

**Fix**: helper `isHTTPS(r)` (checks `r.TLS != nil` OR
`X-Forwarded-Proto: https`) feeds the `Secure` field at every `SetCookie`
callsite (4 spots).

### M1 — SQLite file world-readable  (FIXED)

`sql.Open` defers to the process umask (often `0644` → world-readable). The
DB stores bcrypt hashes, MACs, payment trade IDs, audit log.

**Fix**: after `Ping()` in `db.Open`, chmod main DB + `-wal` + `-shm` to
`0600`. Idempotent.

### M2 — admin login rate-limit only by IP  (FIXED)

8 attempts / 5 min per IP. A botnet with 100 IPs gets 800 attempts/5min,
enough to grind out a weak admin password.

**Fix**: second `rateLimiter` keyed by username (5 attempts / 5 min). Now an
attacker needs both IP rotation AND timing windows — and we audit every
failure so spikes are visible.

### L1 — audit log missing client IP for grant/revoke  (FIXED)

Admin actions on MACs were audited but the row didn't include the calling
IP — useful for forensics when there are multiple admins.

**Fix**: every `Audit` call for grant/revoke/delete now appends `ip=<client>`
to the detail column.

---

## Known limitations (won't fix, by design)

- **No transport encryption in-process.** The Go binary speaks HTTP only.
  Production deployments behind a TLS terminator (Caddy / nginx) are
  expected; we don't bundle a TLS stack to keep the OpenWrt binary tiny
  and CGO-free.
- **Admin password in plaintext config is permitted** for convenience.
  Production admins should use `password_hash:` (run `--gen-password-hash`)
  to keep the YAML safe to commit to private git.
- **MAC spoofing.** Once an attacker on the paid SSID knows a paid MAC
  (e.g. printed on a charger), they can clone it with `ip link set`. We
  don't pin to 802.11 4-way handshake identity, since that would tie us
  to specific hostapd versions. Mitigation: encrypted paid SSID + admin
  visibility into duplicate IPs on the same MAC.
- **No 2FA on admin yet.** Future work; the multi-admin + bcrypt config
  is the floor.
- **No anti-replay for /redeem from the same IP within the rate-limit
  budget.** The 31^12 code space is large enough that 10 guesses /
  10 minutes effectively makes brute force a multi-billion-year exercise.
- **Shadowsocks proxy is TCP-only.** No UDP associate — DNS-over-UDP and
  QUIC won't traverse the tunnel; clients fall back to TCP. This is a
  deliberate scope choice to avoid disturbing the OpenWrt forward path.
- **Shadowsocks WAN exposure is the operator's call.** We default to and
  document LAN-only binding. If you expose the port publicly, a leaked
  password grants an open proxy — use a long `--gen-ss-password` value,
  `allowed_cidrs`, and a firewall source restriction.
- **Shadowsocks-2022 (blake3) is not implemented.** We ship the widely
  compatible classic AEAD (SIP004) format instead; adding 2022 would need a
  blake3 dependency and a different handshake for narrower client benefit.

---

## Dependencies

We pin the following — all reputable, all reviewed:

| Module | Why | License |
|---|---|---|
| `github.com/google/uuid` | order-no generation | BSD-3 |
| `golang.org/x/crypto/bcrypt` | password hashes | BSD-3 |
| `golang.org/x/crypto/{chacha20poly1305,hkdf,chacha20}` | Shadowsocks AEAD proxy (same module as bcrypt — no new dependency) | BSD-3 |
| `gopkg.in/yaml.v3` | config loading | MIT |
| `modernc.org/sqlite` | pure-Go SQLite (no CGO) | BSD-3 |
| `rsc.io/qr` | pure-Go QR codes | BSD-3 |

Run `go list -json -m all` to inspect the full transitive set.
