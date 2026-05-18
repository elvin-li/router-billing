# Changelog

## v0.13 — 账号安全大改造（SMS · TOTP · 备用码 · 信任设备 · 只读 API token）

Six flows that all share the same trust model: prove control of a
second factor before something sensitive happens. Plus the recovery
paths (SMS reset, backup codes, admin reset) so the second factor
never becomes a permanent lock-out, the "trust this device" bypass
so daily logins aren't painful, and least-privilege API tokens so
monitoring scripts can't accidentally revoke a paying user.

### 信任此设备 (`rb_user_trusted` cookie, 30-day bypass)

Adds a "信任此设备 30 天" checkbox to `/user/login/2fa`. When ticked:

- A fresh 32-byte random token is stored in the new
  `user_trusted_devices` table (token + user_id + label + expires_at
  + last_seen + created_at), and set as the `rb_user_trusted` cookie
  scoped to `/user`.
- On subsequent `/user/login` POSTs, if the user has 2FA enrolled
  AND the cookie matches a non-expired row for that user, we skip
  the 2FA challenge and issue the real session directly.
- Crucially the cookie alone never authenticates — it only bypasses
  the second factor AFTER the password is verified, so a stolen
  cookie still needs the password to be useful.

Device management on `/user/2fa` for enrolled users:

- A table lists every trusted device (label = truncated User-Agent,
  last_seen = relative time, expires-in = days remaining).
- The currently-logged-in device gets a "当前" pill.
- Expired rows are shown with a "已过期" pill (they don't bypass
  but the user can see what's stale).
- Per-row "移除" button (`POST /user/2fa/trusted-devices/revoke`).
- A "全部移除" button at the bottom
  (`POST /user/2fa/trusted-devices/revoke-all`), which also clears
  the cookie on the calling browser.

Stale cookies (token gone from DB / belongs to a different user) are
silently wiped on the next login attempt — the response carries a
`Set-Cookie: rb_user_trusted=; Max-Age=-1` so the browser stops
re-sending.

Disabling 2FA via `/user/2fa/disable` AND admin reset via
`/admin/users/reset-2fa` both wipe trusted devices via
`ClearUserTOTP`, so neither leaves trust tokens that would bypass
the next enrollment.

**Tests** (9 new in `user_trusted_devices_test.go`):
- Trust checkbox issues cookie + creates DB row with matching token.
- Trusted-device login skips the 2FA challenge end-to-end.
- Untrusted browser still hits the 2FA challenge.
- Revoking one device doesn't kick the others (parallel devices
  managed independently).
- Revoke-all wipes the DB and clears the calling browser's cookie.
- Disabling 2FA wipes trusted devices.
- Admin reset-2fa wipes trusted devices.
- Stale / wrong cookie gets cleared and does NOT bypass 2FA.
- `labelFromUserAgent` / `formatRelativeTime` table tests.

### 只读 API token (`readonly: true` in `api_tokens`)

Tokens with `readonly: true` are accepted on GET endpoints but
rejected with 403 on non-GET methods. Default remains full access so
existing `api_tokens` entries keep working unchanged. Routes split:

- `/api/admin/health`, `/api/admin/macs` → `requireAPITokenRead`
- `/api/admin/macs/grant`, `/macs/revoke` → `requireAPITokenWrite`

The name documents the policy at the registration site.
`MatchAPITokenFull(string) *APIToken` is the new accessor that
returns the full struct so the middleware can check ReadOnly;
`MatchAPIToken(string) string` stays as a thin label-only wrapper
for callers that don't need scopes.

6 new tests in `api_admin_scope_test.go`:
- Read-only token gets 403 on POST grant + revoke.
- Read-only token still works on GET /macs and /health.
- Legacy (no readonly) tokens still grant + revoke (regression).
- Mixed tokens enforced independently.
- `MatchAPITokenFull` nil/non-nil paths.
- `MatchAPIToken` back-compat (unnamed-token fallback).

### TOTP 备用码 (10 个一次性恢复码)

Without this an enrolled user who loses their phone is stuck. With
this they keep going.

- At successful 2FA enrollment we generate 10 fresh 8-char codes
  (alphabet `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` — visually
  unambiguous, no 0/O/1/I/L), bcrypt-hash them into the new
  `user_backup_codes` table, and render them ONCE on the page
  immediately after confirm. The plaintext only exists in process
  memory at that single render — refresh, navigate, anything →
  gone forever.
- `/user/2fa` for enrolled users now shows "N / 10" remaining with a
  warning pill at ≤3 left and "已用完" at 0. A "重新生成备用码"
  button wipes the existing 10 and shows fresh ones (same one-time
  display).
- `/user/login/2fa` now accepts either a 6-digit TOTP code OR an
  8-char backup code as the value of the `code` form field. We
  detect the difference by length + alphabet (`looksLikeBackupCode`).
  Backup-code path:
  1. Bcrypt-walks every unused row for the user (constant time per
     row; for 10 rows ~700ms worst case at default cost).
  2. On match, UPDATE sets `used_at` so the code can't be replayed.
  3. The audit log records `via=backup_code` instead of `via=totp`.
- Input is normalized (uppercase, strip space/dash) so "abcd-1234",
  "abcd 1234", "ABCD1234" all match the same stored hash.
- Disabling 2FA via `/user/2fa/disable` also wipes the backup codes
  (folded into `ClearUserTOTP` so admin-reset cleans them too).

**Tests** (11 new in `user_backup_codes_test.go`):
- Generator shape: length, alphabet, uniqueness within a batch.
- `looksLikeBackupCode` table test (TOTP-shaped input rejected,
  bad chars rejected, length boundaries respected).
- `normalizeBackupCode` table test.
- Enrollment stores exactly 10 bcrypt hashes, each matching exactly
  one plaintext from the rendered page.
- Backup code unlocks login when TOTP is wrong; reusing the same
  code fails; a different unused code still works.
- Lowercase + dashed input ("abcd-1234") matches.
- Regenerate invalidates old codes (login with old fails, with
  new succeeds).
- Disable wipes backup codes.
- Regenerate rejected for users without 2FA enrolled.
- `/user/2fa` page shows the "10 / 10" counter.
- The 5-attempt cap at `/user/login/2fa` applies to backup-code
  attempts too (a backup-code-shaped wrong code still counts).

### 管理员重置用户 2FA (`/admin/users/reset-2fa`)

For when the user has lost their phone AND their backup codes (or
never saved them). Belt-and-suspenders so the second factor doesn't
turn into a one-way lock.

- New "重置 2FA" button on `/admin/users` (only shown for users with
  `TOTPSecret != ""`).
- Handler clears `totp_secret`, `totp_pending`, AND all backup codes
  via `ClearUserTOTP`. Then `DeleteSessionsByUserID` so any
  post-2FA-cookie attacker on the same browser also loses access.
- Audit log records `user_reset_2fa` with phone + IP.
- New "2FA" column in the user list with a ✓ pill so admins can see
  at a glance who's enrolled.

2 new tests:
- `TestAdminCanResetUserTOTPWhenLocked` — full round trip: enroll
  → admin resets → password-only login bypasses 2FA gate AND sets
  `rb_user` directly (the regression guard for this whole flow).
- `TestAdminReset2FANoOpForUserWithoutTOTP` — idempotent for users
  who never enrolled.

### 用户自助二步验证 (`/user/2fa`)

Self-service TOTP — same RFC 6238 implementation that backs admin 2FA,
opt-in from `/user/me → 管理二步验证`. Designed to mirror the admin
flow so we don't ship two slightly-different lockout policies.

Flow:
1. `POST /user/2fa/begin` generates a 160-bit base32 secret, stores it
   in `users.totp_pending` (overwrites any prior pending so re-clicks
   give a fresh QR).
2. The page renders a QR (`GET /user/2fa/qr` → PNG of the
   `otpauth://totp/router-billing:13800138888?secret=...&...` URL) plus
   the secret in 4-character groups for users whose authenticator
   doesn't QR-scan.
3. `POST /user/2fa/confirm` verifies the typed code against
   `totp_pending`; on success the secret is promoted to live
   (`users.totp_secret`) and pending is cleared in one UPDATE.
4. `POST /user/2fa/disable` requires **both** the current password
   AND a current valid TOTP code — just-password lets a stolen-cookie
   attacker turn 2FA off; just-TOTP defeats lost-phone recovery; both
   together is the standard pattern.

Login-time gating in `handleUserLogin`:
- After password validates, if `user.TOTPSecret != ""` we don't
  `startUserSession` — instead create a 5-minute `user_pending_2fa`
  session, set the `rb_user_pending` cookie (scoped to `/user` only
  so the admin-side cookies stay isolated), and redirect to
  `/user/login/2fa?next=...`.
- The 2FA page accepts the code, swaps pending → real session,
  wipes the pending cookie. Same 5-wrong-attempts-then-destroy cap
  as the admin flow, with its own counter (`userTwoFAAttempts` —
  separate map so admin attempts don't share a budget with user
  attempts).

Schema additions (migration via existing `addColumnIfMissing`):
```sql
ALTER TABLE users ADD COLUMN totp_secret  TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_pending TEXT NOT NULL DEFAULT '';
```

DB API: `SetUserTOTPPending` / `ConfirmUserTOTP` (atomic promote) /
`ClearUserTOTP` + `userColumns` constant + `scanUserRow` helper so
all four user-row reads stay in lockstep when more columns land.

Refactored `GetUser` / `GetUserByPhone` / `SearchUsers` / `ListUsers`
to share `scanUserRow` — no behaviour change, just removes the
copy-paste between three identical Scan calls.

**Tests** (12 new in `user_2fa_test.go`):
- Begin generates pending secret; re-click rotates it.
- Confirm with right code promotes pending → live and clears pending.
- Confirm with wrong code leaves pending intact (no half-promote).
- Enrolled user's password-only login produces `rb_user_pending`,
  NOT `rb_user` — the test fails loudly if 2FA gets bypassed.
- 2FA login with right code finally issues `rb_user`.
- Wrong 2FA code re-renders 200 with the error banner; no cookie.
- 6 wrong codes destroy the pending session (locked/expired).
- Disable rejects wrong password and wrong code separately, then
  accepts both → secret + pending cleared.
- No `rb_user_pending` cookie → 2FA URL bounces to login.
- `/user/2fa/qr` returns a real PNG (magic-byte check).
- `prettySecret` / `extractDigits` table tests for the small helpers.

### `/user/forgot-password` — user-driven SMS reset

v0.11 added the SMS abstraction; v0.12 added the Aliyun adapter. v0.13
wires both into the two flows users actually touch.

### Admin-initiated reset can now SMS the temp password

`/admin/users` grows a second action when SMS is configured: **"重置 +
SMS"** posts `via_sms=1` so the new temporary password is texted to
the user's phone instead of bouncing back through the query string.

- Existing **"重置密码"** still works exactly as before — shows the
  one-shot password inline so admins without SMS aren't blocked.
- On SMS failure the handler falls back to the inline-display path with
  the original temp password, so an Aliyun outage never leaves an admin
  unable to reset.
- Both paths are audited with `via=sms provider=...` / `via=inline` so
  ops can prove what happened later.
- `/admin/sms-log` (new nav entry) shows the last 50 messages when the
  console provider is in use (dev mode). For real providers the page
  points to the provider's own dashboard — we deliberately don't store
  the message bodies, so leaking a DB dump doesn't leak verification
  codes.

### `/user/forgot-password` — user-driven SMS reset (the big one)

Two-stage flow gated entirely on `a.SMS.Available()`:

1. `GET /user/forgot-password` — phone form (link from `/user/login`
   appears only when SMS is wired).
2. `POST /user/forgot-password` — generates a 6-digit code via
   `crypto/rand` uniform sampling, bcrypts it into a new
   `password_resets` row (10-minute TTL, at most one row per user),
   SMSes the plaintext code, advances to stage 2.
3. `POST /user/forgot-password/verify` — bcrypt-compares the typed
   code, validates the new password, rotates `users.password_hash`,
   deletes the reset row, and `DELETE FROM sessions WHERE
   kind='user' AND user_id = ?` so prior tabs are kicked.

**Anti-abuse:**
- Per-IP issuance limiter (6/h) + per-phone issuance limiter (3/h)
  separate from the login limiter so an attacker can't burn through
  somebody's login budget by spamming reset requests.
- Per-IP verify limiter (30/h) + per-phone verify limiter (10/h) on
  top of the per-row attempt cap (5 wrong codes → row deleted, code
  invalidated).
- **No user enumeration** on stage 1: unknown / suspended phones still
  see "code sent" and advance to stage 2; only the SMS itself is
  skipped. Wrong code at verify says "验证码错误" regardless of whether
  the phone is known, so the attacker can't distinguish "no user" from
  "bad code".
- bcrypt over the code means a DB dump doesn't leak in-flight codes.
- Audit log records `password_reset_request`, `password_reset_failed`
  (with `attempts=N`), and `password_reset` with the resolved
  provider name + client IP.

**New table** (`internal/db/schema.sql`):
```sql
CREATE TABLE password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```
Created by `CREATE TABLE IF NOT EXISTS` so existing deploys pick it
up on next startup without manual migration.

**Tests** (8 new in `internal/server/user_forgot_test.go`):
- Happy path: register → request → SMS → verify → new login works,
  old password rejected, reset row deleted.
- Wrong code once, then right code — confirms attempts don't poison
  the row prematurely.
- 5 wrong attempts → row deleted, 6th attempt shows expired/locked.
- Unknown phone → still advances to stage 2, but no SMS sent.
- Per-phone rate limit kicks in after the configured budget.
- `Available()==false` redirects to `/user/login?err=sms_unavailable`.
- Login page omits the "忘记密码？" link when SMS is off, includes it
  when on.
- The stored `code_hash` is a real bcrypt hash (`bcrypt.Cost` parses).

### Misc
- `admin/users/reset-password` handler restructured to drop dead
  `smsSent` boolean flagged by `ineffassign` — early-return on SMS
  success keeps the code straight.
- `userErrLabel` gains six new codes for the reset flow
  (`sms_unavailable`, `sms_failed`, `bad_code`, `expired`,
  `too_many_attempts`, `password_reset`).
- `adminCtx.OK` is now a raw query-string value (was `bool`) so
  templates can branch on the success code, e.g. `{{if eq .OK
  "reset_sms"}}`.

### Stats
- 17 packages tested
- 195 test functions (was 143)

## v0.12 — iptables 后端 + Aliyun SMS

Two infrastructure additions that don't change any user-facing flow but
broaden where router-billing can run + what it can do.

### iptables/ipset firewall backend (老 OpenWrt 兼容)

OpenWrt 21.02 and earlier ship `iptables` instead of `fw4`/`nftables`,
and so do plenty of non-OpenWrt distributions. We now have two complete
implementations of `firewall.API`:

- `nftables` (default, OpenWrt 22.03+) — existing impl, unchanged.
- `iptables` (new) — wraps `ipset` (`hash:mac` set with `counters` flag)
  and assumes the install-script wrote `iptables -m set --match-set
  mac_paid src ...` rules under `/etc/firewall.user`.

Switch with one config line:

```yaml
firewall:
  backend: iptables    # or nftables (default)
```

- `firewall.NewBackend(...)` factory accepts both names (with case +
  whitespace tolerance).
- `Sync` uses `ipset restore` — single kernel transaction, reads stay
  valid throughout. Same atomic semantics as nft flush+populate.
- Tolerates older ipset (pre-6.34) that returns non-zero on `-exist`
  even for benign duplicate-add/missing-del.
- Walled garden is nftables-only for now (needs `daddr` matching that
  our ipset backend doesn't manage); main.go type-asserts and logs
  a clear skip when both are configured.

**Tests**: 9 new in `internal/firewall` — parsers (typical / empty /
no-Members), per-MAC counter extraction, parseUint edge cases,
dry-run smoke for all 5 Manager methods, factory accepts 8 valid
names + rejects unknown.

### Aliyun SMS adapter (`sms.Aliyun`)

Concrete `sms.Provider` for [Aliyun SMS](https://help.aliyun.com/document_detail/101414.html).
The 公控-friendly path:

```yaml
sms:
  provider: aliyun
  aliyun:
    access_key_id: "..."
    access_key_secret: "..."
    sign_name: "MyApp"
    template_code: "SMS_1234"
```

- Implements the V1 canonical-form-params HMAC-SHA1 signing with the
  three RFC-3986 tweaks Aliyun mandates (`%20` not `+`, `%2A`, raw `~`).
- `Send(ctx, phone, message)` — if `message` is JSON it's passed through
  as `TemplateParam`; otherwise wrapped as `{"code": message}` for the
  common single-variable template case.
- Injectable `nowFn` / `nonceFn` for deterministic test signing.
- Upstream error codes (e.g. `isv.SMS_TEMPLATE_ILLEGAL`) surfaced
  verbatim to the caller.

Not yet wired into `/admin/users/reset-password`; that's v0.13. The
infrastructure is ready, the password-reset handler just needs to
flip from "show temp password once" to "POST SMS code" when a
provider is configured.

**Tests**: 7 new in `internal/sms`:
- Deterministic signature pin (regression-detector for sign drift)
- `aliyunEscape` spec compliance (5 cases)
- End-to-end against `httptest.NewServer`
- JSON-shaped messages pass through unchanged
- Upstream API failure → wrapped error
- Defaults + name + `looksLikeJSON` helper

### Stats
- 17 packages tested (was 16)
- 155 test functions (was 130)
- Tags so far: v0.10.1, v0.10.2, v0.11, v0.12

---

## v0.11 — Admin 2FA (TOTP)

Per-admin RFC 6238 TOTP. When an admin has `totp_secret` set, login becomes
two-stage: password + 6-digit code. Compatible with Google Authenticator,
Authy, 1Password, Bitwarden — every popular authenticator.

### What landed
- `internal/totp` — RFC 6238 implementation (~120 LoC). Passes all 6 RFC
  Appendix B test vectors. Rolled in-tree to avoid pulling another module.
- `config.Admin.TOTPSecret` (optional) — base32 secret per admin
- `--gen-totp-secret <username>` CLI — prints secret + `otpauth://` URL +
  ASCII QR (half-block-encoded so it's roughly square in a terminal cell)
- Two-stage login:
  - POST /admin/login → password verified → if secret set, write a 5-min
    `pending_2fa` session row + `rb_admin_pending` cookie → 303 to /admin/login/2fa
  - The pending stage is a SEPARATE cookie + DB kind so `requireAdmin` can't
    be tricked into accepting half-authed traffic
  - POST /admin/login/2fa → verify TOTP (±1 step skew) → DELETE pending →
    create real admin session
- Brute-force protection: 5 wrong codes per pending session → pending row
  killed; admin restarts login. (6-digit space is small enough that this
  matters — 5 attempts/5min budget makes online guessing impractical.)
- `admin_2fa.html` template: autofocus, one-time-code autocomplete,
  paste-friendly (digits-only filter on the input)
- Constant-time verification (`subtle.ConstantTimeCompare`)
- Recovery: documented in the 2FA form footer — SSH in, remove
  `totp_secret` line from config.yaml, restart

### Tests (+11)
- `internal/totp` (7): RFC 6238 vectors, ±1 step skew tolerance, malformed
  secret/code rejection, base32 round-trip + spaces/dashes/lowercase variants,
  provisioning URI shape
- `internal/server` (4):
  - Full flow: password → pending → wrong code rejected → right code → real session
  - Wrong code returns inline error, no session cookie
  - 5 wrong codes locks the pending session
  - No `totp_secret` → old single-stage flow still works

### Programmatic admin API (Bearer auth)
- `config.api_tokens: [{token, label}]` — list of Bearer tokens
- Endpoints (Bearer-only, no CSRF):
  - `GET  /api/admin/health` — same JSON as the cookie-gated version
  - `GET  /api/admin/macs` — full MAC list as JSON
  - `POST /api/admin/macs/grant` — `{mac, days, label?}` extends or adds
  - `POST /api/admin/macs/revoke` — `{mac}` deletes from DB + firewall
- Constant-time token compare; audit log records `actor: "api:<label>"`
- 4 integration tests (401 path, valid grant, bad token, revoke round-trip)

### SMS provider abstraction
- `internal/sms` — `Provider` interface + `Sender` wrapper
- `ConsoleProvider` for dev (writes to log + ring-buffers last N for tests)
- Lays groundwork for Aliyun / Tencent / Twilio implementations that the
  admin-reset-password flow will use; concrete adapters wait for real creds
- 3 tests (nil sender → ErrNotConfigured, ring buffer eviction, default cap)

### Sessions admin tool (v0.10.2 follow-on, mentioned for completeness)
- `/admin/sessions` page lists every live session
- One-click revoke per row
- "🚨 revoke all other admin sessions" button for the "I lost my laptop"
  scenario (keeps the requesting session alive)
- 3 tests

### Stats
- 16 packages tested (was 15) — `totp`, `sms` join
- 130 test functions (was 111)
- All green on every commit since v0.10.2 except one transient gosec G505
  flag-and-fix on `crypto/sha1` (immediately suppressed inline since RFC
  6238 mandates SHA-1)

---

## v0.10.2 — 安全审计：6 项发现，5 项已修

针对内部代码的系统性安全 review，发现 6 项问题，全部修复（1 项 LOW 一起做）。
详细威胁模型、findings 表、reporting 流程见 [SECURITY.md](SECURITY.md)。

### 修复
- **H1 — 用户被停用后旧 session 仍有效（HIGH）**
  `/admin/users/suspend` 翻了 `users.suspended` 但没动 `sessions` 表 → 刚被停用的用户
  可以继续用到 30 天的 cookie 过期。新增 `db.DeleteSessionsByUserID()`；suspend 处理器
  调用后审计行记录被吊销的 session 数
- **H2 — 防御深度：每次请求重查 Suspended（HIGH）**
  `currentUserID` 重新加载 User 行；Suspended=true 即返 0 → 即便 H1 的 DELETE 失败也兜得住
- **H3 — Cookie 缺 `Secure` 标记（HIGH）**
  rb_admin / rb_user / rb_csrf 始终非 Secure。新增 `isHTTPS(r)` 辅助函数（检测 r.TLS
  或 X-Forwarded-Proto: https），4 处 SetCookie 全部接上
- **M1 — SQLite DB 文件世界可读（MEDIUM）**
  含 bcrypt 哈希 + 支付交易号。`db.Open` Ping 后立即 chmod 0600 主文件 + WAL + SHM
- **M2 — 管理员登录限流只按 IP（MEDIUM）**
  新增 `adminLoginByUser` 限流器（5 次/5 分钟/用户名）→ IP 轮换的 botnet 也突破不了
- **L1 — grant/revoke 审计未记客户端 IP（LOW）**
  detail 列新增 `ip=...` 字段，便于多管理员场景下溯源

### 测试（103 → 108）
- `TestSuspendKicksLoggedInUser` — H1 happy path
- `TestSuspendedFlagAlsoBlocksValidSession` — H2 防御深度
- `TestSecureCookieSetWhenBehindTLS` — H3，两种场景：HTTP + 模拟反向代理
- `TestAdminLoginRateLimitByUsername` — M2，用 X-Forwarded-For 变 IP，证明
  仅 IP 限流被绕过、按用户名限流挡住第 4 次
- `TestSQLiteDBFileIsOwnerOnly` — M1，断言 mode 0600

### 文档
- **新增 [SECURITY.md](SECURITY.md)**：威胁模型 7 类、现有控制 8 大类（auth/session/CSRF/
  输入/支付/磁盘/HTTP头/审计）、本轮 6 个发现的 root cause + 修复方案、明确"不修"项
  （无 TLS in-process、明文密码可选、MAC 欺骗、无 2FA、/redeem 不反 replay）
- 报告漏洞流程：GitHub 私有 advisory（不公开 issue）

---

## v0.10.1 — 可测性、Release 自动化、PWA、Docker

### 可测性
- **`firewall.API` 接口**：把 `*firewall.Manager` 的消费面抽成接口（Add/Remove/Sync/EnsureSet/List/Counters）
  - `service.MACService` 现在依赖接口而不是具体类型 → 测试可注入 fake
  - 也为未来 iptables 后端铺路
- **service 包测试**（新 8 个）：grant/extend/delete/revoke/replace/resync/expire-due 覆盖；
  fakeFW 记录 Add/Remove/Sync 调用，断言 DB 与防火墙状态一致
- **scheduler 包测试**（新 4 个）：抽 `Expirer` 接口；测试初始 tick、ctx-cancel、
  错误下不卡死循环、interval≤0 默认 1 小时

### 发布自动化
- **`.github/workflows/release.yml`**：tag `vX.Y[.Z]` push → 自动 `make arm64 + pack + ipk`
  → 解析 CHANGELOG.md 对应版本的小节作为 release 说明 → 上传 artifacts
- **`LICENSE`**：MIT
- **README badges**：CI status / latest release / Go version / platform / license

### 容器化（仅开发用，生产仍是 ipk）
- **`Dockerfile`**：multi-stage（golang:1.22-alpine → alpine:3.20 + nftables）
  非 root 运行；非真实防火墙场景配 `--dry-firewall`
- **`docker-compose.yml`**：一行 `docker compose up` 起本地预览

### Server 强化
- **`/api/pay/create` 限流**：20 次/分钟（按 IP），防止支付意图洪水攻击
  浪费 sqlite 写入 + 上游 HTTPS 往返；超限返 429
- **PWA 化**：
  - `/static/manifest.json` + 192×192 渐变 SVG icon
  - `/sw.js`（root-scope）service worker：cache-first 静态资源；其他网络优先
  - portal.html 注册 SW + 声明 manifest → "添加到主屏幕" 体验

### 测试
- 4 个新集成测试：pay-create rate-limit 429、`/sw.js` 端点、`/static/manifest.json` 端点、portal.html 包含 PWA 声明

### 数字
| | 之前 | 现在 |
|---|---|---|
| 测试包 | 13 / 15 | 15 / 15 ✓ |
| 测试函数 | 84 | 100 |
| Go LoC | 9882 | 10800+ |

---

## v0.10 — 安全、运维、测试三连击

围绕「上线后能用一年不出事」做的一轮。无新业务功能；全部是兜底/可观测/可恢复。

### 安全
- **`/redeem` 限流**：10 次 / 10 分钟（按 IP），防充值码暴力猜测
  （12 字符 31-alphabet 已经是 31¹² ≈ 7.9×10¹⁷ 空间，但加这层省 CPU）

### 运维
- **`/admin/backup/restore`**：上传 `.db` → 校验（SQLite magic + 必须有 `macs` 表）
  → 暂存为 `<dbpath>.pending-restore` → 写审计；**当前服务不动**
- **`main.MaybeApplyPendingRestore()`**：启动时检查 `.pending-restore`，
  原子改名（旧 DB 备份为 `<dbpath>.before-restore-YYYYMMDD-HHMMSS` 含 WAL/SHM）
  → 切换 → 删暂存。**两阶段设计**：上传时不关闭活的连接池，靠 `service restart` 完成切换
- **`/admin/maintenance` 页**：下载备份 / 上传恢复 / 看暂存状态 / 看自动备份配置
- **`--log-json`**：每行日志包成 JSON
  `{"ts":"...","svc":"router-billing","ver":"...","msg":"..."}`，给 ELK/Loki 消化

### CI / 代码质量
- **golangci-lint** 加入 CI 的 `lint` job：errcheck / govet / gosimple /
  ineffassign / staticcheck / unused / misspell / bodyclose / gosec /
  gocyclo / goimports / prealloc。配置 `.golangci.yml` 包含合理排除
  （测试代码松一些；db 包的 fire-and-forget audit 写入豁免）

### 测试（90 → 100+ 用例）
- **arp**（新）：7 个 case 覆盖 `parseNeighOutput`：典型行、FAILED/INCOMPLETE
  跳过、IPv4+IPv6 dedup、垃圾输入容忍、MAC 大小写归一、纯 IPv6 entry、空输入
- **backup**（新）：5 个 case 覆盖 copyFile atomic（无 .tmp 残留 + mode 0600）、
  prune 跨 cutoff + 前缀过滤、RetainDays≥1 兜底（绝不删唯一备份）
- **pay**（新）：14 个 case
  - `randomHex` 形状/字母表
  - WeChat authHeader 格式（5 个必填字段）
  - WeChat DecodeNotify 自洽 AES-GCM 往返 + mchid/appid mismatch / 错 key 拒绝
  - Alipay sign 确定性 + base64 输出
  - Alipay DecodeNotify 自签 RSA 往返 + 错签名 / app_id mismatch 拒绝
  - Alipay Precreate against httptest.NewServer（验 method/content-type/biz_content/sign）
  - Alipay Query SUCCESS path / TRADE_NOT_EXIST path
  - RSA 私钥/公钥 PEM 加载，HTTP 超时合理性
- **sightings**（新）：3 个 case 覆盖 ctx-cancel、默认参数、scan 空 iface 无副作用
- **server**（增量）：`TestRedeemRateLimit` / `TestMaintenancePageRenders` /
  `TestBackupRestoreRejectsNonSQLite` / `TestBackupRestoreAcceptsValidDB`

### 重构
- arp 的解析逻辑从 `ListOnInterface` 拆出来成纯函数 `parseNeighOutput`，
  便于测试不 fork `ip neigh`
- notify 的 `RetryDelay` 提升为字段，便于测试用 ms 级别替代 2s

---

## v0.9 — 「熟人 + 管理 WiFi」模型

把 `Free_WiFi` 从「人人可上的开放网」改成「**WPA2 加密 · 给信任的人 + 管理员自己用**」。

### 改动
- `config.go` `SSIDInfo.FreeKey` 字段 — `/admin/ssid-cards` 同时显示 SSID 名 + 密码
- `install.sh` 没传 `FREE_KEY` 时自动生成 12 位密码 → `/etc/router-billing/wifi-keys.txt` (mode 0600)，最后总结里打印一次
- `uci-defaults`：`FREE_KEY` 为空时在 stderr 大字告警「Free_WiFi 还是开放的，任何路人都能触达 :8080」
- `/admin/ssid-cards`：
  - 「免费 WiFi」卡片改名「熟人 / 管理 WiFi（加密）」，自动带密码
  - 「付费 WiFi（加密）」卡片改名「VIP 付费 WiFi（加密）」
- README + `config.example.yaml` 加新模型说明 + 迁移提示

### 不变
- `Paid_WiFi` 依然是开放的（客户扫码付费走这里）
- `Paid_Secure_WiFi` 依然是 VIP 通道
- nftables / 防火墙规则、计费逻辑、所有 admin/user 流程 — 零改动

### 升级现有部署
存量装机不会自动加密 Free SSID（不破坏现有连接）。手动升级一次：

```sh
# 1. 选一个密码 ≥ 8 字符
FREE_KEY=your-new-key

# 2. 把所有 Free_WiFi wifi-iface 都改成加密
for i in $(uci show wireless | awk -F'[].[]' '/ssid='\''Free_WiFi'\''/ {print $2}'); do
    uci set wireless.@wifi-iface[$i].encryption='psk2'
    uci set wireless.@wifi-iface[$i].key="$FREE_KEY"
done
uci commit wireless && wifi reload

# 3. 保存密码以备查
printf 'free_key=%s\n' "$FREE_KEY" >> /etc/router-billing/wifi-keys.txt
chmod 0600 /etc/router-billing/wifi-keys.txt
```

---

## v0.8 — Admin 工作流 / 收据 / 销量图 / 批量操作 / 实时仪表盘 / 移动端

**Admin 工作流**
- **/admin/users/reset-password**：管理员一键重置任意用户密码 →
  生成 10 位临时密码、bcrypt 入库、吊销该用户所有 session、redirect 时通过 URL 把临时密码显示一次（flash 框 + ⚠ 提示）
- **/admin/macs/bulk**：MAC 列表前置 checkbox + 全选 + 浮动操作条
  - JS-built form 避开 HTML `<form>` 不可嵌套问题（不动行内 extend/delete 表单）
  - 支持批量删除、批量续费 N 天
  - 写审计 `bulk_delete` / `bulk_extend`

**收据 / 报销**
- **/receipt?order_no=...**：可打印电子收据页（A5 排版 + 红色「已支付」印章 + 商家名）
- 仅 paid 订单可查；订单号 30 字符不可猜
- 入口：付款成功页 / 用户中心订单列表 / admin 订单列表 都有「收据」链接
- `@media print` 适配，浏览器「另存为 PDF」一键导出

**销量分析**
- 仪表盘新增「30 天套餐销量」卡片
- 横条图（CSS only，按 amount_cents 归一化），按销售额倒序
- 看一眼就知道哪个 plan 最赚钱
- `db.PlanSalesSince(days)` 返回 `[]{Plan, OrdersCount, TotalCents}`

**实时仪表盘**
- **/admin/stats/stream**：SSE 每 5 秒推 stats + attention
- [stats-stream.js](web/static/stats-stream.js) 更新 `.stat-value` 单元格内容；变化时短暂高亮
- 25 秒心跳保连
- 不需要刷新页面就能看到付款进来 / 用户注册 / 到期变化

**移动端优化**
- ≤ 720px：stats 卡 2 列、表格横向滚动 + 11/13px 字、行操作纵向堆叠、bulk-bar 折行
- ≤ 420px：stats 卡 1 列、header 垂直堆叠
- 暗色模式下的 sales bar、attention 卡都有对应配色

**(已 DEFERRED)** Per-plan tc 带宽限速
- 涉及 qdisc/class/filter 在 OpenWrt 上每种内核版本兼容性差异较大，单元测试覆盖也难
- 留待 v0.9 单独评估稳定性后再加，避免出包不稳

---

## v0.7 — Captive 网关 / 实时支付 / 时段限制 / WX 平台证书 / 集成测试 / CI

**Captive walled-garden（重要）**
- 不再让未付费的设备一开始就被防火墙完全切断
- nftables 新增 `wg_paid` set（ipv4，带 timeout），forward/pre 链都先 check
- [internal/walledgarden](internal/walledgarden/garden.go) goroutine 每 5 分钟解析配置中的域名（默认含 WeChat/Alipay/captive-portal 探测/NTP），diff 后增删 set 元素
- **结果**：用户连上 Paid_WiFi 时，**手机能正常打开微信/支付宝来扫码付款**，否则连支付都做不了

**实时支付反馈**
- 新端点 `/api/pay/wait?order_no=X` 长轮询最多 60 秒
- finalizeOrder 触发即 fan-out 通知所有等待 channel
- portal.js 用 long-poll 代替 2 秒轮询，**支付完成几乎瞬时跳转 success**
- 失败回退到 `/api/pay/status` 2 秒轮询

**关注项面板**
- [/admin/macs](web/templates/admin_macs.html) 顶部黄色高亮提示卡：7 天内到期 / pending 超 10 分钟 / 已停用用户 / 今日失败订单
- 没有时不显示；点击跳对应页

**Time-of-day 时段限制**
- MAC schedule_json 字段（JSON：days[ISO] + start_min/end_min，支持跨午夜）
- 每分钟 goroutine 检查所有活跃 MAC，到点自动开关防火墙白名单（不动 DB 状态）
- 编辑器页 [admin_mac_schedule.html](web/templates/admin_mac_schedule.html)：星期复选 + 时:分输入 + 清除按钮
- 5 个 schedule 单元测试：跨午夜 / 周日 / JSON 解析 / 边界

**WeChat 平台证书校验**
- `pay.WeChat.VerifyNotifyHeaders(headers, body)`：5 分钟时间窗 + RSA-SHA256 验签
- 自动从 `/v3/certificates` 拉证书，AES-GCM 用 APIv3 密钥解密，缓存 6 小时
- 在 `/notify/wx` 里 soft-fail（log 但不直接拒）— 与原 AES-GCM 双重保护
- Webhook 现在**真正防伪**（不光防内容篡改，也防"非微信发出"）

**审计日志筛选**
- /admin/audit 加查询表单：actor（模糊）/ action（dropdown 来自 distinct）/ target（模糊）/ since-until 日期
- `db.SearchAudit(AuditFilter)` 动态拼 WHERE

**测试 + CI**
- 7 个 HTTP 集成测试（httptest）：portal 渲染 + 安全头 / admin 登录跳转 / CSRF 403→303 / 用户注册登录登出 / voucher 全流程 / metrics token / 安全头细节
- 4 个 walled-garden 测试：diff 算法 / 空配置 / IPv6 过滤
- GitHub Actions [ci.yml](.github/workflows/ci.yml)：test+race / arm64 cross-build + ipk / gofmt lint，artifact 上传

---

## v0.6 — 防护硬化 / opkg / 流量计数 / 充值卡打印

**安全**
- **CSRF 防御**：双重提交 cookie 模式
  - `rb_csrf` cookie 由 middleware 自动设置（SameSite=Lax，30 天）
  - 所有 admin/user 表单注入 `<input name="_csrf">`（模板 `{{template "csrf" .}}` partial）
  - requireAdmin/requireUser 上的所有 POST 都常时比较；不匹配 → 403
  - SSE 推送渲染的表单同样从 cookie 读 token 注入
- **管理员可停用/删除用户**：suspend=1 即刻吊销该用户所有 session
- 停用账号登录尝试 → `已停用，请联系管理员`，写审计 `login_suspended`

**打印**
- **充值卡 A4 打印页**：`/admin/vouchers/print?batch=...` 8 张/页虚线撕卡布局
  - 每张含 4-4-4 充值码 + QR（扫码自动打开 `/redeem?code=...`）
  - `@media print` 适配 A4
  - 只打印未使用的充值码

**深色模式**
- CSS `prefers-color-scheme: dark` 自动跟随系统
- 打印页强制白底（`@media print` 内覆盖）

**运维**
- **opkg .ipk 包**：`make ipk` 出 `router-billing_dev_aarch64_generic.ipk`，路由器 `opkg install router-billing*.ipk` 一键装
  - 含 postinst（自动 enable + start）+ prerm（自动 stop + 清防火墙）
  - `/etc/router-billing/config.yaml` 标记为 conffile，opkg 升级不覆盖配置
- **SQLite 周维护**：每 7 天 `PRAGMA optimize` + `VACUUM` 回收空间
- **/metrics** 又多了维度

**功能**
- **per-MAC 流量计数**：nftables set 加 `counter` 标志，`nft -j list set` 解析 JSON
  - `/admin/devices` 多一列「已转发」(KB/MB/GB)，SSE 实时更新
  - `firewall.Counters(ctx)` 返回 `map[MAC]{Packets,Bytes}`
  - 兼容旧 set（无 counter flag → 字节数显示 0）
- **出站 webhook**：`pay` / `redeem` / `grant` / `revoke` 事件 POST 到配置的 URL
  - HMAC-SHA256 签名（`X-Router-Billing-Signature: sha256=<hex>`）
  - 64 深度异步队列 + 单 worker，1 次重试，失败即丢
  - 给商家集成自己的 Slack/Lark/微信告警用

**Bug fix**
- 防火墙脚本之前误加了 `flags interval` 到 `ether_addr` 集合，与 equality 匹配语义冲突，已删
- `statusRecorder` 实现 `http.Flusher` 转发（SSE 修复）

**测试**
- `parseCounters`: 带/不带 counter flag、空、坏 JSON
- `humanBytes`: 0/B/KB/MB/GB/TB 边界

---

## v0.5 — 充值码 / 套餐 UI / 仪表盘 / 自动备份

**新增**
- **充值码系统**（最实用的线下分销场景）
  - 12 位无歧义字母（无 0/O/1/I/L），4-4-4 分组显示
  - 管理员一次生成 1-1000 张同规格卡，按 batch 归集
  - CSV 导出适合发给印刷厂
  - 用户在 `/redeem` 输入码 + MAC → 立即激活；可选过期
  - 已登录用户激活的 MAC 自动归到账号下
  - 失败原因明确：不存在 / 已使用 / 已作废 / 已过期
- **套餐 UI 管理**（`/admin/plans`）
  - DB 表覆盖 config，**改完立即生效不重启**
  - 同 key 的 config 套餐被 DB 覆盖；DB 删掉就恢复 config 默认
  - 支持启用/停用、排序、添加任意自定义套餐
- **自动备份轮转**（`backup:` config 开启）
  - 默认每 24 小时一次 → `/var/lib/router-billing/backups/billing-YYYYMMDD-HHMMSS.db`
  - WAL checkpoint + 原子重命名
  - 自动保留最近 N 天（默认 7），过期删除
- **30 天趋势图**
  - 后台每小时 `SnapshotToday` 写 `stats_daily`
  - `/admin/charts.json` 返回 30 天序列
  - 仪表盘统计卡现在带 SVG sparkline（无 JS 库依赖，纯 fetch+SVG）
- **门户页"已有充值码？输入激活 →"** 链接

**模板辅助**
- `{{prettyCode}}` — 4-4-4 分组充值码显示
- `{{deref}}` `{{isPast}}` — 用于 nullable time 字段

**测试**
- 7 个 DB 集成测试：UpsertMAC 保留 owner、Redeem 4 种状态、Replace 转移所有权、Plans CRUD、Stats 幂等
- 3 个 voucher 单元测试：生成、Pretty 格式化、Validate

---

## v0.4 — 生产硬化

**安全**
- 多管理员账号支持（`admins:` 列表，每个可用 `password` 或 `password_hash`）
- 管理员密码 **常时比较**（subtle.ConstantTimeCompare），bcrypt 哈希可选
- 管理员登录失败 IP 限流（8 次/5 分钟）+ 审计 `login_failed` 事件
- 用户登录现在 **同时按 IP + 按手机号** 限流（防止分布式撞库）
- HTTP 安全头中间件：CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy；HTTPS 检测到时自动加 HSTS
- 用户/管理员失败登录都记审计

**运维**
- `/metrics`：Prometheus 文本格式（mac_total/active/expired、users_total、revenue_cents_total、firewall_set_size、provider_enabled、uptime、db_size）。可选 `metrics_token` Bearer 鉴权
- `/admin/backup`：WAL checkpoint + 流式下载 SQLite 文件（HTTP 200 → `billing-yyyymmdd-hhmmss.db`）
- `/admin/health`：JSON 健康检查（已有，本版加上 user_count）
- CLI：`--check-config` 验证配置不启动；`--gen-password-hash` 读 stdin 输出 bcrypt 哈希（直接复制到 `admins[].password_hash`）

**UX**
- `/admin/ssid-cards`：可打印的 WiFi 二维码海报。三种 SSID + 用户登录页 URL 都生成扫码 QR，标准 `WIFI:T:WPA;S:...;P:...;;` 格式 iOS/Android 相机直接识别。`@media print` 样式适配 A4 打印
- `/admin/devices/stream`：Server-Sent Events 替代 meta-refresh，**真正实时**（5 秒推一次设备列表 + 25 秒心跳）。失败回退到 noscript meta-refresh
- 用户可以 **自己改设备 label**（`POST /user/macs/label`），方便区分 "iPhone 12" / "MacBook" / "工作机"

**测试**
- 配置层认证测试（plaintext / bcrypt / 多用户）
- 新增 4 个测试包：config / dnsmasq / firewall / models / server
- `go test ./...` 全绿

---

## v0.3 — 多 SSID + 用户系统

**新增**
- 第三个 SSID：`Paid_Secure_WiFi`（WPA2 加密，跟开放收费 SSID 共用 br-paid 网桥和 MAC 白名单）
  - 装机时设 `PAID_SECURE_KEY=≥8位密码`，或事后 `sh /usr/share/router-billing/setup-secure-ssid.sh`
- 用户系统（手机号 + 密码）
  - 注册：`/user/register`（11 位 1[3-9] 开头，bcrypt cost 10）
  - 登录：`/user/login`（IP 限流：8 次/5 分钟）
  - 用户中心 `/user/me`：列出所有 MAC、到期时间、剩余天数
  - **替换设备**：把 A MAC 剩余时长原样转给 B MAC（自动 ARP 检测当前设备）
  - **绑定本设备**：把活跃 MAC 归到自己账号
  - 修改密码
  - 已登录用户付费时，订单自动 link 到 user_id
- 在线设备增强
  - 历史 sighting：后台 30 秒一次 ARP+DHCP leases 写入 `device_sightings`
  - 离线 10 分钟内仍展示，方便统一录入
  - 主机名列（来自 `/tmp/dhcp.leases`）
  - 在线 + 未授权设备绿色边框高亮
  - 页面 30 秒 meta-refresh
- 管理员
  - `/admin/users`：注册用户列表 + 每用户 MAC 数
  - `/admin/audit`：审计日志（最近 300 条）
  - `/admin/health`：JSON 健康检查（uptime / DB 大小 / 防火墙集合规模 / 套餐启用状态）
  - 批量导入 MAC（CSV 文本框，`mac[,days[,label]]` 每行一条）
  - 导出 MAC / 订单 CSV
- **支付：内置主动查单（解决国内无 HTTPS 域名问题）**
  - 微信 `GET /v3/pay/transactions/out-trade-no/...`
  - 支付宝 `alipay.trade.query`
  - 每 4 秒后台扫一次 pending 订单 + 浏览器轮询 `/api/pay/status` 时机会触发即时查单
  - webhook 仍可用，但不再必需
- 单元测试：models / dnsmasq / firewall / rate limiter

**改动**
- `db.UpsertMAC` 增加 `userID *int64` 参数
- `db.CreateSession` 改为 `(token, kind, subject, userID, ttl)`
- `db.GetSession` 返回 `*SessionRow {Kind, Subject, UserID}`
- `service.Extend` 加 `userID` 参数
- 新增 `service.Replace(userID, oldMac, newMac, label)`
- 新增 `db.ReplaceMAC`、`db.ListMACsForUser`、`db.ListOrdersForUser`
- 新增 `db.UpsertSighting`、`db.ListRecentSightings`、`db.PurgeOldSightings`
- 新增 `db.ListAudit`
- 新增 `models.User`、`models.Sighting`、`models.ValidPhone`、`models.ValidPassword`
- 新增 `pay.WeChat.Query` / `pay.Alipay.Query`
- 模板新增函数：`daysLeft`、`ago`、`shortMAC`
- 新增包：`internal/dnsmasq`、`internal/sightings`
- 旧版数据库自动迁移（PRAGMA table_info 检测 + ALTER TABLE ADD COLUMN）

**安全**
- 用户密码 bcrypt
- 登录/注册 IP 限流（8/5min、4/1h）
- audit log 记录登录 / 注册 / 付费 / 授权 / 替换 / 收回 / 密码修改
- 自动清理：sessions 表 2 小时一次，audit log 保留最近 10000 条

---

## v0.2 — UI 重设计 + IoT 工作流

- style.css 全面重写：indigo 渐变品牌色、卡片化布局、动画
- 管理后台改为左侧栏 + 暗色渐变 + 统计卡（已授权 / 活跃 / 过期 / 累计收入）
- 在线设备页：实时 ARP 列表 + 一键授权（30 天 / 1 年 / 5 年 / 10 年）
- 充电桩 / IoT 设备工作流：管理员浏览器即可全部完成
- 强制门户 / 支付成功页移动端体验大改
- iOS / Android / Windows 强制门户探测 URL 全部捕获

---

## v0.1 — 基础

- OpenWrt aarch64 单文件二进制（modernc.org/sqlite 纯 Go，CGO 关闭）
- 双 SSID：`Free_WiFi`（lan，免费）+ `Paid_WiFi`（paid 区域，MAC 白名单）
- nftables `inet billing` 表 + `mac_paid` 集合 + fw4 include hook
- 微信 v3 Native + 支付宝当面付（precreate + webhook）
- 强制门户 + 自动 MAC 检测（`ip neigh`）
- 管理后台：登录 / MAC 增删续 / 订单查询
- 套餐：¥1/30天、¥10/365天（可配置）
- 后台定时任务：每小时清扫过期 MAC
- procd init 脚本 + UCI defaults 自动建网络/防火墙/SSID
- install.sh / uninstall.sh
