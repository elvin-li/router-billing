# Changelog

## v0.118 — 深挖轮 4：MAC 计数全表扫描收尾

深挖轮 3 收尾：把 v0.111 引入的 `CountMACsByUser`（单条
GROUP BY）推广到最后两个仍在全表 `ListMACs` 后逐行数数的调用
点——`/api/admin/users`（每次 API 调用都拉全部 MAC 行到 Go 侧）
与 `/admin/export/users.csv`。行为不变（同样统计
`user_id IS NOT NULL` 的全部 MAC，不分状态），仅省去随 MAC 表
增长的线性内存/CPU。

其余复查确认无缺陷（不改动）：nftables 原子 sync/walled-garden
payload、WeChat 平台证书缓存与 AES-GCM 解签、Alipay 分账金额
解析、notify 单 worker 重试管线、sightings/dnsmasq 轮询、
deploy 脚本（v0.104/v0.110 已加固）、rateLimiter 硬上限 GC。
`go test ./...` 全绿；server/service/notify/pay 包 `-race` 绿；
golangci-lint 无告警。

## v0.117 — 深挖轮 3：用户认领 MAC 的 TOCTOU、2FA 计数器泄漏、UTF-8 截断

v0.116 之后的第三轮独立审计，聚焦此前多轮加固后仍残留的
check-then-write 竞态与慢性资源泄漏。修复三类真实缺陷。

A. (MEDIUM, 竞态/越权) `/user/macs/claim` 的认领路径是非原子的
GetMAC 检查 → 无条件 `UpsertMAC`：检查与写入之间若发生并发变
更，会出现两种错误结果——(1) MAC 刚被转移给另一用户时被静默
抢回（与 v0.111 用 `ExtendMACOwned` 修掉的 user-grant 扇出同
类，认领路径漏掉了）；(2) 更糟：`UpsertMAC` 的 UPDATE 分支无
条件写 `status='active'`，认领与管理员 Revoke 并发时会把刚拉
黑的行翻回 active——下一次每小时防火墙 resync 就把被封设备重
新放行。新增 `DB.ClaimMAC`：资格条件（active、未过期、无主或
本人）全部进 WHERE 子句，认领只转移所有权、绝不碰
status/expiry/label；`/user/macs/label` 同样改为
`SetMACLabelOwned`（`WHERE user_id = ?` 原子守卫），改名不再
能落在刚转走的设备上。回归测试覆盖：认领无主、幂等重认领、拒
绝他人设备、拒绝并保持 blocked（不复活）、拒绝已过期、非属主
改名被拒（端到端）。

B. (LOW, 慢性内存泄漏) admin/user 两个 2FA 尝试计数 map
（`twoFAAttempts`/`userTwoFAAttempts`）只在成功或锁定时删除条
目——被放弃的 pending 登录（关标签页、5 分钟会话自然过期）每
次泄漏一条，路由器数月不重启会无界增长。改为共享的
`attemptTracker`：条目带首次尝试时间，map 超过 128 条时在插入
路径按 15 分钟 TTL 清扫（远超 5 分钟 pending TTL，活跃暴破计
数绝不会被误清）。回归测试断言过期条目被清、存活条目计数保留。

C. (LOW, 数据损坏) 全部 14 处自由文本长度上限用字节切片截断
（`label[:60]`、`notes[:1000]`、`reason[:200]`、`msg[:500]`、
UA `[:80]` 等）——中文输入在边界处被从多字节 rune 中间切开，
无效 UTF-8 原样入库：html/template 与 JSON 导出渲染成 U+FFFD
替换符，CSV 导出直接输出坏字节。新增 `truncateRunes`（字节预
算不变、回退到 rune 边界）并全站替换。回归测试逐字节预算断言
永不产生无效 UTF-8。

其余复查确认无缺陷（不改动）：pay 轮询/finalize/refund 互斥与
金额核验、voucher 消耗-补偿链、backup VACUUM INTO+fsync、
Alipay RSA2 验签与金额解析、scheduler/purge/expiry-reminder
的 panic 防护与去重、CSRF/安全头/信任代理链、admin 三层 token。
全量 `go test ./...` 与 `go test -race`（server/db 包）绿。

## v0.116 — 深挖轮 2：管理端 CSV 导出静默截断修复 + 剩余子系统全覆盖复查

v0.115 之后的第二轮独立全库审计（重点覆盖此前审计较少的面：
sms/config/models/walledgarden/firewall-ipset/db-migrate/backup/
notify/arp/openwrt 部署脚本/api_admin/SSE 流/模板 XSS 面），发
现并修复一个真实缺陷。

A. (MEDIUM, 静默数据丢失) 管理端 CSV 导出全线被 DB 层静默截
断：各导出 handler（orders/users/macs/audit/sms-log/
webhook-log/vouchers）向 DB 层请求 1000–10000 行，但
`internal/db` 各查询函数的防御性 clamp 把「超过小阈值（100/
200/1000）的 limit」直接重置回小默认值——例如
`ListOrders(5000)` 实际只返回 100 行、`SearchUsers(…, 5000)`
只返回 200 行。导出文件看起来正常、无任何警告，管理员拿到的
对账/备份数据不完整（超过 100 单的月度对账即受影响）。修复：
DB 层引入统一的 `clampLimit(limit, def)`（非正数→默认值，上
限统一 10000），`ListOrders`/`SearchMACs`/`SearchUsers`/
`ListVouchers`/`SearchAudit`/`SearchSMSLogs`/
`SearchWebhookDeliveries`/`SearchOrdersFiltered` 全部改用；
orders 导出上限提到 5000、vouchers 导出提到 10000。回归测试
（`admin_export_limits_test.go`）对 6 类导出各插入超过旧阈值
的行数并断言 CSV 行数不再截断。

其余复查确认无缺陷（不改动）：Aliyun SMS 签名/并发安全与
Console ring buffer、config 校验全链（bcrypt/totp/token 长
度/时长负值/SMS provider 白名单）、schedule 跨午夜与 ISO 周
日、walled garden 公网过滤/字面 IP/缓存 TTL、ipset
build-aside-and-swap 原子替换、迁移的 user_version 门控 token
哈希化、backup VACUUM INTO + fsync + .tmp 清扫、notify 单
worker 的 re-enqueue 退避 + panic 恢复 + nil client 防御、
模板无 template.HTML/JS 注入面、api_admin 三层 token 权限与
1MiB 全局 body cap（csrfMiddleware 对含 /api 在内的全部路由
生效）、SSE 流每 tick 复查会话存活、attention 3s 缓存的锁窗
口正确。全量 `go test ./...` 与 `go test -race ./...` 绿。

## v0.115 — 深挖轮：微信回调 nonce panic、限流器内存/CPU 上限、竞态测试修复

v0.114 之后再做一轮全子系统深挖（支付回调解密、限流器资源上
限、只读 token 三层权限、QR 端点、日程复活、walled garden DNS
缓存、nft 超时、date() 统计、到期扫描原子性、CI/ipk/install.sh
权限），发现并修复三个真实缺陷。

A. (MEDIUM, 远程 panic DoS) `WeChat.DecodeNotify` 把通知体里攻
击者可控的 `resource.nonce` 直接传给 `aead.Open`——Go 的 GCM
在 nonce 长度不等于 12 字节时是 **panic** 而不是返回错误，且
`/notify/wx` 的头部验签是软失败（平台证书拉取失败时仅记日志、
继续走 AES-GCM 体认证），所以任何人 POST 一个 nonce 长度异常
的 JSON 就能触发 panic（net/http 恢复后中断该连接并刷整页栈日
志）。现在解密前校验 `len(nonce) == aead.NonceSize()`，不符返
回 `ErrInvalidPayload`；`refreshPlatformCerts` 的证书解密同样
加防（虽走 TLS 可信通道，防御性跳过坏条目）。回归测试覆盖
空/过短/过长三种 nonce。顺带：`--check-config` 现在校验
`pay.wechat.api_v3_key` 必须恰 32 字节（AES-256 要求），否则
以前要到第一笔回调才在 `aes.NewCipher` 报错。

B. (MEDIUM, 资源耗尽 DoS) IP 键控限流器（登录/找回密码等共 5
个实例）的 hits map 只清理**过期**条目——窗口期内的活跃 key
无上限。攻击者轮换 IPv6 源地址（一个 /64 有 2^64 个可用地址）
以 1000 req/s 灌一小时即 360 万条目（数百 MB），足以打爆内存
受限的路由器。两处修复：map 超过 8192 时硬性驱逐回 4096（在
那个量级本来就是洪水，牺牲一点限流精度换不 OOM）；同时把原来
「超过 4096 后每次插入都全表扫描」的 GC 改为按大小阈值摊销触
发——修复前那本身就是 O(n)/请求的 CPU 燃烧点（回归测试从
3.3s 降到 0.02s）。5 万唯一 key 洪水回归测试断言 map 恒
≤8192。

C. (LOW, 假红 CI) `TestAdminTestWebhookEnqueuesEvent` 的捕获
服务器先递增 hits 再写 lastBody，而等待方把 hits≥1 当作
「body 已就绪」——-race 调度下主 goroutine 可在两步之间读到
空 body；且单次 `r.Body.Read` 本就可能只读到部分分块。改为
`io.ReadAll` 全量读取后再递增计数。该测试在本轮全量 -race 中
实际失败过一次，非理论问题。

其余复查确认无缺陷（不改动）：`/api/pay/qr` 仅编码 DB 中
qr_payload（开放编码器已在 v0.105 关闭）、SSID/voucher QR 均
在 admin 门禁后、只读 token 的 Read/Write/Privileged 三层
（备份流属 Privileged）、`/api/admin/sessions` 不回 token、
voucher 列表只回 4 字符前缀、日程复活已有
TestScheduleEnforceDoesNotResurrectConcurrentRevoke 覆盖、
`audit_log.at` 由 SQLite CURRENT_TIMESTAMP 写入故 `date(at)`
可解析（不属 v0.107 那类 Go 格式回归）、`ExpireDueMACs` 为单
条原子 UPDATE...RETURNING、walled garden DNS 失败缓存/公网过
滤/IPv6 映射剥离均有测试、nft/ipset 全部 exec 路径带 5s 超
时、install.sh 密钥文件用 `install -m 0600 /dev/null` 预建无
权限窗口、CI 含 -race/ipk 结构与 0600 校验/aarch64 断言/
Docker 健康检查。全量 `go test -race ./...` 绿。

## v0.114 — 合并收尾 + 全库复audit：VACUUM 快照 fsync、导出文件名注入

v0.113 合并落地后的收尾轮：先把 PR #14 (merge-audit-hardening)
的 12 个提交全部合入（其 merge-base 即本分支 HEAD，语义无冲
突，全量测试 + race 通过）；再对 PR #1/#2/#3 与全部 22 条
origin/cursor/* 分支做最后一遍逐提交内容级比对，确认除下述一
项外全部已有等价实现；最后对 web 处理器、支付回调、2FA/信任设
备、防火墙、walled garden、后台任务、DB 事务层做整轮复查。

A. (LOW→MEDIUM, 备份耐久性；PR #3 漏网移植) 备份轮转器的
`VACUUM INTO` 路径在 rename 发布快照前不做 fsync。SQLite 写
VACUUM INTO 目标时不保证落盘（synchronous 不作用于目标库），
在路由器常见的延迟分配文件系统（ext4/f2fs）上，rename 之后断
电可能留下一个顶着合法快照名的零长度/半截「备份」——恰好是
v0.108 给 checkpoint+copy 回退路径加 fsync 时修的同一类问题，
主路径漏掉了。现在 VACUUM INTO 产物同样先 `fsync` 再
rename，失败则删除临时文件报错（下一轮重拍）。

B. (LOW, 头注入面) `/admin/vouchers/export.csv` 把自由文本的
`?batch=`/`?status=` 原样拼进 `Content-Disposition` 的
quoted-string 文件名。net/http 会中和 CR/LF，但双引号原样通
过：名为 `x";evil="1` 的批次可以逃出引号、向响应头走私附加参
数，且跨浏览器 RFC 6266 解析行为不一致。其余导出端点在 v0.107
已统一为常量文件名，唯独 voucher 导出为自描述保留了批次名——
现在过 `filenameSafe`（仅留 ASCII 字母数字与 `._-`，60 字符封
顶）。过滤本身仍按原始批次值匹配，导出内容不变。回归测试断言
头里恰好一对引号、无参数走私、行数据完整。

其余复查确认无缺陷（不改动）：支付金额核验/finalize 防取消/
退款互斥、session 与 trusted-device 哈希迁移的调用方全部传原
始 cookie 值、panic 按钮 keep 语义、2FA 登录/确认/关闭的重放
高水位与尝试上限、webhook 重入队 worker、walled garden 公网
IP 过滤与部分 DNS 失败缓存、nft 原子事务与 5s 超时、
purge/expiry/reminder 各 loop 的关机与去重语义、schedule 跨午
夜窗口、Alipay RSA2 验签 + app_id 校验、WeChat 平台证书验签 +
AES-GCM + mchid/appid 校验。顺带把 PR #14 带进来的迁移注释中
过时的「v0.97」版本号改正为实际发布版本 v0.113。

## v0.113 — 合并遗漏修复 + 新一轮审计：voucher 授予竞态、撕裂备份下载、SSID QR 泄漏

两部分工作。第一部分把仍在未合并分支上的真实修复移植进来
（对照 PR #1/#2/#3 及全部 origin/cursor/* 分支逐提交内容级比
对，已被等价实现覆盖的不重复合并）；第二部分是新一轮子系统审
计发现的三个新缺陷。

### 新发现并修复（本轮审计）

A. (HIGH, 并发丢失更新) `GrantFromVoucher` 没有持有 v0.110 引入
的服务级互斥锁——同族的 GrantFromOrder / Extend / Revoke /
Resync / ExpireDue 全部在锁内，唯独 voucher 授予路径漏掉。后果
与 v0.110-A 完全同类：兑换的 `FW.Add` 落在并发 Resync 的
「读活跃列表 → 全量重建」窗口内时，会被重建直接冲出内核集合
——充值码已消耗、设备却离线，直到下一次对账。失败路径的
resync 改用已持锁的 `resyncLocked`（避免自死锁）。确定性 gate
回归测试（冻结 Resync 于 FW.Sync 内、并发跑 GrantFromVoucher）
在修复前代码上验证会失败。

B. (MEDIUM, 数据损坏) `/admin/backup` 与 `/api/admin/backup` 下
载端点仍是 checkpoint 后直接 `io.Copy` 活库文件——v0.109 已给
夜间轮转备份改用 `VACUUM INTO` 修掉撕裂快照，但按需下载路径漏
掉了：下载期间落盘的写事务（支付、会话、审计）可撕裂页面，静
默产出损坏的备份——恰恰是主库丢失后运维要恢复的那份文件。现
在两个端点都先 `VACUUM INTO` 一致性快照再流式返回（临时文件用
后即删），仅当 VACUUM INTO 本身报错才回退旧行为，与轮转器策略
一致。

C. (MEDIUM, 凭据泄漏 + 开放编码器) `/admin/ssid-cards/qr` 从查
询串接受 `?ssid=&password=` / `?url=`：WPA 密码随 GET URL 进浏
览器历史与访问日志（每次 <img> 拉取一行）；PNG 响应带
`Cache-Control: public, max-age=300`，明示共享缓存可存储含密码
的已认证响应；自由参数还让它成为我们域名上的开放 QR 编码器
（与 v0.103 修掉的 /api/pay/qr 同类）。现改为枚举参数
`?card=free|paid|secure|portal`，载荷全部服务端从配置解析，响
应 `no-store`。回归测试钉住两个属性。

### 从未合并分支移植（内容级比对后仅取 HEAD 仍缺失的）

来自 PR #3 (cursor/comprehensive-optimization)：

- (MEDIUM, sec) 会话令牌与受信设备（「记住此浏览器」跳过 2FA）
  令牌改为 SHA-256 哈希落库——拿到 DB 文件或备份不再等于拿到可
  重放的登录/免 2FA cookie。一次性迁移（PRAGMA user_version=1/2）
  原地改写存量行，设备上的 cookie 继续有效、无人被登出。
  /admin/sessions 撤销表单改为回传哈希，页面 HTML 不再内嵌每个
  live 会话的原始 cookie 值。
- (MEDIUM, sec) /admin/users/reset-password 生成的临时密码不再
  经重定向 URL（?reset_pwd=...，浏览器历史/中间层日志都会留
  存）传递，改走进程内一次性 flash 存储（2 分钟 TTL，弹出即
  删，刷新页面不再显示）。
- (MEDIUM, 正确性) Resync 现在感知时段计划：窗口关闭的 MAC 不
  再被启动/手动/周期 resync 放回防火墙（此前会放行至多一分钟，
  直到分钟级 enforcer 再移除）。到期巡检 cron 每个 tick 额外跑
  一次 panic 隔离的 Resync，瞬时 nft 失败造成的防火墙漂移一小
  时内自愈，无需重启或手动 /admin/resync。
- (perf) attention 计数器 3 秒进程内缓存（此前每次管理页渲染、
  仪表盘双查、每条 SSE 流每 5 秒各打 6 条 COUNT）；
  /admin/users 的按用户 MAC 计数改为一条 GROUP BY；无过滤 MAC
  列表在 SQL 层 LIMIT（此前全表进 Go 再截断）、管理页统一 500
  行上限；/admin/devices 的计费行改为一条 IN 批量查询（此前每
  设备一次 GetMAC）；/pay/success 的收据查找改为带 30 分钟反探
  测窗口（窗口条件下沉到 SQL）的定向索引查询
  `LatestPaidOrderForMAC`——旧的「扫最新 50 单」在支付后又产生
  50+ 订单时会静默丢失收据链接。

确认已被等价实现覆盖、未重复合并的：PR #1/#2 的 render 缓冲、
payqr 编码器、批量导入（v0.102/103 已含）；PR #3 的金额校验、
VACUUM INTO 轮转备份、webhook 队列排空、nft 原子事务、XFF 信
任代理、finalize 防取消等；auth-2fa-csrf-port /
background-jobs-deep-opt / firewall-garden-deploy /
port-db-tx / port-remaining-fixes 各分支的全部提交（HEAD 均有
等价实现）。

## v0.112 — Web handler audit: CSP-dead inline JS, unbounded multipart bodies, cacheable voucher QRs

Follow-up hunt over the web handler surface for the usual suspects.
Confirmed already-correct (no change needed): every mutating UI handler
is POST-only (no CSRF-exempt mutating GETs remain after the v0.108/109
logout fixes), every rendered POST form carries the `_csrf` field with
the right template scope, `missingkey=zero` is in effect and smoke-
tested, clickjacking headers (X-Frame-Options SAMEORIGIN + CSP
frame-ancestors 'self') apply to every response, and all session-bearing
cookies are HttpOnly + Secure-on-TLS + SameSite=Lax. What remained was
three real bugs:

A. (HIGH, functional + safety) The CSP has shipped `script-src 'self'`
(no 'unsafe-inline') since v0.8 — but the templates were full of inline
`<script>` blocks and `onclick=`/`onsubmit=` attributes, ALL of which
CSP-enforcing browsers silently refuse to run. Consequences in a real
browser: every `confirm()` guard on a destructive action never fired
(delete user / delete MAC / revoke session / panic button / cancel-stale
/ trim logs all executed on first click with no prompt), the orders-page
refund button did literally nothing (its dialog opener was an inline
function), the /admin/macs bulk-select toolbar was dead, the backup-codes
copy button was dead, the redeem-code input formatter never ran, and the
portal service worker never registered. Fixed by externalizing all of it:
new `static/ui.js` (delegated `data-confirm` / `data-print` /
`data-dialog-close` handlers — delegation also covers rows injected by
the devices SSE stream, whose generated `onsubmit` was equally blocked),
`static/admin-macs.js` (bulk bar), `static/admin-orders.js` (refund
dialog), `static/redeem.js`, `static/user-2fa-codes.js`, and the SW
registration moved into `portal.js`. 43 inline handlers across 19
templates became `data-*` attributes. `TestTemplatesAreCSPCompatible`
pins the invariant (no inline scripts / handlers in templates or
JS-generated markup; every referenced static script exists).

B. (MEDIUM, DoS) `verifyCSRF` reads the token via `r.FormValue`, which
for multipart bodies runs `ParseMultipartForm` — buffering the WHOLE
body (everything past 32 MiB spills to temp files) with no total-size
limit. Because the CSRF check runs in the auth wrappers BEFORE any
handler code, handler-level `http.MaxBytesReader` caps (e.g. the 256 MiB
cap in the restore upload) were installed after the body had already
been consumed and never actually applied. Net effect: any client — even
unauthenticated, e.g. against /user/forgot-password — could stream
gigabytes of multipart at a form endpoint and fill the router's
tmpfs/flash. csrfMiddleware now caps every request body at 1 MiB (far
above the largest legitimate form, the import textareas) before anything
parses it; the one genuinely big-body endpoint, `/admin/backup/restore`,
keeps its advertised 256 MiB. Over-cap uploads now die at the CSRF gate
with 403.

C. (LOW) `/admin/vouchers/print/qr` served the QR PNG of a full
unredeemed voucher code — a bearer value redeemable for paid days — with
`Cache-Control: public, max-age=3600`, explicitly inviting shared proxy
caches to store an authenticated admin response and leaving codes in
browser disk cache on shared machines. Now `no-store`.

## v0.111 — Deploy-script audit: uninstall left a dangling fw4 include, ipk broke image builds

Audit pass over deploy/openwrt, the ipk maintainer scripts, Dockerfile
and docker-compose. Confirmed already-correct: the nftables-1.0
`fwd`→`forward` rename, the `PKG_UPGRADE` guard in prerm (no firewall
teardown mid-upgrade), and client isolation on setup-secure-ssid.sh's
update path. Fixed what remained:

A. `uninstall.sh` removed `/usr/share/router-billing` but left the fw4
`include` (registered by uci-defaults) pointing at the now-deleted
`firewall-billing.sh` in `/etc/config/firewall` — every firewall reload
after uninstall referenced a missing script. Uninstall now deletes the
matching include section(s) (descending index order) and commits.

B. `ipk/postinst` and `ipk/prerm` ran unconditionally on the build host
when the package is installed into an image root (`IPKG_INSTROOT`
set): `/etc/init.d/router-billing` doesn't exist there, so `set -e`
failed the whole install — and the uci/nft paths would have targeted
the host, not the image. postinst now creates the rc.d enable symlinks
(S95/K10) inside the target root and exits; prerm exits immediately
(nothing is running in a build root). SSID/firewall setup happens via
uci-defaults at the image's first boot, as OpenWrt intends.

C. All eight deploy scripts were mode 0644 in git (the Makefile papered
over it with `install -m 0755` at package time, but a git checkout or
extracted source tree had non-executable scripts). Exec bits set.

D. shellcheck SC2086: unquoted `firewall.@zone[$IDX]` /
`wireless.@wifi-iface[$SECTION]` uci arguments are glob patterns
(`[0]` is a character class) and could be rewritten by pathname
expansion. Quoted in uci-defaults and setup-secure-ssid.sh.

E. `install.sh` generated the Free_WiFi key from 12 random bytes
(16 base64 chars) — stripping `/+=` could leave fewer than the 12
chars cut. Bumped to 18 bytes / 24 chars, matching the uci-defaults
generator (which was already fixed for exactly this reason).

## v0.110 — Concurrency: DB↔firewall lost updates serialized; duplicate reminder SMS

Race-hunting pass over everything that pairs a SQLite mutation with a
firewall or SMS side effect. The DB layer is transactional and both
firewall backends serialize their own commands, but the PAIRING of the
two was not atomic — concurrent actors (payment finalizer, hourly
expiry scheduler, minute schedule enforcer, admin handlers) could
interleave into firewall state that contradicts the DB until the next
resync. All fixes carry deterministic regression tests (a one-shot gate
freezes one actor inside its firewall/SMS call while the conflicting
actor runs); each test was verified to fail against the pre-fix code.

A. (HIGH) `MACService` now holds a service-level mutex across every
composite DB+firewall operation (grant, extend, revoke, delete,
replace, resync, expiry sweep, schedule enforcement). Closed lost
updates, each of which knocked a PAYING customer offline (or left a
blocked one online) for up to an hour:

- a grant landing between `Resync`'s active-list read and its full
  set rebuild was flushed straight back out of the kernel set;
- a payment re-activating a MAC between `ExpireDue`'s DB flip and its
  firewall-removal loop had its fresh `FW.Add` yanked by the sweep;
- the minute schedule enforcer could re-add a MAC that a concurrent
  admin revoke had just blocked and removed, for the rest of the
  schedule window.

`GrantFromOrder`'s failure-path resync now reuses the already-held
lock (`resyncLocked`) instead of self-deadlocking.

B. The immediate schedule apply (`/admin/macs/schedule` save + clear)
moved from the handler into the locked service method
`ApplyScheduleNow`: the v0.108 eligibility check was correct but ran
unlocked, so a revoke/expiry landing between the row re-read and the
`FW.Add` was silently overwritten. Clearing a schedule on an
ineligible MAC now defensively removes it (previously: just didn't
add).

C. Overlapping expiry-reminder passes double-texted users: the hourly
loop and the manual /admin/sms-log/expiry-reminders trigger share a
22h audit-row de-dup window that is only written AFTER each SMS is
delivered, so two concurrent passes both listed (and texted) the same
owners. One pass at a time now — the second pass observes the first
one's de-dup rows and sends nothing. SMS costs real money per message,
so this was a billable bug, not just noise.

## v0.109 — User logout CSRF + payment/voucher correctness

### User logout CSRF hardening

Deep-review follow-up closing a CSRF-logout vector that the v0.108 admin
logout hardening left open on the user side. No product features.

A. (MEDIUM) `/user/logout` ended the session on ANY method — including a
plain GET — and performed no CSRF check, and `user_me.html` triggered it
via a bare `<a href="/user/logout">` link. Because our session cookies
are SameSite=Lax, cookies ride along on top-level cross-site GET
navigations and on the speculative link-prefetches some browsers issue,
so a hostile `<a>`/`<img>` or an eager prefetcher could silently sign a
logged-in user out. This is the exact vector v0.108 fixed for
`/admin/logout`; the user path had been missed. `/user/logout` is now
POST-only with a CSRF token (GET bounces to `/user/me` with the session
intact), and the account page renders logout as a POST form carrying the
CSRF field.

### Payment/voucher correctness: redeem burn compensation, refund/finalize serialization

Deep pass over the money paths (orders, refunds, voucher redemption).
Two real bugs, both of the "value consumed but not delivered" family
that v0.106 already closed on the pay-finalize path.

A. (HIGH) A redeemed voucher could be burned with nothing granted.
`POST /redeem` consumed the code (`RedeemVoucher`) and then applied the
days via `MACSvc.Extend` — which (a) ran on the request context, so a
browser disconnect between "consumed" and "granted" aborted the grant,
and (b) failed hard on a firewall-only error even though the DB grant
had committed. Either way the customer's code stayed consumed:
"授权失败请联系管理员", no automatic recovery — the exact hole the pay
path fixed in v0.106 with `RevertOrderToPending`, missed on redeem.
Now: the grant runs under `context.WithoutCancel`, uses the new
`GrantFromVoucher` (same contract as `GrantFromOrder`: error only when
nothing durable happened; firewall failures log + resync but don't
fail a durable grant), and on a real grant failure the new
`UnredeemVoucher` compensation puts the code back to unused (guarded
by code + redeeming MAC so it can only undo that specific redemption)
and tells the user to retry.

B. Refunds could interleave with payment finalization. `finalizeOrder`
serializes on `pollMu`, but both refund handlers (admin UI and the
programmatic `/api/admin/orders/refund` meant for chargeback
automation) called `MarkOrderRefunded` directly. A refund landing
between `MarkOrderPaid` and `GrantFromOrder` saw status=paid, rolled
back days that had not been granted yet, and then the grant landed
anyway — a refunded order that kept its access (and, on the
grant-failure branch, a `RevertOrderToPending` that could no longer
fire). All refunds now go through `App.refundOrder`, which takes
`pollMu` so a refund waits for any in-flight finalize and only rolls
back a fully-granted order.

Regression tests: firewall-down redeem still succeeds (DB is source of
truth), grant-blocked redeem un-redeems the code and the retry works
(simulated with a SQLite trigger on `macs`), `UnredeemVoucher` guard
semantics, and refund blocking on `pollMu` until finalize completes.

## v0.108 — Background-job reliability follow-up: hung-webhook backstop, fsync'd backups

Deep-review follow-up to the v0.107 jobs merge, closing residual gaps
on the same surface. No product features.

A. (HIGH) The notify worker could still wedge forever on a single
request: an endpoint that accepts TCP and never responds held the
single worker goroutine for as long as the HTTP client allowed — and a
Notifier whose HTTPClient had no Timeout (http.DefaultClient has none)
allowed forever. Every delivery attempt now runs under a hard
per-attempt context deadline (`AttemptTimeout`, default 30s)
independent of the client config; a timed-out attempt still retries on
schedule. A nil HTTPClient no longer nil-panics per event. Response
bodies are drained (bounded) before close so keep-alive is reused.

B. Backup fallback copy is fsync'd before rename. Without the flush, a
power cut shortly after rename could leave a zero-length "backup" on
ext4/f2fs.

C. A snapshot whose context is already canceled no longer falls through
to checkpoint+copy without a WAL checkpoint. It aborts cleanly
(removing `.tmp`).

D. An expiry-reminder pass stops once its context is canceled instead
of writing one `expiry_reminder_failed` audit row per leftover MAC.

E. Admin-digest audit rows use `context.WithoutCancel`, and the manual
digest trigger detaches from the request context.

## v0.107 — Consolidated hardening: merge of PRs #5–#13

One combined release merging nine parallel hardening branches (test
hardening, DB transactions/time/indexes, firewall/portal, background
jobs, portal/user security, admin API, auth/2FA/CSRF, admin UI,
config/CI/docker). Where branches fixed the same bug independently the
stronger fix won:

- nftables List(): the JSON-based parser (firewall branch) replaced the
  text-anchored parser (test branch); both fixed the dropped-first-MAC
  bug, and the exec-level regression tests were ported to the JSON API.
- Client-IP attribution: security.trusted_proxies (auth branch, CIDR
  allowlist + realIPMiddleware, last-XFF-entry semantics) replaced the
  portal branch's security.trust_proxy_headers boolean; all call sites
  now go through the middleware-resolved IP.
- Walled garden: full-list atomic rebuild with timeout refresh
  (firewall branch) combined with the public-IPv4 answer filter and
  literal-IP passthrough (portal branch).

Also includes the test-hardening branch's new coverage for config
loading, schedule enforcement, arp/sightings exec paths and the JSON
logger. Details per area below.

### Firewall/portal correctness: 22.03 apply failure, walled-garden 25h death, List drops a MAC, paid-zone router exposure

Correctness pass over the MAC whitelist, the captive-portal redirect
and the paid/free SSID split. Everything below was verified against a
live kernel (nft 1.0.9, the OpenWrt 23.05 userspace).

A. (HIGH) firewall-billing.sh failed WHOLESALE on OpenWrt 22.03. The
`tcp dport 443 reject` sat in the nat/prerouting chain, but kernels
before 5.11 only allow the reject statement in input/forward/output
(nft_reject validate; prerouting was added in commit 117ca1f8920c) —
and 22.03 ships kernel 5.10. The kernel refuses the whole `nft -f`
transaction at commit time, so apply produced ZERO billing rules and
every Paid_WiFi device was online for free — the exact failure mode
v0.104 fixed for the `fwd` keyword, reintroduced one hook down.
(`nft -c`/"verified parsing" can't catch it: the EOPNOTSUPP comes from
the kernel at commit.) The 443 reject now lives in the forward chain
(valid on every kernel this project supports) as `reject with tcp
reset`, which is also the correct signal for captive-portal probes.
HTTP redirect stays in prerouting; behavior for clients is unchanged.

B. (HIGH) The walled garden silently died after 25 hours of daemon
uptime. Elements carry a 25h timeout, but the kernel does NOT refresh
an element's expiry when it is re-added — and the resolver only pushed
IPs it hadn't seen before. Stable payment-server IPs (WeChat/Alipay
resolve very consistently) therefore expired out of the set and were
never re-added: unpaid devices could no longer reach the payment
servers, i.e. nobody could pay, until the daemon restarted. The
resolver now pushes the FULL resolved list every refresh cycle and the
new Manager.SyncWalledGardenIPs rebuilds the set atomically (one
`nft -f -` transaction) with fresh 25h timeouts. IPs are validated as
plain IPv4 before they enter the nft script — DNS answers are
attacker-influenced input. A total DNS outage leaves the set alone
(drains via timeout) instead of wiping it.

C. (HIGH) nftables List() dropped the first MAC of every listing (the
same bug PR #5 fixed on its branch, independently confirmed here
against real nft output). The text parser cut from the TABLE's opening
brace, split on commas and truncated tokens at the first space, so the
first element — glued to "set mac_paid { … elements = {" — was always
discarded. Any consumer reconciling DB↔firewall from List would
conclude that MAC was offline. List now parses `nft -j` JSON with the
same parser Counters uses.

D. (MED) Sync (nft backend) was flush-then-add as two separate nft
processes: every resync briefly exposed an EMPTY whitelist (paid users
redirected to the portal mid-session), and an error between the two
calls left it empty until the next resync. Both operations are now one
`nft -f -` netlink batch — readers see old or new membership, never
the gap, and a failed transaction keeps the old set. The ipset backend
had the same flaw (`ipset restore` replays lines, it is not a
transaction, despite the comment): it now stages into `mac_paid_swp`
and uses `swap`, which IS atomic; the live set is never flushed.

E. (MED, security) The fw4 paid zone was created with input=ACCEPT,
exposing every service on the router itself — dropbear/SSH, LuCI,
anything listening — to unpaid strangers on the open SSID. The
explicit Allow-DHCP/DNS/Portal rules that have always been generated
alongside it only make sense with input=REJECT, which is what the zone
now gets; the three allows keep DHCP, DNS and the portal working.
Re-running the uci-defaults script (which an ipk upgrade does
automatically) migrates existing ACCEPT zones; manual installs can run
`sh /etc/uci-defaults/99-router-billing-ssid` or flip
`uci set firewall.@zone[N].input='REJECT'` by hand.

F. (MED) opkg upgrades opened a free-internet window: prerm runs on
upgrade too (remove-then-install) and purged the whole billing table,
so redirect/drop rules were gone while the new package unpacked. prerm
now skips the purge when opkg signals PKG_UPGRADE=1; real removals
still purge.

G. setup-secure-ssid.sh's "SSID exists, update the key" path had never
worked: `awk -F'[].[]' {print $2}` extracts the literal "@wifi-iface",
not the section index, so the subsequent `uci set` always errored out
under `set -e`. Now extracted with an anchored sed capture (the
uninstall.sh how-to had the same field bug, plus it deleted sections
in ascending index order — deletions shift later indices — now
descending). The key is also recorded into wifi-keys.txt like
install.sh does.

H. ipk installs brought the Free SSID up OPEN: only install.sh
generated FREE_KEY, but the uci-defaults script runs with an empty
environment from postinst / first boot. It now generates the key
itself when it is about to create the SSID without one, and records it
in /etc/router-billing/wifi-keys.txt (0600), same as install.sh.

I. Hardening: paid SSIDs get AP client isolation (isolate=1 — the open
paid network is all strangers; the free/friends SSID stays isolate=0);
config.yaml is installed 0600 instead of 0644 (it holds the admin
bcrypt hash and WeChat/Alipay merchant keys) by both install.sh and
the ipk build, and install.sh tightens existing installs.

New regression tests: real nft-1.0.9 JSON List output keeps the first
MAC; sync payloads are single transactions (flush-only when empty);
walled-garden payload validates/rejects IPv6, garbage and nft-script
injection; the resolver re-pushes the full list every cycle and leaves
the set alone on DNS outage; the ipset restore script stages+swaps and
never touches the live set directly.

### DB layer: broken date() stats, expiry-sweep atomicity, tx gaps, indexes

SQLite/Go correctness pass over internal/db.

A. (HIGH) Two daily stats were permanently zero. modernc.org/sqlite
stores Go-bound time.Time as "2006-01-02 15:04:05.999 +0000 UTC" — a
format SQLite's date() function returns NULL for. So SnapshotToday's
`date(paid_at) = date('now')` recorded paid_orders = 0 in every daily
snapshot ever taken, and Attention's `date(created_at) = date('now')`
kept the FailedToday dashboard chip at 0 no matter how many orders
failed. Both now compare against datetime('now','start of day'),
which works lexicographically on the shared "YYYY-MM-DD HH:MM:SS"
prefix — the same pattern DashboardSnapshot already used (its comment
even warned about date(); the two older call sites never got the
memo). SnapshotToday also no longer swallows the count error.

B. (MED) ExpireDueMACs was a SELECT list followed by a separate
blanket UPDATE — not atomic. A MAC extended between the two
statements stayed active but was still in the returned list, so the
caller revoked firewall access for a customer who had just renewed; a
MAC expiring between the statements got flipped but was never
reported, so its revoke webhook/notify never fired; and two
concurrent sweeps could both report the same MAC (double webhooks).
Now a single `UPDATE ... RETURNING mac` — flip and report are one
atomic statement, each due MAC is claimed by exactly one sweep.

C. (MED) ClearUserTOTP ran three separate statements (wipe secret,
delete backup codes, delete trusted devices). A failure after the
first left 2FA off WITH live trusted-device tokens that would
silently bypass the next enrollment's challenge. All three writes now
commit in one transaction.

D. (MED) SuspendUser's session purge was a separate best-effort
statement whose error was discarded — a failed delete left the
suspended user with a working session until natural expiry.
DeleteUser had the same swallowed-error pattern. Both are now single
transactions that propagate errors.

E. (LOW) BumpPasswordResetAttempts was UPDATE-then-SELECT; two
concurrent failed verifies could both read the same post-increment
value, under-counting attempts against the brute-force cap. Now one
`UPDATE ... RETURNING attempts`.

F. (PERF) Missing indexes: sessions(user_id) — every per-user session
op (suspend purge, "sign out other devices", list, count) scanned the
whole table; and audit_log(action, target) — the daily expiry-
reminder loop's correlated NOT EXISTS probe re-scanned every
expiry_reminder row per candidate MAC. Both added via schema.sql's
idempotent CREATE INDEX IF NOT EXISTS, so existing deploys pick them
up on next startup.

Regression tests for all of the above, including concurrency tests
(verified under -race) that fail on the pre-fix code.

internal/db/db.go
internal/db/schema.sql
internal/db/tx_time_index_test.go

### Background-job reliability: webhook pipeline stall, SMS spam, torn backups

Reliability pass over the background jobs (scheduler, notify worker,
SMS loops, backup rotator, purge janitor). Complements v0.107's DB
fixes; no product features.

A. (HIGH) The webhook notify worker retried failures in-place, sleeping
through the backoff (up to ~5.5 min per event on the default 2s/30s/5m
schedule) on the single goroutine that drains the 64-slot queue. One
dead/slow endpoint stalled the whole pipeline until the queue
overflowed and later pay/grant/revoke events were silently dropped.
Retries are now scheduled with a timer and re-enqueued, so fresh
events keep flowing while a failed one waits its turn. (Retried events
may arrive out of order relative to newer ones — receivers should key
on the event payload, not arrival order.)

B. (HIGH) A panic in the notify worker — including the OnDelivery hook
that persists webhook_deliveries rows — or in one scheduler expiry
pass was unrecovered, killing the entire process (billing UI, payment
webhooks, firewall enforcement) over one bad tick. Both now recover,
log, and continue.

C. (HIGH) Backup snapshots could be silently corrupt: the rotator
checkpointed the WAL and then byte-copied the live DB file, so any
write landing mid-copy (order paid, session created) tore pages in the
copy — discovered only when restoring after losing the primary.
Snapshots now use `VACUUM INTO` (transactionally consistent under
concurrent writers), written to a .tmp and renamed, clamped to 0600.
Falls back to checkpoint+copy only if VACUUM INTO itself errors.

D. Backup rotator could wedge a full flash partition permanently:
prune only ran after a successful snapshot, so once the disk filled,
every snapshot failed and nothing was ever freed. Prune now runs even
when the snapshot fails. Orphaned `*.db.tmp` files from interrupted
snapshots (which the prune filter used to skip forever) are removed
once they're an hour old, and a failed copy flush no longer leaks its
partial .tmp.

E. (SMS spam) The expiry-reminder de-dup marker is an audit row written
AFTER the SMS goes out — with the caller's context. If that context
died in between (admin closed the manual-trigger page mid-pass, server
shutdown), the insert failed silently and every later hourly pass
re-texted the same users until the MAC expired. De-dup/outcome audit
rows and the sms_log row now use context.WithoutCancel, and the manual
trigger detaches from the request context entirely (same rationale as
the v0.106 payment-finalize fix). /admin/maintenance/expire-now is
likewise detached so a client disconnect can't split the DB expiry
flip from the firewall resync.

F. Daily admin digest fired one hour EARLY: the loop scheduled at
`hour-1` while config documents "at the given UTC hour" (1..24, 24 =
midnight). Also, after a suspend/clock step of N days the loop's
`target += 24h` catch-up fired N digest SMSes back-to-back; the next
send is now recomputed from the wall clock (extracted into testable
`nextDigestAt`).

G. Reminder SMS body understated remaining time by truncating
(71h → "2 天"); now rounds up ("3 天").

H. Aliyun SMS adapter: a literal &Aliyun{} (nil nowFn/nonceFn) panicked
inside whichever background goroutine sent the SMS; lazy in-place
HTTPClient/Endpoint defaulting inside Send was a data race under the
concurrent senders (reminder loop, digest loop, login alerts). Both
fixed with local-variable defaults and nil guards.

I. The purge janitor only ever ran 2h after boot, so routers that get
power-cycled daily never purged expired sessions / audit / sms /
webhook logs at all. One housekeeping pass now runs at boot (the
weekly VACUUM intentionally still waits — a daily-rebooted router
should not VACUUM daily).

Regression tests cover: fresh events flowing past a failing event's
backoff, retry completion, OnDelivery-panic survival, scheduler
panic survival, digest hour semantics + clock-jump absorption,
reminder de-dup across a mid-pass context cancel, day-count rounding,
snapshot integrity under a live DB (PRAGMA integrity_check), prune
running despite snapshot failure, stale .tmp cleanup, boot-time purge
pass, Aliyun zero-value Send and concurrent-Send race (-race).

### Security: X-Forwarded-For rate-limit bypass, SSE session leak, /pay/success order oracle, walled-garden LAN hole

Four independent portal/user-surface fixes:

A. clientIP() trusted X-Forwarded-For unconditionally. On the default
deployment (binary listening directly on the router LAN, no reverse
proxy) that header is client-controlled, so ONE spoofed header per
request defeated every IP-keyed rate limiter: unlimited voucher-code
guesses at /redeem (the only brute-force defense on 12-char codes),
login floods, /api/pay/create order floods, forgot-password SMS
pumping — and forged the IPs written into the audit log. XFF is now
only honored behind the new opt-in `security.trust_proxy_headers`
config (set it ONLY when a proxy you control overwrites the header).

B. /admin/devices/stream and /admin/stats/stream checked the admin
session only at connect time. A revoked session (panic button,
revoke-all, logout elsewhere) or an expired one kept receiving live
device data — MACs, IPs, DHCP hostnames, revenue counters —
indefinitely, since heartbeats keep the connection open forever. Both
streams now re-validate the session cookie on every tick/heartbeat
and close when it's gone.

C. /pay/success?mac= accepted any raw string and always looked up the
most recent PAID order for it — anyone who knew a neighbor's MAC
(they're broadcast on the LAN) could fetch their order number and
from it the full /receipt (amount, plan, order/trade numbers), any
time. The param now goes through NormalizeMAC, and the receipt link +
expiry row only render for orders paid in the last 30 minutes (the
page is only ever reached right after paying) or for the requester's
own detected device.

D. Walled-garden DNS answers pointing at loopback / RFC1918 /
link-local / CGNAT / multicast / 240/4 space are rejected before
entering the nftables bypass set. Previously a misconfigured or
hostile upstream resolver answering 192.168.1.1 for a garden CDN
domain let UNPAID devices reach the router itself (or other LAN
hosts) ahead of the drop rule. Literal IP entries configured in
`walled_garden.domains` still pass verbatim (explicit admin intent).

Also: db.RedeemVoucher's mark-redeemed UPDATE now re-asserts
`redeemed_at IS NULL AND revoked = 0` in its WHERE clause
(compare-and-set), so a double-spend can't win even if the
SetMaxOpenConns(1) serialization ever changes.

Tests: XFF ignored by default / honored when trusted, redeem limiter
survives header rotation, both SSE streams close within ticks of
session revocation (real httptest.Server), fresh-vs-stale receipt
gating + reflected-garbage mac, 16-goroutine single-winner redeem
(race detector clean), non-public DNS answers filtered vs literal IP
passthrough.

### Admin API: backup scope escalation, grant ownership clobber, CSV formula injection

Four admin-API security fixes:

A. /api/admin/backup accepted READ-ONLY Bearer tokens. The raw SQLite
file contains plaintext session tokens (which mint live admin/user
cookies), password hashes, TOTP secrets, full unredeemed voucher
codes, and SMS message bodies — exactly the material every JSON read
endpoint deliberately strips. A leaked monitoring token was therefore
a full-scope token in disguise. The route now goes through
requireAPITokenPrivileged, which rejects readonly tokens with 403 on
every method. Off-router backup automation must use a non-readonly
token (which it should have anyway — it holds the whole DB).

B. /api/admin/users/grant and /api/admin/users/grant-by-phone listed a
user's MACs and then extended each one through the unconditional
UpsertMAC path, which OVERWRITES macs.user_id. A device transferred
to a different user between the list and the per-MAC write (user-side
replace/claim flow) was silently re-extended AND reassigned back to
the granted user. New db.ExtendMACOwned / MACSvc.ExtendOwned guard
the update with WHERE user_id = ? in a single statement; a row whose
ownership changed is skipped (logged, excluded from macs_extended),
never stolen.

C. CSV exports (/admin/export/{macs,orders,users,audit,sms-log,
webhook-log}.csv + /admin/vouchers/export.csv) wrote user-influenced
text raw. MAC labels are settable by END USERS via /user/macs/label;
audit detail, SMS bodies, and gateway error strings carry external
text too. A label like =HYPERLINK(...) or a DDE payload executes when
the admin opens the export in Excel/LibreOffice. All text cells now
pass through csvCell, which prefixes ' when the first non-space byte
is one of = + - @ TAB CR. Timestamps/ids/normalized MACs are
unaffected.

D. /api/admin/orders/cancel-stale silently discarded JSON decode
errors, so a malformed body ({"older_than_hours":"48"} — string, not
int) fell back to the 24h default and canceled a MORE aggressive
window than the caller asked for. Empty body still means the
documented 24h default; malformed non-empty JSON is now a 400 with
zero cancellations.

Tests: readonly backup 403 (+ no DB bytes, no audit row, 401 without
token), ExtendOwned skip/extend matrix + grant-by-phone end-to-end
isolation, csvCell unit matrix + macs/audit/sms-log export round-trips
through encoding/csv, cancel-stale malformed-JSON 400 with order
untouched.

### Auth hardening: TOTP one-time use, backup-code race, XFF rate-limit bypass, admin-2FA CSRF, reset enumeration

Five distinct fixes across login / 2FA / forgot-password, each with
regression tests:

1. **TOTP codes are now one-time use** (RFC 6238 §5.2). A 6-digit code
   used to stay valid for its whole ±1-step window (~90 s) — anyone
   who saw the victim type it (shoulder-surf, phishing relay) could
   immediately reuse it to open a second session, or to pass the
   2FA-disable check. `totp.MatchingStep` reports the timestep a code
   matched and the server keeps a per-secret high-water mark; a replay
   is treated exactly like a wrong code. Applies to user login 2FA,
   admin login 2FA, and user 2FA disable.

2. **Backup-code double spend under concurrency.**
   `MarkBackupCodeUsed` never reported whether the conditional UPDATE
   actually landed, so two logins racing on the same code could both
   read it as unused and both pass. It now returns a consumed flag and
   `verifyAndConsumeBackupCode` requires it — exactly one racer wins.

3. **X-Forwarded-For no longer defeats per-IP rate limits.**
   `clientIP` trusted the FIRST XFF entry from anyone; a direct client
   could stamp a fresh fake IP per request and walk through every
   per-IP limiter (login, register, forgot-password issue/verify) and
   forge the ip= recorded in audit rows. The header is now ignored
   unless the request arrives from `security.trusted_proxies` (new
   config, single IPs or CIDRs, default empty = never trust), and when
   trusted we take the LAST entry — the one the proxy appended — never
   client-supplied leading entries. Deployments behind nginx/Caddy
   should list the proxy address to keep per-client keying.

4. **/admin/login/2fa POST now CSRF-checked** like its user-side
   counterpart (checked before the attempt counter, so a cross-site
   form can't silently burn the 5-attempt budget and lock the admin
   out of a pending login). Template carries the `_csrf` field.

5. **Forgot-password verify no longer enumerates accounts.** Probing
   `/user/forgot-password/verify` with a made-up code answered
   验证码错误 for unregistered phones but 已过期 for registered ones —
   a registration oracle that never sent an SMS. Both now answer
   已过期, and neither path runs bcrypt so timing is uniform as well.
   Related: `/user/login` now burns a dummy bcrypt comparison on
   unknown phones so response timing doesn't reveal registration
   either.

### Admin UI correctness: logout CSRF, schedule/firewall leak, stale badges, filtered exports

Correctness pass over the admin templates and the handlers that feed
them.

A. (HIGH) Clearing a MAC's schedule — or saving one whose window is
currently open — re-added the MAC to the paid nftables set
unconditionally. A BLOCKED or EXPIRED device regained internet access
until the next resync tick. Both the clear branch and the
immediate-apply path (`applyOneSchedule`) now check eligibility
(status=active AND not expired) first, and the apply path defensively
removes ineligible MACs instead.

B. (MED) `/admin/logout` was a GET link. SameSite=Lax cookies ride
along on top-level cross-site GET navigations and on speculative link
prefetches, so a hostile link — or an eager browser prefetcher walking
the sidebar — could sign the admin out (session fixation setup /
denial of service). Logout is now POST + CSRF; the sidebar renders a
form styled like the old link, and GET bounces to the dashboard with
the session intact.

C. The 最近在线 pill on `/admin/macs/detail` showed 在线 whenever ANY
sighting row existed, even one from weeks ago. It now applies the same
10-minute recency window as `/admin/devices` and shows 离线 otherwise.

D. `/admin/login?err=…` codes from the 2FA flow (`2fa_expired`,
`2fa_locked`, `2fa_misconfigured`) were silently dropped on the GET
render — an expired pending-2FA session bounced the admin to a blank
form with no explanation. They now render as proper messages; unknown
codes are not echoed. `errLabel` also gained real messages for the
plan-validation codes (`bad_key`, `label_too_long`, `days_too_large`,
`price_too_large`) plus `not_found` / `bad_mac` / `db`, which used to
surface as raw code strings.

E. Filters/links: the orders header's 已过滤 badge ignored the
`user_id` filter; the `/admin/macs` attention links dropped the status
filters their dashboard twins carry; `ok=audit_trim` had no flash on
the audit page; order numbers on the user detail page weren't links.

F. The SSE frames on `/admin/devices` were unsorted, so two seconds
after page load the carefully ranked list (online-unknown first, then
online-known, …) reshuffled into DB order. Frames now sort with the
same ranking as the initial render.

G. CSV exports: `orders.csv` / `audit.csv` are named
`*-filtered.csv` when any filter is active, so a partial download
isn't mistaken for the full dataset; the MAC export's in-memory search
post-filter was case-SENSITIVE (`q=office` missed "Office-Printer")
while the page itself uses case-insensitive LIKE — now lowercased on
both sides.

H. Tests: `pages_smoke_test.go` dropped the nonexistent `/admin/2fa`
URL (it vacuously passed by rendering the portal catch-all), gained
filtered-URL variants, and now asserts every admin page actually
renders the admin shell. New regression tests cover the schedule
firewall eligibility, logout semantics, login error surfacing, the
sighting recency pill, and export filenames/case-insensitivity.

### Config strictness, packaging fixes, CI stops trusting itself

Platform pass over config validation, the Docker dev path, the .ipk
packaging, and the CI checks that were quietly green while things were
broken. Extends v0.104's strict `--check-config` — every item below
fails at load time instead of misbehaving at runtime.

A. Config validation holes closed (all previously passed --check-config):

- `security.password_strength` typos (e.g. "strong") silently meant
  lax — a hidden security downgrade. Now only ""/lax/strict validate.
- Empty `api_tokens[].token` entries were silently ignored at runtime
  (operator believes a token exists; every request 401s). Tokens now
  must be ≥16 chars, unique, non-empty; rate_limit_per_min ≥ 0.
- `password_hash` wasn't checked to be bcrypt — pasting a sha256 hex
  (or the plaintext) locked the admin out with no diagnostic. Same for
  non-base32 `totp_secret`: Verify() always false = permanent 2FA
  lockout discovered at the login prompt. Both are validated at load.
- Plaintext admin passwords must be ≥8 chars (bcrypt hashes are
  exempt; `changeme` in the example config remains exactly at the
  floor). Setting both password AND password_hash is now an error, as
  are duplicate admin usernames across admin:/admins[].
- `listen`/`portal_port`/`portal_host` were never validated — a
  missing colon in listen passed --check-config and died at bind.
- Negative durations (scheduler/backup/walled-garden intervals) were
  silently replaced by hardcoded fallbacks deep in each goroutine.
- `firewall.backend` typos passed --check-config, then log.Fatal'd at
  boot. Validation mirrors firewall.NewBackend's accepted names.
- `sms.provider` typos and incomplete aliyun credentials degraded to
  "SMS disabled" with only a log line — password-reset texts just
  never arrived in prod. Now rejected, along with out-of-range
  expiry_reminder_days / admin_digest_hour.
- `webhook.url` must be an absolute http(s) URL and requires a
  secret — unsigned webhooks can't be verified by the receiver, so
  anyone finding the endpoint could forge payment events.
- Walled-garden domain entries that are URLs ("https://x/path") never
  resolve; the resolver retried the bogus lookup forever while
  payment hosts stayed unreachable. Bare domains enforced.
- Security knob ranges (admin_session_hours, user_session_days,
  audit_log_keep, auto_cancel_stale_order_hours, hsts_max_age_seconds)
  are rejected when out of documented range instead of being silently
  clamped to something the operator didn't ask for.

B. Docker dev path was entirely broken and CI was green: the image put
web assets at /app/web while the compose-mounted config.example.yaml
points web_root at /usr/share/router-billing/web — template parsing
fatal'd on boot, so `docker compose up` never worked. Assets moved to
the config's path (matching the .ipk layout). Added a /healthz-based
HEALTHCHECK to the image, and cap_drop ALL + no-new-privileges +
healthcheck to docker-compose (image already ran non-root as `rb`).

C. .ipk packaging: the control file's hardcoded `Version: 0.6` was
shipped in every build — `opkg upgrade` never saw a newer version.
The Makefile now stamps VERSION into the staged control, and
release.yml passes the tag (v0.108 → 0.108) so the binary's
--version, the ipk filename and the control field all agree. Also:
`ipk` added to .PHONY; the old archive is removed before `ar -rc`
(ar UPDATES an existing archive, risking stale member order —
debian-binary must be first for opkg); tar uses --numeric-owner; and
/etc/router-billing/config.yaml ships 0600 instead of world-readable
0644 (it holds admin credentials, pay keys and API tokens).

D. CI false greens: build-arm64 would happily upload an x86-64 binary
if GOARCH regressed (now `file`-checked for aarch64); `make ipk`
exiting 0 said nothing about installability (structure, member order,
control fields, version/filename agreement and config perms are now
verified); and the Docker image was never built at all (new job:
build, assert non-root uid, --check-config in-container, and boot to
a healthy /healthz with all capabilities dropped).

E. `--gen-password-hash` echoed the password to the terminal despite
its "no echo if TTY" comment — it now uses term.ReadPassword on TTYs
(piped stdin still works) and enforces the same 8-char floor as the
config validator.

Tests: config_test.go grows a Load()-based rejection table covering
every new validation rule, acceptance tests for hardened configs and
password_strength case-variants, and a test pinning
config.example.yaml itself as valid so the example can't drift from
strict --check-config even if the workflow step is reshuffled.

## v0.106 — Payment hardening: refund-replay resurrection, amount cross-check, lost grants

Money/security pass over the payment finalize path.

A. (HIGH) Redelivered payment notifications could resurrect refunded
orders. Both WeChat and Alipay redeliver success notifications for up
to ~24h; MarkOrderPaid had no terminal-state guard, so a redelivery
(or a replayed capture) arriving AFTER an admin refund flipped the
order refunded→paid and re-granted the MAC days — the customer kept
the refund AND the access, and the books showed the order paid.
`refunded` is now terminal: the notification is acked (so the PSP
stops retrying) without touching the order or the MAC. The UPDATE is
additionally guarded on the status that was read, so a refund racing
a webhook can't be overwritten either.

B. (HIGH) The PSP-confirmed amount was never checked against the
order — pay.ErrBadAmount existed but nothing used it. PaidNotice now
carries AmountCents (WeChat notify `amount.total`, WeChat query,
Alipay notify/query `total_amount`, parsed without floats) and the
finalizer refuses + audits (`pay_amount_mismatch`) when it doesn't
match the order's amount_cents. Amount-less payloads still finalize
(0 = unknown, not "free").

C. (HIGH, reliability) A failed grant after mark-paid was
unrecoverable: MarkOrderPaid's one transitioned=true signal was
consumed, so PSP retries and the poller both no-oped and the customer
paid for nothing. Now: (1) a firewall-only failure no longer fails the
grant — the DB row is authoritative, an immediate Resync converges the
set, and the paid signal/audit/notify still fire (previously all three
were skipped and the webhook 500'd uselessly); (2) if the DB grant
itself fails, the order is reverted to pending so the next
notify/poll retries the whole finalize; (3) finalize runs under
context.WithoutCancel so a browser disconnect on the /status and
/wait paths can't abort it halfway between "paid" and "granted".

D. WeChat DecodeNotify only accepts event_type=TRANSACTION.SUCCESS —
refund/other events can't be misread as payments.

E. Alipay request `timestamp` is now GMT+8 (北京时间) as the gateway
requires; a UTC router used to send it 8 hours off.

F. order_no entropy bumped from 32 to 64 random bits (31 chars total,
still within WeChat's 32-char out_trade_no cap) — it doubles as the
bearer token for /api/pay/status, /api/pay/wait and /receipt, and the
timestamp prefix is guessable. Old 23-char order numbers keep working
everywhere, including audit-log links.

G. Request-size caps: /api/pay/create body limited to 4KB, /notify/ali
to 64KB (matching /notify/wx).

Regression tests cover the refund-replay resurrection, the amount
mismatch (rejected + audited), finalize idempotency, unknown-amount
acceptance, the Beijing-time timestamp, the event_type filter, and the
new order_no shape.

## v0.105 — Password change / reset now kills other sessions + trusted devices

Changing password from `/user/me` previously left every other
`rb_user` session alive. A stolen cookie stayed logged in after the
victim rotated the password. The change now keeps only the browser
that submitted the form (`DeleteUserSessionsExcept`) and wipes
`user_trusted_devices` so a remembered 2FA skip cannot outlive the
old password.

The same trusted-device wipe now also runs on SMS forgot-password
verify and on admin reset-password (admin already deleted sessions).

## v0.104 — OpenWrt: firewall-billing.sh was a parse error on nftables 1.0.x

Critical ops fix. The nftables filter chain was named `fwd`, which
became a reserved keyword in nftables 1.0.x (OpenWrt 22.03+ / 23.05
ship 1.0.2 / 1.0.8). On those routers the ENTIRE firewall script was
a parse error — and both init.d and the ipk postinst wrapped the
apply call in `|| true`, so the failure was completely silent: no
portal redirect, no drop rule, every Paid_WiFi device online for
free. Reproduced against nftables 1.0.9 (parse error), verified
fixed (parses + rules land).

Also fixed while in there:

- apply is now actually idempotent. Rules declared inside a
  `table { chain { ... } }` block get APPENDED on every apply, so
  each service restart added 7 duplicate rules. Chains are now
  declared empty, flushed, and re-added — verified the rule set is
  identical (4 pre + 3 forward) after repeated applies, and that
  mac_paid set elements survive re-apply (whitelist preserved).
- Legacy `fwd` chain (from installs whose nft still parsed it) is
  deleted on apply so traffic isn't evaluated by two hooks.
- init.d start and ipk postinst no longer swallow apply failures
  silently — still non-fatal, but they log to logread/stderr with
  an explicit "billing rules missing" warning.
- CI: `--check-config config.example.yaml` is now strict (the
  `|| true` is gone). Verified: exits 0 on the example config, 2 on
  parse/validation errors — the example config can no longer drift
  out of validity unnoticed.
- README architecture diagram + firewall.Manager doc comment updated
  to the `forward` chain name. Go code never referenced the chain
  (it only manages the mac_paid set) — no binary behavior change.

## v0.103 — Security: /api/pay/qr open QR encoder closed; 1000x voucher bulk import

(Incorporates the standalone fix/payqr-and-bulk-vouchers branch.)

A. /api/pay/qr took its payload directly from the URL ?payload=...
parameter — fetching the order row only to nil-check it. Anyone
holding any valid order_no could use the endpoint as a free QR
generator serving phishing URLs from our domain. Now the upstream
PSP's QR string is stored on orders.qr_payload at create time and
the handler renders exclusively from the row; the URL parameter is
ignored. Legacy orders without a stored payload get a clean 404.

- schema.sql + migrate.go: orders.qr_payload TEXT NOT NULL DEFAULT ''
- db.SetOrderQRPayload(ctx, orderNo, payload)
- QRPNG URL no longer carries the payload param

B. Voucher bulk import/generate did one implicit transaction (=1
fsync) per row — a 1000-row batch was several seconds even on SSD,
worse on router flash. db.CreateVouchersBulk wraps all inserts in
one transaction with a prepared statement (~1 fsync per import).
UNIQUE collisions fail only their own row (SQLite stmt-level error
semantics), so a duplicate paste mid-import doesn't lose the rest.

7 race-clean tests: URL payload must not be load-bearing (identical
PNG bytes with/without attacker payload), legacy order 404s, bulk
all-success / partial-duplicate / empty / expires_at round-trip.

## v0.102 — render() buffers output; missingkey=zero; all-pages smoke test

render() previously executed templates straight into the
ResponseWriter. When ExecuteTemplate emits some bytes and *then*
errors (e.g. a typo'd struct field halfway through a table — the
exact shape of the v0.96 dashboard bug), the user got HTTP 200 +
half a page + "internal\n" appended, because the implicit
WriteHeader from the first Write beat http.Error's 500. Now the
template renders into a bytes.Buffer first and only a fully
successful render is written; errors produce a clean 500.
(Incorporates the standalone fix/render-buffer-and-missingkey-zero
branch.)

Template option missingkey=zero: naked {{.MissingKey}} on the
map[string]any contexts most handlers pass now renders "" instead
of the literal string "<no value>".

New all-pages smoke test: seeds every table a template ranges over
(MACs active+expired, orders pending+paid, vouchers incl. expired,
sessions, trusted devices, sightings, sms/webhook logs, audit rows
of each actor shape) and renders all 26 admin pages + 6 user/public
pages, asserting 200 and zero "<no value>" occurrences. Combined
with buffered render, any future template↔handler field drift fails
CI instead of silently shipping.

## v0.101 — DB: LIKE wildcard escaping + three missing indexes

Search correctness: every user-facing search (admin MAC/label,
orders, users-by-phone, audit actor/target/detail) built its LIKE
pattern as "%"+q+"%" without escaping — so searching for a literal
"%" matched every row and "a_b" also matched "axb". All six LIKE
sites now escape \ % _ via escapeLike() and declare ESCAPE '\'.
(Injection was never possible — patterns were always bound params —
this is a correctness fix.)

Router-class performance, all served by existing startup migration
(schema.sql reapplies with IF NOT EXISTS on every boot):

- orders(status, paid_at) — the dashboard runs ~13
  "status='paid' AND paid_at >= ..." aggregates per page load;
  previously each one scanned all paid rows.
- sessions(expires_at) — the purge loop deletes by expiry every
  few minutes.
- audit_log(action) — /admin/audit's exact-match action filter and
  the DISTINCT action dropdown; audit_log is the largest table on
  long-running installs.

5 race-clean tests: escapeLike unit table + literal-wildcard
regression coverage on MACs / orders / users / audit searches.

## v0.100 — Fix: redeem/voucher redirects escape user & admin input

Redirect URLs in the voucher paths concatenated raw input:

- POST /redeem echoed the submitted code as-is in the bounce URL —
  `X&ok=1` injected a fake success flag into /redeem, `X#frag`
  truncated the query.
- POST /admin/vouchers/generate embedded the admin-typed batch name
  raw (`a&b c` → parameter injection + invalid space in Location).
- POST /admin/vouchers/batch/revoke for the unbatched bucket
  redirected with a literal `batch=(no batch)` — raw space and
  parens in the Location header.

Everything now goes through url.QueryEscape. The hand-rolled
httpEsc() helper (which skipped non-ASCII, leaving raw Chinese
error text to http.Redirect's implicit escaping) is deleted in
favor of the stdlib. Flash messages decode identically — only the
on-the-wire encoding is stricter.

3 race-clean regression tests asserting the injected params do NOT
appear and values round-trip through url.Parse exactly.

## v0.99 — Security: open redirect at login/2FA, GET-mutable resync, metrics token timing

Three related hardening fixes, each with regression tests:

1. Open redirect at user login. The POST /user/login `next`
   parameter was only checked with HasPrefix(next, "/") —
   "//evil.com" (protocol-relative) and "/\evil.com" (backslash
   normalization) bounced the freshly authenticated user to an
   attacker-chosen external domain. The 2FA login handler
   (/user/login/2fa) trusted its query-string `next` with NO
   validation at all. Both now go through safeNextPath(): single
   leading slash, no second slash/backslash, no CR/LF; anything
   else falls back to /user/me. The login form GET no longer
   echoes a hostile next into the hidden field, and requireUser
   now query-escapes the RequestURI it embeds in ?next= (a
   ?a=b&c=d original URL previously leaked its params out of the
   next value).

2. /admin/resync accepted GET. verifyCSRF only guards POST, and
   the session cookie is SameSite=Lax — so a cross-site
   <img src="/admin/resync"> or top-level navigation triggered a
   firewall rebuild using the admin's ambient cookie. The sidebar
   button already POSTs with a CSRF token; the handler is now
   POST-only (405 otherwise).

3. /metrics compared the bearer token with plain string == —
   remote timing could confirm the token byte-by-byte. Now
   subtle.ConstantTimeCompare, same as the API-token path.

12 race-clean test cases: safeNextPath shape table, hostile-next
login + 2FA integration (Location must stay /user/me), form echo,
resync GET→405 + no audit row + POST-still-works.

## v0.98 — Fix: pay-create no longer leaves orphaned pending orders

Pre-v0.98 `/api/pay/create` inserted the pending order row BEFORE
validating the payment provider. Any request with an unknown
provider ("paypal") or a disabled one (WeChat/Alipay not
configured) got a 400 — but the pending order stayed in the DB,
was polled by the background loop for 30 minutes, and inflated
the admin pending/attention counters. On installs with only one
provider enabled this happened every time a client raced a
config change.

Now the provider is validated first (unknown / disabled → 400,
zero DB writes). Additionally, if the upstream Precreate call
itself fails (WeChat/Alipay 5xx), the just-created pending order
is canceled — the QR code was never shown, so nobody can pay it.

3 race-clean tests: unknown provider leaves 0 orders, disabled
wechat/alipay leave 0 orders, bad-MAC/bad-plan validation
precedence unchanged.

## v0.97 — auditTargetHref recognizes real generated order numbers

Extends v0.92/v0.95's smart-link function. The audit smart-link
only matched order targets with an "ORD"/"ord" prefix — but
`newOrderNo()` actually generates "B" + 14-digit UTC timestamp +
8 hex chars (e.g. B20260825010203deadbeef). Result: every real
production order audit row (order_refunded / order_canceled /
pay) rendered as plain text since v0.92; only hand-crafted test
fixtures ever got linked.

The generated shape is matched strictly (exactly 23 chars,
digit/hex position checks) so ordinary words starting with "B"
never get misrouted. The order_no is also query-escaped in the
generated href now.

Precedence chain stays:
  MAC → order (ORD prefix | generated shape) → phone → user_id

8 race-clean test cases: generated-shape positive, 5 near-miss
negatives (length/charset/prefix), query-escaping, plus a
round-trip test pinning newOrderNo() output to the matcher so
the two can't silently drift apart again.

## v0.96 — Fix: dashboard plan-sales table was silently empty

Pre-v0.96 the /admin/dashboard "最近 30 天按套餐" table referenced
`{{.Count}}` and `{{.Revenue}}` on each row, but the
`db.PlanSales` struct actually exports `OrdersCount` and
`TotalCents`. Go's html/template silently renders `<no value>`
for unknown field references, so the table showed:

  套餐       笔数            营收
  month      <no value>      ¥<no value>

…which has been the dashboard output for months on every install.
Fixed by aligning the template to the actual struct field names.

The bug-discovery vector was deciding to write the v0.94
plan-sales API tests — comparing field names made it obvious the
dashboard had been silently broken. (`admin_macs.html` had it
right all along; only `admin_dashboard.html` was wrong.)

1 race-clean test pinning the post-fix behavior + the
anti-regression "no `<no value>` in the response" assertion so
this can't silently regress again.

## v0.95 — auditTargetHref recognizes user IDs

Extends v0.92's smart-link function. Pure-digit audit targets of
1-9 chars now route to /admin/users/detail?id=N. This covers the
`user_grant` action rows (introduced in v0.29) where target is
the user.ID stringified — clicking once now jumps to the user's
detail page.

Precedence chain stays:
  MAC → ORD prefix → 11-digit-1-prefix (phone) → 1-9 digit (user_id)

10-digit numbers and 11-digit-non-1 numbers stay unlinked
(probably noise; better silent than wrong).

1 race-clean test case added to the shape-coverage table covering
both the user_id positive case ("42", "100000") and the
10-digit/11-digit-non-1 negative cases.

## v0.94 — GET /api/admin/plans/sales

Per-plan paid-revenue + order count over the last N days for ops
dashboards charting "which plan is selling best?"

  GET /api/admin/plans/sales?days=30  Bearer
  -> 200 { plans: [{plan, orders, revenue_cents}, ...], days: 30 }

Reuses db.PlanSalesSince. Sorted DESC by revenue. days defaults
to 30, max 3650. Readonly acceptable.

4 race-clean tests: aggregate correctness on 3-order fixture,
sort by revenue, readonly accepted, POST 405.

## v0.93 — /admin/audit actor cells link to actor-filtered view

Mirror of v0.92's smart target link. Each actor cell in the audit
table becomes a one-click "show me only this actor" link. Date
range filter (since/until) is preserved through the link so
clicking doesn't reset the rest of the filter.

  Before: <td class="mono">admin:bob</td>
  After:  <td class="mono"><a href="/admin/audit?actor=admin:bob">admin:bob</a></td>

Use case: investigating a security alert — "show me everything
admin:bob did between 2026-05-12 and 2026-05-19." Pre-v0.93
required typing the actor into the filter; now click once on
any of bob's audit rows to scope to just bob, then refine.

2 race-clean tests: actor cell IS a link (accepts both `:` and
`%3a` URL-escape variants), since/until are preserved in the
generated href.

## v0.92 — /admin/audit target cells become smart links

Each audit target string is auto-linked based on its shape:

  shape                              → target page
  ─────────────────────────────────────────────────────────────
  AA:BB:CC:DD:EE:FF (any MAC form)   → /admin/macs/detail
  ORD-... / ord-...                  → /admin/orders/detail
  11-digit starts-with-1 (CN mobile) → /admin/sms-log?phone=...
  anything else                      → plain text

New `auditTargetHref(target)` Go func + template func. Completes
the audit-page→detail navigation web after v0.72 actor
autocomplete + v0.86 action-frequency chips.

2 test functions: 7-case shape-coverage table, end-to-end page
render asserting both MAC + order target links appear in HTML.

## v0.91 — /admin/users/detail surfaces MAC notes + cross-links

Completes the "notes everywhere" trio (after v0.88 list inline +
v0.89 order detail). User detail page's MAC table now shows each
device's notes inline so customer context is one-screen.

Each MAC cell also links to /admin/macs/detail (parity with the
order-detail MAC cell). Navigation hub:

  user_detail ──┬─→ mac_detail (per-MAC)
                └─→ order_detail (per-order) ──→ mac_detail

2 race-clean tests: seeded notes + marker on user detail, MAC
cell links to detail page (accepts `:` and `%3a` URL-escape).

## v0.89 — Order detail page surfaces MAC notes

Pairs with v0.88's list-view notes inline. When support drills
into a specific order via /admin/orders/detail, they now also see
the linked MAC's notes inline so customer context is one-screen.

Layout in the "关联 MAC 当前状态" section:

  MAC: AA:BB:CC:DD:EE:FF  (link → MAC detail page)
  标签: phone
  客服备注: 📝 VIP customer - escalate quickly   ← v0.89 row
  状态: [active]
  到期时间: ...

Also turned the MAC string in the table into a link to its detail
page — the order detail and MAC detail pages now cross-link freely
(navigation parity with the user detail page).

The notes row is hidden when the MAC has no notes (silence is the
default).

2 race-clean tests: order with seeded MAC notes shows them, order
with empty-notes MAC hides the row.

## v0.88 — /admin/macs shows notes inline

Makes v0.82's per-MAC notes visible at-a-glance from the list view.
Previously you had to click into /admin/macs/detail to see notes.

  phone
  📝 IPTV box, expected high traffic   (full text via title=)

`text-overflow: ellipsis` at 240px max-width keeps rows compact;
title="..." preserves the full text on hover. No 📝 marker when
notes are empty — silence is the default.

2 race-clean tests: seeded notes appear inline with marker,
no-notes row stays clean (no spurious marker in row chunk).

## v0.87 — POST /api/admin/macs/label (programmatic rename)

Pairs with v0.84's /api/admin/macs/notes — admins can now rename
a MAC via API without touching expiry or any other field. Useful
for bulk-rename automation after a customer-ID migration.

  POST /api/admin/macs/label  Bearer <write-token>
  { "mac": "AA:BB:CC:DD:EE:FF", "label": "office tablet" }
  -> 200 { "status": "ok", "mac": "..." }
  -> 400 / 404

Label trimmed and capped at 64 chars (same as plan label). Input
normalized through models.NormalizeMAC. Audit row marks via=api
and records the new label value for the audit trail.

5 race-clean tests: happy-path persists + audit, 100-char input
truncates to 64, expiry untouched after label change, 404 on
missing mac, 400 on bad mac, readonly token reject.

## v0.86 — /admin/audit action-frequency chip row

Surfaces v0.85's CountAuditActionsByDate output inline at the top
of /admin/audit. Operators get a one-glance histogram of "what's
been happening in the window I'm looking at" — and each chip is a
shortcut that re-applies its action to the filter:

  动作频次（按日期范围过滤后）
  [grant 42] [login 18] [revoke 5] [voucher_batch 3] [refund 1]

Clicking [grant 42] navigates to /admin/audit?action=grant
(preserving the current since/until). Inverse of the v0.72
actor-autocomplete: where that helped you remember the actor
string, this helps you scan the action distribution.

Section hidden when no rows match the current filter (e.g.
future-dated since → no chips).

2 race-clean tests: chips render with a 2-action fixture, future-
since hides the action-specific chip. (No "empty DB" test
because loginAdmin() always writes a login row, so the table is
never truly empty.)

## v0.85 — GET /api/admin/audit/totals

Action-frequency report over a date range. Useful for ops
dashboards charting "grants this week vs last" or compliance
summaries like "Q2: 1234 logins, 567 grants, 89 revokes."

  GET /api/admin/audit/totals?since=YYYY-MM-DD&until=YYYY-MM-DD
       Bearer <any-token>
  -> 200 { "totals": [ {"action": "grant", "count": 42}, ... ],
           "total":  N }

`total` is the pre-summed cross-action count so dashboards don't
have to add. Results sorted DESC by count (then by action name)
so the most-frequent action lands first.

Empty since/until = no bound. Read-only token acceptable.

New DB helper `CountAuditActionsByDate(ctx, since, until)`.

5 race-clean tests: 4-row fixture confirms per-action counts +
sum, future-since yields 0, sort puts popular before rare,
readonly accepted, POST → 405.

## v0.84 — POST /api/admin/macs/notes (programmatic notes write)

Programmatic equivalent of v0.82's UI notes form. Useful for sync
from external CRM / ticketing systems:

  POST /api/admin/macs/notes   Bearer <write-token>
  { "mac": "AA:BB:CC:DD:EE:FF", "notes": "from CRM ticket #1234" }
  -> 200 { "status": "ok", "mac": "..." }
  -> 400 missing/malformed; 404 not found

Critical semantic distinction from the v0.83 import path:
- **import** (POST /api/admin/macs/import): empty `notes` field
  PRESERVES existing notes — anti-footgun on CSV re-upload
- **explicit notes** (this endpoint): empty `notes` CLEARS the
  field — that's how callers wipe a stale annotation

The two endpoints serve different intents — bulk upsert vs
explicit set — so the divergent behavior is intentional. Comment
in the handler explains it for the next reader.

Input normalized through models.NormalizeMAC (dashed / lowercase
forms accepted). Notes auto-truncated to 1000 chars.

Audit row: `mac_notes` target=mac detail="len=N via=api ip=...".

6 race-clean tests: happy-path persist + audit, empty-notes
clears existing, normalize round-trip, 404 missing mac,
400 bad mac, readonly reject.

## v0.83 — MAC import accepts notes (UI + API)

Extends v0.82's per-MAC notes to the bulk-import paths so ops
can pre-populate context at upload time.

UI (/admin/macs/import textarea):
  AA:BB:CC:DD:EE:01,30,phone,customer's IPTV box
  AA:BB:CC:DD:EE:02,30,tablet            ← no notes column = empty

API (POST /api/admin/macs/import):
  { "macs": [
      {"mac":"AA:BB:CC:DD:EE:01","days":30,"label":"phone",
       "notes":"customer's IPTV box"},
      ...
    ] }

Anti-footgun semantics on the API path: omitting the notes field
(or sending empty string) on a re-import does NOT clear existing
notes. Operators who DO want to clear must use the v0.82
/admin/macs/notes UI form with an empty textarea — that path is
explicit. The import path being silent-noop on empty notes
prevents accidental loss on CSV re-uploads.

Notes field auto-truncates to 1000 chars consistent with the
v0.82 cap. Failures to write notes log to stderr but don't
bump the import's `failed` counter — the MAC itself succeeded.

3 race-clean tests: UI 4th-column persists, API notes field
persists + bare-row leaves empty notes, anti-footgun on
re-import without notes preserves pre-existing content.

## v0.82 — Per-MAC notes (free-text support context)

Adds a `notes` text column to the macs table. `label` was always
"short identifier" (printed on the MAC list); for support context
like "customer's IPTV box — expected high traffic" or "shared
device, used by family" the operator needs a longer field.

Schema: new `macs.notes TEXT NOT NULL DEFAULT ''` migrated via
addColumnIfMissing — zero-impact for existing rows.

UI:
- /admin/macs/detail (v0.48) gains a "备注" textarea + save button
- POST /admin/macs/notes — saves trimmed text capped at 1000 chars
- Flash "备注已保存 ✓" on success

API exposure: the existing `mac` field in API responses now
includes `notes` (since the field is on the model). No new
endpoint — caller can use POST /api/admin/macs/grant with label
for short or use the UI for the longer free-text.

Audit row: `mac_notes` target=mac detail="len=N ip=...". The
content is not logged (would balloon the audit table on the
common "paste a paragraph" workflow).

4 race-clean tests: save persists + audits, 2000-char input
is truncated to 1000 server-side, detail page renders the
textarea pre-filled with saved content, malformed MAC →
err=bad_mac.

## v0.81 — GET /api/admin/version (minimal status snapshot)

Tiny endpoint for status-page widgets polling every few seconds.
Faster than /api/admin/health (which runs `DB.Stats()` + Attention
queries every call) since /version is a pure in-memory read.

  GET /api/admin/version   Bearer <any-token>
  -> 200 { "version": "v0.81", "uptime_seconds": 12345,
           "wechat_enabled": true, "alipay_enabled": true }

Read-only token acceptable. Payload deliberately minimal — no
mac_total / user_count / revenue / db_path. Anti-noise red-line
test enforces that posture.

4 race-clean tests: snapshot echoes version + uptime, readonly
accepted, POST → 405, payload is minimal (no operational
detail leaked).

## v0.80 — CSV export for sms_log + webhook_deliveries (milestone)

Closes the last gap in the observability story. After v0.43 (DB
table), v0.49 (webhook table), v0.44/v0.50 (API), v0.68/v0.69
(UI filters), and v0.79 (date range), the observability tables
now also have CSV export — same filter knobs as the on-screen
view.

  GET /admin/export/sms-log.csv?phone=&only_failed=&since=&until=
  GET /admin/export/webhook-log.csv?event_type=&mac=&only_failed=&since=&until=

Default limit 1000, max 10000. Filename follows the established
v0.41/v0.66/v0.67 pattern:

  no filter → `sms-log.csv` / `webhook-log.csv`
  any filter → `sms-log-filtered.csv` / `webhook-log-filtered.csv`

UI: "导出 CSV" button next to "立即裁剪" on each log page; link
carries the current filter set through end-to-end.

6 race-clean tests: each export returns valid CSV with header +
row, webhook event_type filter excludes non-matches, filename
flavor switches with filter presence, both pages render the
export button.

## v0.79 — SMS/Webhook log: since/until date range filters

Closes the last filter gap on the observability pages. Previously
the persistent log views (sms_log, webhook_deliveries) could be
narrowed by phone / event_type / MAC / only_failed but NOT by
date. Forensic workflows like "show me last Tuesday's webhook
failures" required scrolling.

UI:
  GET /admin/sms-log?since=2026-05-12&until=2026-05-19
  GET /admin/webhook-log?since=2026-05-12&until=2026-05-19

API:
  GET /api/admin/sms/log?since=YYYY-MM-DD&until=YYYY-MM-DD
  GET /api/admin/webhook/log?since=YYYY-MM-DD&until=YYYY-MM-DD

`Since` is inclusive of the day's start; `Until` is inclusive of
the day's end (`< start_of_day(until + 1 day)` in the WHERE so
00:00–23:59:59 of the until date all appear). Matches v0.16's
order-date-range semantics.

DB: SMSLogFilter / WebhookDeliveryFilter gained Since + Until
fields; zero strings = no bound. Existing callers unchanged.

UI: date inputs on both filter forms; reset includes them in
the "any filter active" check.

4 race-clean tests: SMSLogs since-filter excludes future-since
rows, WebhookDeliveries until-in-past excludes everything, both
admin pages render the new date inputs.

## v0.78 — GET /api/admin/macs/get (programmatic v0.48)

Programmatic equivalent of v0.48's MAC detail page. Returns the
MAC row + owner (auth-material stripped) + current sighting +
last 50 orders + audit timeline. Single endpoint = single round
trip for "give me everything about MAC X" support automation.

  GET /api/admin/macs/get?mac=AA:BB:...   Bearer <any-token>
  -> 200 { "mac": {...}, "owner": {...}|null,
           "sighting": {...}|null,
           "orders": [...], "audit": [...] }
  -> 400 if mac missing or malformed
  -> 404 if mac not found

Input normalized through models.NormalizeMAC so dashed / lower-
case forms resolve to the canonical row.

Owner is a deliberate subset (id, phone, suspended, totp_enabled,
created_at) — no password_hash / totp_secret / totp_pending.
Anti-leak red-line test pins this with the secrets-as-literals
search pattern used by v0.47/v0.65.

6 race-clean tests including the normalization round-trip, the
400 / 404 branches, and the anti-leak check.

## v0.77 — GET /api/admin/sessions

Programmatic mirror of /admin/sessions. Useful for monitoring:
"alert if admin sessions > expected" or trend user concurrent-
session counts.

  GET /api/admin/sessions?kind=admin|user   Bearer <any-token>
  -> 200 { "sessions": [ {kind, subject, user_id, expires_at}, ...
         ], "count": N }

Critical: response NEVER includes the session token. Leaking it
would effectively hand the holder full auth. Anti-leak test pins
this red line so a refactor can't accidentally widen the response.

kind filter is exact ("admin" / "user" / empty). Anything else
→ 400.

5 race-clean tests including the token anti-leak red-line, kind
filter, bad-kind 400, readonly accepted.

## v0.76 — /admin/devices links known MACs to detail page

Small navigation polish. The /admin/devices online-devices table
now turns each MAC into a link to the v0.48 detail page when the
MAC is "Known" (exists in the macs table).

Unknown MACs — devices currently online but never authorized —
stay plain text. Clicking those would 404-redirect, which would
just confuse the operator.

The MAC column display + the hostname subline are otherwise
unchanged.

1 race-clean test: fixture with a known MAC + recent sighting
confirms the detail link is rendered (accepts both raw `:` and
`%3a` URL-escape forms).

## v0.75 — GET /api/admin/audit/distinct?field=actor|action

Programmatic equivalent of v0.72's actor datalist (and the
pre-existing action dropdown source). Useful for ops dashboards
that build their own audit-search UI.

  GET /api/admin/audit/distinct?field=actor    Bearer <any-token>
  -> 200 { "values": ["admin:alice", "admin:bob", ...] }

  GET /api/admin/audit/distinct?field=action
  -> 200 { "values": ["grant", "login", "revoke", ...] }

`field` is required and must be exactly "actor" or "action".
Anything else returns 400 — narrow allowlist by design so we
don't accidentally expose `detail` (which can contain sensitive
text like SMS messages or IPs).

5 race-clean tests: actor returns sorted unique over a 3-actor
fixture, action de-duplicates a duplicated grant row, bad/missing
field both 400, readonly token accepted.

## v0.74 — GET /api/admin/sightings

Programmatic access to the device_sightings table. Ops automation
can now inventory who's currently on the network without scraping
/admin/devices.

  GET /api/admin/sightings?since_hours=24   Bearer <any-token>
  -> 200 { "sightings": [...], "count": N }

since_hours defaults to 24, max 720 (30 days). Read-only token
acceptable — payload is detection metadata only (no auth material).

Common pattern: drift-detection cron compares
`/api/admin/sightings` against `/api/admin/macs?status=active`
and alerts on "MACs paid but never seen" or "MACs seen but
never paid."

4 race-clean tests: 24h window excludes >24h-old rows, wider
window includes them, readonly accepted, POST → 405.

## v0.73 — MAC detail page: last-seen sighting

Adds a "最近在线" row to /admin/macs/detail (v0.48) populated from
the device_sightings table. Support workflow: customer says
"my phone isn't connecting" — admin can immediately see whether
the device has been detected by ARP / dnsmasq recently, and what
IP it grabbed.

  最近在线: [在线] 2026-05-19 13:42 · 192.168.5.42 · roommate-phone
  首次发现: 2026-05-12 09:30

When no sighting exists (device never connected to the paid SSID),
the row shows "无网络探测记录" so it's clear the detector hasn't
seen the MAC at all (vs simply offline at this moment).

New `db.GetSightingForMAC(ctx, mac)` — single-row lookup;
returns (nil, nil) on no row to distinguish "missing" from
"error."

3 race-clean tests: full info renders with seeded sighting,
the no-sighting hint appears when row absent, DB-level missing
returns nil.

## v0.72 — /admin/audit actor autocomplete (datalist)

The actor filter input previously required typing the exact actor
string (e.g. `user:13800138000` vs `admin:bob` vs `system`).
Adding a `<datalist>` autocomplete sourced from the distinct
audit_log.actor values means operators get type-ahead suggestions
without remembering the exact prefix.

New `db.DistinctAuditActors(ctx) ([]string, error)` — sorted
SELECT DISTINCT, capped at 500 (each registered user can appear
as their own actor on busy installs).

UI: actor input now carries `list="audit-actors"` + a `<datalist>`
populated with all known actors. The browser handles the
suggestion popup natively (no JS needed).

2 race-clean tests: DistinctAuditActors returns unique + sorted
over a 4-row 3-actor fixture, /admin/audit page embeds the
datalist with the seeded actor.

## v0.71 — Order detail page: webhook deliveries section

Pairs with v0.70's user-detail SMS history. Order detail page
(/admin/orders/detail) now also shows the last 20 webhook
deliveries that fired for THIS order's MAC. Support workflow:
"the customer says they paid but their account on our downstream
system still shows unpaid — did the webhook fire?"

The section renders:
- event_type code, attempt count, HTTP code, OK/FAIL pill,
  duration_ms — same layout as /admin/webhook-log
- error_msg surfaces as a hover tooltip on FAIL rows
- "查看全部 →" link jumps to /admin/webhook-log?mac=<the MAC>
  (v0.69 UI filter) for >20 rows

Section is hidden when no webhook deliveries exist for the MAC
(no empty card noise on early-life deploys).

2 race-clean tests: 2-row fixture with one OK + one FAIL +
unrelated row, confirming OK/FAIL rendering with tooltip, the
filtered link (URL-escape variants accepted), AND that an
unrelated MAC's row doesn't leak in. Plus the hide-when-empty
case.

## v0.70 — User detail page: SMS history section

Milestone release. Support workflow: customer calls about "I
never got my verification code" — admin opens
/admin/users/detail and now sees the user's SMS history inline
without hopping to /admin/sms-log.

Last 30 sms_log rows targeting the user's phone, rendered as
a table with the OK / FAIL pill (consistent with the main
sms-log page). FAIL rows expose the underlying error_msg via
`title=""` attribute so hovering shows the upstream provider
error.

Link "查看全部 →" jumps to `/admin/sms-log?phone=<user.Phone>`
(the v0.68 UI filter) for cases where the most-recent 30 aren't
enough.

Section is hidden when the user has no SMS history (no empty
card noise on first-day deploys).

2 race-clean tests: 2-row fixture shows OK + FAIL pills + error
tooltip + the filtered-log link, and the section is hidden on
clean DB.

## v0.69 — Webhook log: event_type + MAC filters

Closes the filter gap on the third observability page. After
v0.45 (SMS log filters) and v0.68 (UI phone filter), the
webhook delivery viewer now also accepts narrowing filters for
the common "show me everything we tried to send about this
specific order/MAC" workflow.

  GET /admin/webhook-log?event_type=order_paid&mac=AA:...&only_failed=1
  GET /api/admin/webhook/log?event_type=order_paid&mac=AA:...&only_failed=1

DB layer: new `WebhookDeliveryFilter` struct with EventType/MAC/
OnlyFailed/Limit; `RecentWebhookDeliveries(limit, onlyFailed)` is
now a thin shortcut over `SearchWebhookDeliveries(filter)` so v0.49
and v0.50 callers keep working unchanged.

UI: inline form on /admin/webhook-log with two text inputs +
the existing only_failed checkbox; reset link clears all three.
The "仅显示失败" toggle link in the page header is replaced by
the same checkbox in the filter form.

5 race-clean tests covering EventType + MAC isolation, the
EventType+OnlyFailed compose case, page filter form rendering,
and an end-to-end filter round-trip on the page itself.

## v0.68 — /admin/sms-log: phone + only_failed UI filters

UI counterpart to v0.45's API filters. The DB-backed sms_log table
on /admin/sms-log was previously a "last 100 rows, no filter"
list — useful for casual checking but painful for support
workflows like "show me everything we tried to send this
customer."

  GET /admin/sms-log?phone=13800...&only_failed=1

Inline form on the persistent-records section: text input for
phone substring, checkbox for only_failed, 筛选 + 重置 buttons.

Reuses v0.45's `db.SearchSMSLogs(SMSLogFilter)` — no new DB
surface. The form's URL is bookmark-friendly so support agents
can save a customer-specific filter.

3 race-clean tests: phone filter isolates matching rows + excludes
others, only_failed filter excludes OK rows, page renders both
filter controls.

## v0.67 — /admin/export/macs.csv 支持 q/status/user_id 过滤

Closes the last gap in the "CSV export matches the on-screen
filter" trio. After v0.33 (orders), v0.41 (vouchers), and v0.66
(users), the MAC CSV export now also accepts the same filters
as the /admin/macs page.

  GET /admin/export/macs.csv?q=AB:CD&status=active&user_id=42

Routes through the v0.40 indexed-by-user-id path when user_id is
set; falls back to SearchMACs for q/status; defaults to ListMACs
when no filter.

`/admin/macs` page's export link now passes through q + status
filters; button label switches to "导出筛选 MAC" when active.

Filename pattern matches v0.41/v0.66:
- no filter   → `macs.csv`
- any filter  → `macs-filtered.csv`

5 race-clean tests covering each filter (status, user_id, q), the
filename flavor switch, and the page link round-trip.

## v0.66 — /admin/export/users.csv 支持 q/suspended/totp 过滤

Pre-v0.66 the users CSV export returned every registered account
regardless of what the user was looking at on /admin/users.
With v0.57's API filters already supporting q/suspended/totp,
the CSV export was the last surface where ops had to dump
everything and post-filter in Excel.

  GET /admin/export/users.csv?q=138&suspended=0&totp=0

Filters compose. Phone substring via SearchUsers, suspended/totp
post-filter in Go (same logic as v0.57).

`/admin/users` page's export link now embeds the current `q`
filter and switches the button label to "导出筛选结果" when a
filter is active.

Content-Disposition filename:
- no filter   → `users.csv`
- any filter  → `users-filtered.csv`

So a downloaded export is self-describing — match the v0.41
voucher-export filename pattern.

4 race-clean tests: q filter excludes non-matches, suspended=1
filter isolates suspended rows, filename flavor switches with
filter presence, /admin/users page embeds q in the export link.

## v0.65 — POST /api/admin/users/suspend

Programmatic equivalent of v0.5's /admin/users/suspend UI button.
Anti-abuse automation can lock an account on a fraud signal
without an admin clicking through.

  POST /api/admin/users/suspend  Bearer <write-token>
  { "user_id": 42, "suspend": true }
  -> 200 { "status": "ok", "user_id": 42, "suspended": true }
  -> 400 / 404

Suspended users keep their existing MAC time but can't log in
(sessions die immediately, future logins are denied).

The API endpoint mirrors UI semantics including the session
eviction — without it, a currently-logged-in abusive user
would keep the cookie and the suspend would do nothing until
the cookie expired.

Audit rows: `user_suspend` (or `user_unsuspend`) target=user_id
detail="via=api ip=...". Distinct action verbs so dashboards
can show the time-series of locks and unlocks separately.

5 race-clean tests: flip on + off with DB confirmation + both
audit rows, suspend evicts existing sessions, missing user 404,
readonly reject, audit row marks via=api.

## v0.64 — POST /api/admin/users/notify-expiry

Programmatic admin toggle for the per-user expiry-reminder opt-out.
Useful for support workflows ("this customer asked us to stop
texting them") and bulk re-enable scripts after a deliverability
issue.

  POST /api/admin/users/notify-expiry  Bearer <write-token>
  { "user_id": 42, "on": true }
  -> 200 { "status": "ok", "user_id": 42, "notify_expiry": true }
  -> 400 if user_id missing
  -> 404 if user not found

Reuses `db.SetUserNotifyExpiry` from the existing /user/me self-
service toggle. Audit row: `user_notify_pref` target=user_id
detail="on=Y via=api ip=...".

4 race-clean tests: flip off → DB reflects, flip back on, missing
user → 404, missing user_id → 400, readonly token → 403, audit row
carries via=api + on= value.

## v0.63 — GET /api/admin/backup

Programmatic DB backup download for off-router backup automation.
Companion to the v0.13-era /admin/backup UI link.

  GET /api/admin/backup   Bearer <any-token>
  -> 200 application/x-sqlite3, Content-Disposition attachment

Pattern: nightly `curl` cron from a backup VM:

  curl -O -J -H "Authorization: Bearer $RB_TOKEN" \
       https://router-billing.local/api/admin/backup
  # → billing-20260519-031507.db

WAL checkpoint runs before the byte copy so the file is
self-consistent (no in-flight writes in the -wal sidecar).

Read-only token IS accepted: the DB file contains the operator's
own data, and any read token can already exfil user lists via
/api/admin/users. So the backup endpoint isn't a wider surface
than the existing /api/admin/users read scope.

Refactor: the WAL-checkpoint + stream body now lives in a shared
`streamBackup(actor, ip)` helper used by both UI (handleAdminBackup)
and API paths. Audit row has `via=api` vs `via=ui` based on actor
prefix.

4 race-clean tests: response starts with the SQLite magic header
("SQLite format 3\x00"), audit row marks via=api with size=,
readonly token accepted, POST → 405.

## v0.62 — GET /api/admin/dashboard (programmatic snapshot)

Programmatic equivalent of /admin/dashboard's roll-up panels.
Returns the same DashboardSnapshot + Attention counters in one
JSON payload so ops scripts can chart trends without scraping
HTML.

  GET /api/admin/dashboard   Bearer <any-token>
  -> 200 {
       "snapshot": {
         today_revenue_cents, today_paid_orders, today_new_users,
         today_new_macs, week7_revenue_cents, week7_paid_orders,
         month30_revenue_cents, month30_paid_orders,
         month30_new_users, prev_month30_revenue_cents,
         prev_month30_paid_orders, prev_month30_new_users,
         active_sessions
       },
       "attention": {
         expiring_soon, stale_pending, suspended_users,
         failed_today, sms_failures_24h, webhook_failures_24h
       }
     }

prev_month30_* fields (from v0.28's MoM logic) let callers compute
their own MoM deltas without re-running the math.

Read-only token acceptable — payload is aggregate stats only, no
user-identifying data leaks.

4 race-clean tests: payload shape (all 13 snapshot keys + 6
attention keys), seeded-data round-trip (today revenue + SMS
failure counter), readonly accepted, POST → 405.

## v0.61 — /admin/health expose attention counters

Adds `attention` block to both /admin/health and /api/admin/health
responses so monitoring scripts can alert on the dashboard's
attention metrics without parsing HTML.

  GET /api/admin/health
  -> 200 { ...legacy fields...,
           "attention": {
             "expiring_soon":        3,
             "stale_pending":        0,
             "suspended_users":      1,
             "failed_today":         0,
             "sms_failures_24h":     2,
             "webhook_failures_24h": 0
           } }

Common alert recipes:
- `attention.sms_failures_24h > 5` → pager
- `attention.stale_pending > 50` → run cancel-stale
- `attention.expiring_soon > 100` → expedite reminder campaign
- `attention.suspended_users == 0` → all good

Reuses the existing `db.Attention()` query (cheap single batch)
so the endpoint stays sub-millisecond.

Pre-v0.61 fields are unchanged (anti-regression test pins all 11
legacy keys so existing scripts don't break).

2 race-clean tests: attention block populated when fixtures hit
each category, legacy fields all still present in the response.

## v0.60 — Config-driven auto-cancel stale orders

Saves operators from wiring cron for v0.55's bulk cancel. Set
the new config knob and purgeLoop will run the sweep on its
existing 2-hour cadence:

  security:
    auto_cancel_stale_order_hours: 24    # 0 (default) = disabled

Same atomic semantics as the v0.52/v0.55 cancel paths
(UPDATE WHERE status='pending'). Hours clamped [1, 720].

Audit hygiene: the no-op case (zero rows flipped) does NOT
write an audit row — otherwise an enabled background sweep would
generate `count=0` noise every 2 hours. When the sweep IS
productive, the row reads:

  system | orders_cancel_stale | count=N hours=H via=purge_loop

so reviewers can tell the periodic sweep from one-off UI clicks
(via=ui) or API automation (via=api).

Default stays 0 (disabled) — existing deploys keep their
behavior. Operators who want hands-off pending-backlog hygiene
opt in.

3 race-clean tests: clamp function pinned over 6 edge cases,
sweep-flips-and-audits integration check, and a guard test
that a no-op sweep doesn't audit.

## v0.59 — Dashboard: 过去 24 小时投递失败 panel

New attention panel on /admin/dashboard surfacing recent SMS +
webhook delivery failures. Operators previously had to navigate
to /admin/sms-log or /admin/webhook-log to find these — now they
see the count at a glance with one-click drill-down links to the
respective log pages (the webhook link auto-filters to
`?only_failed=1`).

  过去 24 小时投递失败
    3 条 SMS 发送失败     → /admin/sms-log
    7 次 Webhook 投递失败 → /admin/webhook-log?only_failed=1

The panel is hidden when both counters are zero.

`AttentionCounts` grew two new fields — `SMSFailures24h` and
`WebhookFailures24h` — backed by `success=0 AND sent_at >=
datetime('now','-1 day')` queries. The 24h window is rolling
(not midnight-based) so a failure at 18:00 yesterday still
appears at 17:00 today.

Deliberate non-change: these counters are NOT added to
`Attention.Total()` (which drives the navbar red dot). That
indicator stays focused on user-facing issues; observability
gets its own visually-distinct (red border) attention panel.

4 race-clean tests: panel renders with seeded failure rows,
panel hidden when only success rows exist, 24h window excludes
2-day-old failures, Total() excludes the new counters.

## v0.58 — 侧边栏关注事项徽章 (sidebar attention badges)

The admin /admin/dashboard "需要关注" panel was the only place
ops saw the four-counter Attention() roll-up (expiring MACs,
stale-pending orders, suspended users, failed-today orders).
Now those counts also render as small amber chips next to the
corresponding sidebar entries, so an admin notices "3 expiring
MACs" without first navigating to the dashboard.

  侧边栏:
  ┌────────────────────────┐
  │ MAC 管理      [3] ◄── 即将过期 (≤7 天)
  │ 用户          [1] ◄── 已停用账户
  │ 订单          [5] ◄── 滞留 pending + 今日 failed
  └────────────────────────┘

Implemented in `adminCtx()` — every admin template now gets
`SidebarBadge_Macs / _Users / _Orders` keys (zero values
suppress the chip via `{{if .SidebarBadge_X}}`).

Re-uses the existing `db.Attention()` query (cheap, single
batched round-trip) so the badge add-on is a no-op for any
admin page render. Failure to compute attention silently
drops the badges rather than 500-ing.

CSS: `.sidebar-badge` — amber chip, right-aligned within the
nav row, brightens slightly on hover.

2 race-clean tests: badges appear when fixtures hit each
attention category (expiring MAC + stale pending + suspended
user) AND badges are absent on a clean DB.

## v0.57 — /api/admin/users filter by suspended + totp

Pre-v0.57 the user-list endpoint had only `q` (phone substring).
Adding `suspended` + `totp` filters unlocks two common reports:

  GET /api/admin/users?suspended=1
    → who's locked out?
  GET /api/admin/users?suspended=0&totp=0
    → active users to nudge into enabling 2FA
  GET /api/admin/users?q=138&suspended=0
    → active users in a phone-prefix range (for SMS campaigns)

Filters compose. `?suspended=0&totp=0` is the "non-2FA active
user" set most ops eventually want.

Post-filter in Go (the row count is bounded by `limit`, max 500,
so the in-memory pass is fine). No new SQL surface required.

Response shape gains a `count` field alongside `users` so
clients can detect "did we hit the limit?" without iterating.
Legacy no-param callers still get the `users` array unchanged.

4 race-clean tests: suspended filter both directions, TOTP
filter both directions, suspended+totp compose, and a
backward-compatibility check that the no-filter path keeps
working.

## v0.56 — UI "清理过期订单" button on /admin/orders

UI counterpart to v0.55's bulk-cancel API. One-click "kill all
the abandoned-checkout backlog older than 24h" affordance for
ops who haven't set up cron.

  POST /admin/orders/cancel-stale  {hours=24}
  -> /admin/orders?ok=cancel_stale&count=N&hours=24

Button lives in the orders page toolbar next to the CSV export
link. Confirm dialog spells out the threshold. `hours` form
field is clamped to [1, 720] server-side so a fat-finger
"99999" gracefully becomes 720 instead of 500-erroring.

Reuses `db.CancelStalePendingOrders` from v0.55. Audit row
carries `via=ui` so reviewers can tell UI clicks from automation.

The flash banner echoes count + hours so the operator gets
instant feedback ("已批量取消 12 条超过 24h 的 pending 订单").

4 race-clean tests covering: happy path (mixed-age fixture,
only stale flips, audit via=ui), hours clamp on oversize input,
GET redirects without firing, and the page renders the form.

## v0.55 — POST /api/admin/orders/cancel-stale (bulk cleanup)

Companion to v0.52's single-order cancel. Designed for hourly
cron use to keep the pending backlog small. Customer abandons
checkout → order sits at pending forever → /admin/orders gets
noisier every day.

  POST /api/admin/orders/cancel-stale   Bearer <write-token>
  { "older_than_hours": 24 }    // optional, default 24
  -> 200 { "canceled": N }

Empty body is also fine — cron can POST nothing and rely on the
24h default.

Bounds: older_than_hours in [1, 720] (1h .. 30d). 0 / unset → 24.
Single atomic UPDATE so a payment arriving mid-sweep can't lose:
the `status = 'pending'` guard in the WHERE makes the race
correct either way (we transition pending → failed, payment
handler transitions pending → paid; only one wins per row).

New DB helper `CancelStalePendingOrders(ctx, olderThan)`.

Audit: `orders_cancel_stale` detail="count=N hours=H via=api ip=...".

5 race-clean tests: 4-row mixed-age fixture confirms only the
>cutoff pending rows flip (paid + fresh untouched), default 24h
case, oversize-hours 400, readonly token reject, empty-body OK.

## v0.54 — Audit 详情关键字搜索 (q=…)

The existing `actor` / `action` / `target` filters covered the
columns but not the `detail` column where most context lives
("ip=...", "via=api", "phone=...", "err=..."). Adding a `q`
substring filter on detail makes the audit page actually
searchable for free-text incident review.

  GET /admin/audit?q=via=api          ← only API-origin actions
  GET /admin/audit?q=ip=10.0.0        ← only entries from this IP
  GET /admin/audit?q=upstream timeout ← only SMS retry failures
  GET /api/admin/audit?q=...&action=grant

Composes with the other filters (action=grant AND q=upstream
timeout returns the grants whose detail mentions that text).

Wired end-to-end:
- New `Q string` field on `db.AuditFilter` (LIKE %s%)
- /admin/audit page input "详情关键字"
- /api/admin/audit accepts `?q=`
- CSV export link in the audit page passes the q through

4 race-clean tests: DB-level Q on a 3-row fixture, Q+action
compose case, /api/admin/audit?q= round-trip, /admin/audit page
renders the input.

## v0.53 — UI 取消按钮（v0.52 的 UI 对应）

Inline "取消" button on each pending row in /admin/orders. Same
atomic semantics as v0.52's API endpoint — UPDATE WHERE
status='pending' so a race that just paid the order can't lose
the payment.

  POST /admin/orders/cancel  {order_no}
  -> /admin/orders?ok=canceled
     ?err=not_pending  (race: order just left pending)
     ?err=not_found    (bad order_no)
     ?err=missing_order (no order_no in form)

Reuses `db.CancelPendingOrder` from v0.52 so the behavior can't
drift between UI and API paths. Confirm dialog spells out "此操作
会将状态置为 failed，且不可逆转" to avoid fat-finger disasters.

Audit row: `order_canceled` target=order_no detail="via=ui ip=..."
(distinct via=ui marker so reviewers can tell UI clicks from
API automation).

5 race-clean tests: happy path with DB state + audit assertion,
already-paid case redirects with err=not_pending and leaves
status unchanged, missing-order err=not_found redirect, GET
redirect (don't fire), orders list renders the form only for
pending rows.

## v0.52 — POST /api/admin/orders/cancel

Cleanup automation for stuck pending orders: customer abandoned
the payment flow, gateway never reported back, the order sits in
`pending` forever (until /admin/orders shows a noisy backlog).

  POST /api/admin/orders/cancel   Bearer <write-token>
  { "order_no": "ORD-..." }
  -> 200 { "status": "canceled", "order_no": "..." }
  -> 404 if order_no missing
  -> 409 if order isn't pending (already paid / failed / refunded)

Transitions `pending → failed` atomically via UPDATE WHERE
status='pending', so a race that just paid the order can't lose
the payment. The order moves to `failed` not a new "canceled"
status — keeps the schema vocabulary stable.

New DB helper `CancelPendingOrder(ctx, orderNo) (*Order, error)`
returns sql.ErrNoRows for missing, fmt error for wrong-status,
and the post-transition order on success.

Audit row: `order_canceled` target=order_no detail="via=api ip=...".

6 race-clean tests: happy path + audit row, 404, 409 on paid,
400 on missing order_no, readonly token reject, and a DB-level
idempotence-style test that the second cancel call errors.

## v0.51 — 立即裁剪 sms_log / webhook_deliveries 按钮

Round out the v0.35 + v0.39 trim-now button family with the two
v0.43/v0.49 observability tables. Operators who just lowered
security.audit_log_keep can now reflect it across all three
logs without waiting up to 2 hours for the next purgeLoop tick.

  POST /admin/maintenance/sms-log-trim
  POST /admin/maintenance/webhook-log-trim

Buttons appear inline on /admin/sms-log and /admin/webhook-log
respectively (with confirm dialogs). Each writes its own audit
row (`sms_log_trim` / `webhook_log_trim`) so the trim history
is visible alongside the data it trimmed.

GET on both endpoints redirects (not fires) to match the v0.35
pattern of guarding against browser-preload accidents.

5 race-clean tests: 12-row fixture trimmed to cap, audit rows
land for each, GET → redirect, both pages render the form.

## v0.50 — GET /api/admin/webhook/log

Milestone release. Programmatic access to the v0.49 webhook_deliveries
table, paired with v0.44's /api/admin/sms/log so monitoring scripts
now have JSON endpoints for every persistent observability log
(audit, sms, webhook).

  GET /api/admin/webhook/log?limit=N&only_failed=1   Bearer <any-token>
  -> 200 { "logs": [ {id, sent_at, event_type, mac, attempt,
                     status_code, success, duration_ms, error_msg},
                    ... ], "count": N }

Common monitoring pattern: cron polls `?only_failed=1&limit=20`;
alerts when any row's `sent_at` is within the last 5 minutes —
webhook is presently broken and ops needs to investigate.

Same posture as the v0.44 sms log API: read-only token acceptable
since the payload is the operator's own delivery state, not auth
material. limit defaults to 100, max 1000. Newest first.

5 race-clean tests covering happy-path (newest-first ordering),
only_failed isolation, limit enforcement, readonly token, and
POST→405.

## v0.49 — 持久化 Webhook 投递日志

Companion to v0.43's sms_log: persistent observability for the
notify.Notifier. Pre-v0.49 a webhook failure left a single stderr
line that vanished on log rotation — operators had to grep
journalctl to answer "did this event ever reach the downstream?"

New `webhook_deliveries` table records one row per attempt
(initial + each retry):

  id, sent_at, event_type, mac, attempt, status_code,
  success, duration_ms, error_msg

Wire-up:
- `notify.Notifier.OnDelivery` callback (new field) fires after
  each HTTP attempt with (ev, attempt, statusCode, durationMs, err).
- App.NewApp wires it to a `db.LogWebhookDelivery` writer using
  context.Background() so the row lands even if the retry
  happens after the original request returned.
- `deliver()` calls the callback on both success AND failure
  paths so the row reflects reality regardless of outcome.

New /admin/webhook-log page:
- Last 200 attempts newest-first
- "仅显示失败" toggle (`?only_failed=1`) for monitor follow-up
- HTTP status code + duration_ms columns so ops can spot slow
  upstream
- New sidebar entry "Webhook"

purgeLoop trims `webhook_deliveries` on the same `security.audit_log_keep`
cap as audit_log and sms_log.

6 race-clean tests:
- Real-server delivery → 200 + success row recorded
- 500-responding server → success=false row with error_msg
- only_failed filter isolates FAIL rows
- PurgeWebhookDeliveries trims to cap
- /admin/webhook-log page renders rendered rows
- only_failed=1 URL filter excludes OK rows

## v0.48 — /admin/macs/detail?mac=… (MAC timeline)

Companion to v0.42's order-detail page. Customer says "my phone
isn't online" and reads off their MAC; admin pastes it into the
URL, sees the full history in one page.

  GET /admin/macs/detail?mac=AA:BB:CC:DD:EE:FF

Renders:
- Basic info: current status, expiry, label, updated_at
- Owner link (if any) → /admin/users/detail?id=N
- Last 50 orders that paid for this MAC (each row links to the
  order-detail page from v0.42, so admins can drill further)
- Audit timeline targeting this MAC up to 200 rows
  (`grant`/`revoke`/`replace` etc.)

Input is normalized through models.NormalizeMAC so dashed /
lowercase / colon forms all resolve to the canonical row. Bad MAC
strings redirect to `/admin/macs?err=bad_mac`; missing rows go to
`?err=not_found`.

/admin/macs list now turns the MAC cell into a link to the detail
page so the workflow is `click → see full history`.

5 race-clean tests:
- Full-render check: MAC + label + owner phone + order link +
  audit row content all present
- Input normalization: lowercase dashed input finds the canonical
  MAC and renders it back in colon form
- Missing MAC → 303 with ?err=not_found
- Malformed MAC → 303 with ?err=bad_mac
- Macs list cell links to detail (accepts both raw `:` and
  html/template's `%3a` URL-escape variants)

## v0.47 — GET /api/admin/orders/get (programmatic v0.42)

Programmatic equivalent of v0.42's UI detail page. Returns the
order row, current linked MAC state (or null if deleted), and
the audit timeline targeting this order_no. Useful for support
automation: given an order_no from a customer ticket, build a
unified view without scraping the admin HTML.

  GET /api/admin/orders/get?order_no=ORD-...   Bearer <any-token>
  -> 200 { "order": {...}, "mac": {...}|null, "audit": [...] }
  -> 404 if order_no not found
  -> 400 if order_no missing

Read-only token acceptable — payload contains only the order's
already-stored fields plus public audit text. No auth material
slips through (anti-leak test covers password_hash/totp_secret).

5 race-clean tests:
- Happy path with seeded audit row + MAC link
- 404 on missing order
- 400 on missing order_no param
- Readonly token accepted (GET)
- MAC-deleted-after-order case returns mac=null + order + audit
- Anti-leak: response carries no password_hash / totp_secret

## v0.46 — POST /api/admin/maintenance/optimize-now

API mirror of v0.39's UI button. Completes the three-button
"manual maintenance trigger" API set (alongside v0.38's
expire-now + audit-trim).

  POST /api/admin/maintenance/optimize-now   Bearer <write-token>
  -> 200 { "ms": N }

Same posture as the UI handler: runs `PRAGMA optimize` (SQLite's
recommended lightweight reanalysis), sub-second on every
realistic router-billing DB size. VACUUM is intentionally NOT
exposed — it can hold a write lock for minutes.

Audit: `optimize_now` detail="ms=N via=api ip=...".

3 race-clean tests: POST + ms + audit assertion, readonly-token
reject, GET → 405.

## v0.45 — /api/admin/sms/log filters

v0.44 returned the last N rows undiscriminately. v0.45 adds two
filters that make the endpoint actually useful for monitoring +
support workflows:

  GET /api/admin/sms/log?phone=13800...&only_failed=1

- `phone=N`        exact match (support: "show me everything we
                   tried to send this customer")
- `only_failed=1`  success=0 rows only (monitoring: "alert when
                   the failure rate spikes")

Filters compose — `?phone=13800...&only_failed=1` returns FAIL
rows for that phone only, which is exactly the support follow-up
after a monitor fires.

DB layer: `SearchSMSLogs(SMSLogFilter)` with optional Phone +
OnlyFailed; the v0.43 `RecentSMSLogs(limit)` is now a thin
shortcut over it so v0.44 callers keep working.

3 race-clean tests covering each filter alone + the compose case.

## v0.44 — GET /api/admin/sms/log

Programmatic access to the v0.43 sms_log table. Useful for monitoring
scripts that want to alert on a streak of FAIL rows (e.g. Aliyun
creds rotated and ops forgot to update them) without scraping the
admin HTML.

  GET /api/admin/sms/log?limit=N   Bearer <any-token>
  -> 200 { "logs": [ {id, sent_at, provider, phone, message,
                     success, error_msg}, ... ], "count": N }

limit defaults to 100, capped at 1000. Newest rows first. Readable
by any token (read or write); the message contents are already in
the DB so the read scope matches the existing /api/admin/audit
endpoint's posture.

Common pattern: a cron polling `?limit=50` and counting `success=false`
rows fires an alert when the failure rate spikes. Pairs nicely with
the existing `/api/admin/health` for "is the system breathing?" plus
"is SMS delivery actually working?"

5 race-clean tests: 3-row fixture confirms newest-first ordering,
limit=5 cap enforced, readonly token accepted, POST returns 405,
FAIL rows include error_msg.

## v0.43 — DB-backed SMS log (sms_log table)

Pre-v0.43, SMS delivery state was either:
- in-memory ring buffer (Console provider only, lost on restart)
- stderr log lines (Aliyun)

Neither survived restarts AND neither worked for the Aliyun customer
case "ops, why didn't this phone get the expiry reminder yesterday?"
— operators had to dig through journalctl. With a sustained-traffic
deploy that's hours of log spelunking.

New `sms_log` table, populated by every `App.SendSMS` call
regardless of provider:

  id, sent_at, provider, phone, message, success, error_msg

Schema migrates via the existing `CREATE TABLE IF NOT EXISTS`
pattern (no addColumnIfMissing needed — it's a new table).

All 7 `a.SMS.Send(...)` call sites rewritten through the new
`a.SendSMS(...)` wrapper which calls the provider AND logs the
outcome (success or failure with error_msg) in one place. Future
SMS providers automatically get logged without per-callsite
changes.

`/admin/sms-log` page renders a new "持久化发送记录" section
showing the last 100 DB rows with provider, status pill (OK/FAIL),
and the original message — survives restarts. Console ring buffer
stays alive too for fast iteration during local development.

purgeLoop trims `sms_log` to `security.audit_log_keep` rows on the
same 2-hour schedule as audit_log.

5 race-clean tests: success path records row, failure path records
row with error_msg captured, RecentSMSLogs orders newest-first,
PurgeSMSLog respects the keep cap, /admin/sms-log page renders the
new DB section.

## v0.42 — /admin/orders/detail?order_no=… (timeline view)

Support workflow: customer emails about a specific order, support
agent pastes the order_no into the URL, sees the full timeline in
one page — instead of grep-ing the audit table separately.

  GET /admin/orders/detail?order_no=ORD-...

The page renders:
- The order row (number, plan, amount, payment method, trade_no,
  user link, MAC, paid_at)
- Current MAC state (or a warning banner if the MAC was deleted
  post-order — audit still rendered so the history is intact)
- Audit timeline targeting this order_no (covers `order_paid`,
  `order_refunded`, `manual_note`, etc.), up to 200 rows
- Inline refund button (only for `paid` orders) with the same
  confirmation flow as the orders list

The `/admin/orders` list now turns the order_no cell into a link
to the detail page so the workflow is `click → see history`.

5 race-clean tests:
- Full-render check with 2 seeded audit rows
- Missing order_no param → redirect to /admin/orders
- Bad order_no → /admin/orders?err=not_found
- Order whose MAC has been deleted → warning banner + page still
  renders the order info + timeline
- Orders list links to detail via the order_no cell

## v0.41 — Voucher CSV export filter by status

  GET /admin/vouchers/export.csv?batch=...&status=unused|redeemed|revoked|expired

For accounting workflows like "give me only the redeemed ones from
this batch so I can reconcile the revenue", or "give me the unused
ones to reprint as a promo".

Filter happens in Go on the result of ListVouchers (capped at 1000
rows already), so the in-memory pass is fine — no new SQL surface
needed. The Content-Disposition filename embeds the status when
filtered (`vouchers-batch-unused-20260519-093015.csv`) so the
download is self-describing.

No-status legacy callers still get every row in the batch.

6 race-clean tests:
- 4-row fixture (one per status) confirms each filter returns
  exactly its row + excludes the other 3
- No-status request returns everything
- Filename includes the status when filtered

## v0.40 — /api/admin/macs filter + limit params

Pre-v0.40, `GET /api/admin/macs` returned every MAC row unfiltered.
On a long-running install that's 10k+ rows shipped over the wire on
every poll — way too much for monitoring loops on slow links. Now
the endpoint accepts:

  GET /api/admin/macs?q=AA:BB&status=active&user_id=42&limit=100

- `q`       — substring on mac/label (via existing SearchMACs)
- `status`  — active|expired|blocked (exact match)
- `user_id` — int; only MACs owned by that user
- `limit`   — int, default 200, cap 1000

The unfiltered path is also capped now (200 default) so a forgetful
caller doesn't get the 10k-row response by accident.

When `user_id` is set the query routes through the indexed
ListMACsForUser path; q/status are post-filtered in Go since the
row count is bounded by one user's devices (typically << 100).
Without user_id, q/status go through the existing indexed
SearchMACs.

Response now also includes `count` alongside `macs` so clients can
detect "did we hit the limit?" without iterating.

5 race-clean tests covering each filter in isolation, the
user_id+status compose case, the limit enforcement, and the bad-
user_id 400.

## v0.39 — /admin/maintenance/optimize-now (PRAGMA optimize)

Third button in the "手动触发后台任务" card (after v0.35's
expire-now and audit-trim). Runs SQLite's recommended-lightweight
`PRAGMA optimize` immediately. purgeLoop runs it weekly; this
button is for "I just did a big data migration and want plans
re-analyzed now."

  POST /admin/maintenance/optimize-now
    -> /admin/maintenance?ok=optimize_now&ms=N

VACUUM is **deliberately** not bundled in. VACUUM can hold a write
lock for minutes on a busy DB and isn't safe to fire from a UI
button; the docstring tells operators to run `sqlite3 ... "VACUUM"`
manually during a known-quiet window if they need disk reclaim.
PRAGMA optimize itself is sub-second on every realistic
router-billing DB size.

Audit: `optimize_now` target="" detail="ms=N ip=..." so reviewers
see how long it took.

3 race-clean tests: POST runs + audit assertion, GET-redirects-
without-firing, page-render confirms the form is present.

## v0.38 — API mirrors of v0.35 maintenance triggers

For deploy scripts that just rolled a config change and want
the new behavior live NOW — no need to SSH and click the button.

  POST /api/admin/maintenance/expire-now   Bearer <write>
    Runs ExpireDueMACs + MACSvc.Resync.
    -> 200 { "expired": N }

  POST /api/admin/maintenance/audit-trim   Bearer <write>
    Runs PurgeAuditLog(security.audit_log_keep).
    -> 200 { "kept": N }

Both reject GET (405) so an accidental browser preload of the URL
can't fire the sweep. Both write audit rows with `via=api` so
reviewers see the source attribution.

Useful patterns:
- CI deploy hook: POST /api/admin/maintenance/expire-now after
  pushing a plan change so the firewall reflects new expiry
  windows before the first user re-connects.
- Config-cap-lowered automation: POST /api/admin/maintenance/audit-trim
  immediately after editing security.audit_log_keep down.

5 race-clean tests including happy paths with audit-row assertions,
readonly-token reject (both endpoints), and 405-on-GET coverage.

## v0.37 — POST /api/admin/audit/note

Programmatic counterpart to the UI's manual-note form (v0.24).
Useful for webhook handlers or external automation that want to
leave a trace in audit_log without inventing a new logging surface.

  POST /api/admin/audit/note   Bearer <write-token>
  { "note":   "Refund issued via gateway dashboard",
    "action": "manual_note",      // optional, default "manual_note"
    "target": "ORD-12345" }       // optional
  -> 200 { "status": "ok" }

Constraints (matched to the UI handler):
- empty note → 400 (defense against a deploy script writing
  whitespace rows to the table)
- note auto-truncated to 1000 chars
- target capped at 200 chars
- action: free-form but validated through planKeyOK
  ([A-Za-z0-9_-]{1,32}) so the audit search box can find rows.
  "manual_note" passes through unchanged.

Common patterns this unlocks:
- Deploy script: `action="deploy", target="prod", note="v1.2.3 rolled out"`
- Webhook handler: `action="manual_note", target=order_no, note="external refund"`
- Config-reload bot: `action="config_reload", note="diff hash xyz"`

Each entry ends with `via=api ip=...` so reviewers can distinguish
API-origin notes from UI clicks.

6 race-clean tests: happy-path with detail/via=api assertion,
custom-action shape (deploy/prod), empty-note 400, slash-in-action
400 with field=action hint, 2000-char note truncation, readonly-
token reject.

## v0.36 — POST /api/admin/webhook/test

Programmatic equivalent of the /admin/maintenance/test-webhook
button (v0.20). Useful for CI / deploy-time integration checks:
"after the new release rolls out, confirm our webhook handler still
receives events."

  POST /api/admin/webhook/test   Bearer <write-token>
  -> 200 { "status": "enqueued", "url": "https://..." }
  -> 503 if webhook isn't configured

Delivery is async — a 200 means the event hit the Notifier queue,
not that the downstream service received it. The caller confirms
receipt on their side (or watches the audit log for retry/drop).

Audit: `webhook_test` with `via=api ip=...` so reviewers can tell
UI test clicks from automation integration tests.

Refactor: the `type=test` event body is now produced by a shared
`notifyTestEvent(actor, ip)` helper used by both the UI and the API
handler — so the payload shape can't drift between the two paths.

4 race-clean tests: real-server delivery confirmation (httptest
upstream verifies the event lands), 503 when unconfigured,
readonly-token reject, and audit-row via=api assertion.

## v0.35 — 手动触发后台维护任务

Two buttons on /admin/maintenance that immediately fire what the
background purgeLoop runs every 2 hours. Useful when ops just
changed config and wants the new behaviour live NOW rather than
after the next tick.

  POST /admin/maintenance/expire-now
    -> Runs ExpireDueMACs + MACSvc.Resync.
    -> /admin/maintenance?ok=expire_now&expired=N

  POST /admin/maintenance/audit-trim
    -> Runs PurgeAuditLog(security.audit_log_keep).
    -> /admin/audit?ok=audit_trim

Both write their own audit row (`expire_now` / `audit_trim`) so
the trail shows the manual intervention. GET requests to the trigger
URLs redirect back rather than firing the action, so a browser
preload can't accidentally trigger a sweep.

UI: new "手动触发后台任务" section on /admin/maintenance with
both buttons + a confirm-dialog. The expiry button shows the
expired-row count in the flash so operators get instant feedback.

4 race-clean tests:
- expire_now flips an actually-due MAC + writes the audit row
- audit_trim respects security.audit_log_keep + writes its own row
- GET requests to both endpoints redirect (don't fire)
- /admin/maintenance page render includes both forms

## v0.34 — POST /api/admin/users/grant-by-phone

Convenience sibling to v0.29's `/api/admin/users/grant`: takes the
phone number a support agent typed off a call instead of requiring
a pre-resolved user_id.

  POST /api/admin/users/grant-by-phone   Bearer <write-token>
  { "phone": "13800120001", "days": 7, "label": "support-extend" }
  -> 200 { "user_id": 42, "phone": "13800120001",
           "macs_extended": 3, "macs": [...] }

Phone is validated through models.ValidPhone BEFORE the lookup so
a typo'd input surfaces as a clean 400 instead of an ambiguous
"user not found". Existing phone → 200 with the user's resolved
user_id echoed for the caller's records. Real phone format / no
account → 404.

Audit shape mirrors v0.29 but appends `phone=<phone>` so a reviewer
searching by phone (the support ticket field) can find the row.

6 race-clean tests: happy path with audit assertion, invalid phone
400, valid phone no-account 404, readonly-write reject, zero-days
400, and the standard response-body anti-leak check.

## v0.33 — Orders 按 user_id 筛选 + 导出

Support workflow: "show me every order this customer ever placed
→ CSV → forward to refund team." Previously you had to click into
the user's detail page (which only listed up to 50). The orders
search now accepts `?user_id=N` end-to-end:

  GET /admin/orders?user_id=42
  GET /admin/export/orders.csv?user_id=42

The filter composes with the existing q/status/since/until params
so you can scope further ("paid orders from user 42 in May 2026").
Orders with NULL user_id (anonymous voucher redeems, legacy data)
are EXCLUDED from the user_id-filtered view by design.

DB layer: new `UserID int64` field on OrderFilter; the query adds
`AND user_id = ?` only when UserID > 0 so the filter stays
backwards-compatible (zero value = no filter).

UI: a small `<input name="user_id" type="number">` in the existing
toolbar form; the CSV-export link carries the user_id through;
the "清除" reset button now also resets the user_id field.

2 race-clean tests:
- DB-layer: 4-order fixture (2 for u1, 1 for u2, 1 with NULL
  user_id) confirms UserID=u1.ID returns exactly the 2 expected,
  UserID=u2.ID exactly the 1, UserID=0 leaves the filter off.
- UI-level: page-render check that user_id=999999 matches nothing
  AND that orphan orders (NULL user_id) don't leak into the
  user-filtered view, AND that the export link carries the
  param.

## v0.32 — API 套餐 CRUD

Completes the API surface for plans. Mirrors the /admin/plans UI:

  GET  /api/admin/plans                Bearer <any-token>
                                       -> 200 { plans: [...] }
  POST /api/admin/plans/save           Bearer <write-token>
                                       -> 200 { status: "ok" }
  POST /api/admin/plans/delete         Bearer <write-token>
                                       -> 200 { status: "ok" }

LIST merges DB-overlay plans on top of config-defined fallbacks
(same logic activePlans() uses for the UI). Read-only tokens are
accepted.

SAVE shares the v0.31 validation: planKeyOK + label≤64 + days≤3650
+ price_cents≤10_000_000. Each rejection includes a `field` hint
in the JSON so the caller can highlight the offending input:

  400 { "error": "bad key (must match ...)", "field": "key" }
  400 { "error": "days too large (max 3650)", "field": "days" }
  ...

DELETE is a noop on missing key when the DB has nothing to remove
(matches UI semantics — the config-defined fallback would
re-surface).

Audit shape matches UI plan_save / plan_delete, with `via=api`
appended so reviewers see source attribution.

9 race-clean tests including a 4-case table-driven validation
test asserting the `field` hint is exactly the offending field,
plus the now-standard readonly-write-rejection pair (save + delete).

## v0.31 — 套餐保存严格校验

Server-side validation on /admin/plans/save catches the typo where
an operator types "30000" instead of "30 days" or "1000000" instead
of "1000" (=¥10). Without these bounds the saved plan immediately
ships to /buy and could trigger an absurd customer charge or a
1000-year expiry date.

New rejections (each redirect with a distinct ?err=<reason>):
- `bad_key`         — plan_key must match `[A-Za-z0-9_-]{1,32}`
                      (used in /buy?plan=<key>, audit targets, DB PK).
- `label_too_long`  — label > 64 chars
- `days_too_large`  — days > 3650 (10 years, sanity cap)
- `price_too_large` — price_cents > 10_000_000 (¥100,000)

Lower-bound rejections (key empty / days≤0 / price≤0) keep their
existing `err=invalid_days` flash for backwards compatibility.

6 race-clean tests:
- TestPlanKeyOK — 15-case table-driven pin on every accept/reject
  edge of the key validator (empty, oversize, non-ASCII, slash,
  dot, semicolon, plus, etc.)
- One test per rejection branch (bad_key, days_too_large,
  price_too_large, label_too_long) confirming the redirect AND
  the DB is unchanged.
- One happy-path test confirming a valid plan does land.

## v0.30 — 公开 /health 端点（无 auth）

For load balancers, uptime monitors (UptimeRobot, Pingdom, k8s
readiness probes), and anyone that just wants "is the service
alive" without needing a token.

  GET /health
  GET /healthz    (k8s convention alias)

  200 OK   { "status": "ok", "version": "...", "uptime_seconds": N }
  503      { "status": "degraded", "error": "db ping: ..." }

The DB ping is a `SELECT 1` with a 2-second deadline so a wedged
sqlite returns 503 promptly rather than hanging the monitor.

Distinct from the three existing health-ish endpoints:
- `/admin/health`     — cookie-gated, full operational stats
- `/api/admin/health` — Bearer-gated, same payload
- `/metrics`          — Bearer-gated, Prometheus exposition

`/health` stays MINIMAL on purpose — no row counts, no revenue,
no provider names, no firewall state. Those reveal operational
detail that shouldn't be on the open internet.

4 tests including the anti-leak red-line that the public response
never contains `mac_total`, `revenue_cents`, `wechat_enabled`,
`firewall`, etc. — the same screen we put on every other
public-facing endpoint.

## v0.29 — POST /api/admin/users/grant (按 user 批量续期)

For support workflows where the customer is identified by their
account ID, not by a specific device MAC. The existing
`/api/admin/macs/grant` requires you to know the device; this one
fans out across every MAC the user owns.

  POST /api/admin/users/grant   Bearer <write-token>
  { "user_id": 42, "days": 7, "label": "support-extend" }
  -> 200 { "user_id": 42, "macs_extended": 3,
           "macs": [ {"mac": "...", "expires_at": "..."}, ... ] }

Behavior:
- A user with **zero MACs** is NOT an error — returns 200 with
  `macs_extended: 0`. Useful for partner integrations that
  don't track per-device state.
- A nonexistent user_id returns 404 (so support can spot a
  typo immediately rather than silently succeeding).
- Per-MAC errors (firewall sync hiccup, etc.) log but don't
  fail the whole batch. The `macs` response array is the set
  that actually got extended.

Audit trail:
- One `grant` row per MAC (matching UI / per-MAC API shape)
- One `user_grant` summary row at the top with `macs=N`
  so reviewers don't have to grep N timestamps to reconstruct
  the batch.

6 race-clean tests including the zero-MAC happy case, the 404,
the readonly-token reject, both 400 branches (zero user_id / zero
days), AND the now-standard anti-leak red-line that the response
never contains password_hash / totp_secret / session_token.

## v0.28 — Dashboard 月环比 (MoM delta) 标签

/admin/dashboard now shows month-over-month deltas next to each
30-day stat. The comparison window is `[-60d, -30d)` vs the current
`[-30d, now)` — the boundary `datetime('now','-30 days')` is shared
between both queries so no row is counted twice.

The chip is a tiny coloured pill rendered by a reusable
`{{template "momPill" .X}}` snippet:
- ↑ 12% (green)  — growing
- ↓ 8%  (red)    — shrinking
- → 0%  (grey)   — unchanged but with real previous-period data
- NEW  (blue)    — current > 0 but prev = 0 (no percentage)
- ↓ -100% (red)  — prev > 0 but curr = 0 ("gone")

The math lives in `momDelta(curr, prev) momDeltaInfo` (server pkg)
so the rounding is testable independently from the template — half-
away-from-zero so 14.7% → 15% and -14.7% → -15% (Go's integer
division floors toward zero by default which would give the wrong
sign on negative remainders).

Three new DB columns on DashboardSnapshot (PrevMonth30RevenueCents,
PrevMonth30PaidOrders, PrevMonth30NewUsers); each backed by one
extra SQL query in the existing batched round-trip.

CSS: `.mom-pill` + `.mom-up` / `.mom-down` / `.mom-flat` / `.mom-new`
in style.css — chip-shaped, inline, 11px, sits next to the label.

10 race-clean unit-test cases on the momDelta function (zero/zero,
new-from-zero, complete-dropoff, unchanged, both rounding edges,
etc.) + an integration check that /admin/dashboard never leaks the
`<no value>` template-key-miss footprint.

## v0.27 — API 充值码生成 + 批量作废

Completes the API write-surface for vouchers. Partners with the
write-token can now:

  POST /api/admin/vouchers/generate   Bearer <write-token>
  { "count": 100, "days": 30, "batch": "promo-2026Q2",
    "label": "summer-promo", "expires_days": 180 }
  -> 200 { "batch": "promo-2026Q2", "created": 100,
           "codes": ["AB12-CD34-EF56", ...] }

  POST /api/admin/vouchers/batch/revoke   Bearer <write-token>
  { "batch": "promo-2026Q2" }
  -> 200 { "revoked": 42 }

The generate endpoint returns plaintext codes (4-4-4 dashed
form) because the partner *needs* the plaintext to print or
sell them — this matches the existing UI generator. The list
endpoint (`GET /api/admin/vouchers`) still masks codes to a
4-char prefix; only the freshly-minted ones are returned in
plaintext, and only to the writer who just created them.

Generate limits: count clamped to [1,1000]; days must be
positive; expires_days optional (omitted = no expiry); batch
defaults to a `B<timestamp>` label same as the UI.

Batch-revoke is the API mirror of v0.26's UI button —
RevokeVoucherBatch underneath, already-redeemed rows untouched,
empty-string batch revokes the unbatched bucket.

Audit:
- generate: `voucher_batch` target=<batch> detail="count=N days=D via=api"
- batch revoke: `voucher_batch_revoke` target=<batch> detail="count=N via=api"

Matches the UI handlers' audit shape so reviewers see one
consistent trail regardless of origin.

8 race-clean tests covering happy path, default batch name,
oversize-count reject, zero-days reject, readonly-token reject
(both endpoints), unbatched-bucket semantics, audit-row
assertion, AND an anti-leak check that the response body
never contains password_hash / totp_secret / session_token.

## v0.26 — 批量作废充值码

When a partner deal falls through, killing 500 vouchers one-by-one
isn't realistic. Add a one-click "作废 N" button next to each batch
in the /admin/vouchers stats table.

  POST /admin/vouchers/batch/revoke   {batch}
  -> /admin/vouchers?ok=batch_revoke&revoked=N&batch=...

DB-level `RevokeVoucherBatch(ctx, batch) (int, error)` returns
the count of rows that newly flipped to revoked (excludes
already-redeemed AND already-revoked — `revoked = 0` in the
WHERE means no double-flip side effect, the returned count is
exactly the rows that changed).

Already-redeemed rows are intentionally left alone. Flipping
those would lie about real usage — `redeemed_at` is the source
of truth for "this code paid for service".

Empty-string batch maps to the "(no batch)" bucket consistent
with VoucherBatchStats, so unbatched vouchers can also be killed.
The handler swaps the display sentinel before the DB query so
the UI/URL roundtrip stays clean.

Audit: `voucher_batch_revoke` target=<batch> detail="count=N ip=...".

5 race-clean tests covering DB-mixed-state, unbatched bucket, full
e2e POST flow with audit-row assertion, CSRF rejection, and the
UI form rendering check.

## v0.25 — API 批量发放 (JSON 流量入口)

`/admin/macs/import` (textarea, v0.4) is great for ops typing
into a browser. For partner automation (corporate WiFi VPN
gateway issuing 200 MACs at once when an employee joins) you want
JSON in / JSON out.

  POST /api/admin/macs/import   Bearer <write-token>
  { "default_days": 90,
    "macs": [
      {"mac": "AA:BB:CC:00:00:01", "days": 30, "label": "phone"},
      {"mac": "aa-bb-cc-00-00-02",                "label": "tv"},
      {"mac": "AA:BB:CC:00:00:03"}
    ] }
  -> 200 { "added": 3, "failed": 0 }

Rules:
- Each row's `days` falls back to `default_days`, which itself
  defaults to 30 if absent.
- Invalid MACs (anything `models.NormalizeMAC` can't parse)
  bump the failed counter — the rest of the batch still runs.
- Empty `macs` list → 400.
- More than 1000 rows → 400 (same per-call cap as the UI path).
- Readonly tokens → 403.
- Each successful grant audits `action=grant` with
  `detail="days=N via=api ip=..."`, matching the UI handler's
  trail so reviewers don't see two flavors of grant rows.

6 race-clean tests including the >1000-row reject and the
default_days propagation regression.

## v0.24 — 充值码导入 + API 退款 + 审计可观测性

Four operational additions covering admin tooling + API completeness.

### `/admin/vouchers/import` — CSV import of pre-existing codes

For deployers migrating from another voucher system or printing
codes offline. The existing `/admin/vouchers/generate` creates
random codes; this one accepts what you give it.

  POST /admin/vouchers/import  bulk=<csv>

Each line: `code,days[,label[,batch[,expires_at_RFC3339]]]`.
Blank lines + `# ...` comments skipped. Codes go through
`voucher.Canon` (uppercase, strip dashes/spaces). days defaults to
30. Codes < 6 chars are rejected. Duplicate codes hit UNIQUE
constraint and bump the failed counter. Each successful insert
audits as `voucher_imported`.

UI: collapsed `<details>` 导入已有充值码 section under 批量生成.
Flash shows added=N · failed=M counts.

5 tests including Canon-normalization regression guard.

### `POST /api/admin/orders/refund` — programmatic refund (write)

Pairs with the v0.15 admin-UI refund button. Useful for chargeback
automation tied to webhook handlers on the gateway side.

  POST /api/admin/orders/refund  Bearer <write-token>
  { "order_no": "...", "reason": "..." }
  -> 200 { "status": "refunded", "mac": {...post-rollback MAC...} }

Same atomic DB transition (`MarkOrderRefunded`). Audit detail
gets `via=api` so reviewers can tell the source. Error mapping:
400 missing order_no, 403 readonly token, 404 missing order, 409
order not paid.

6 tests including the readonly-token regression guard.

### `/admin/audit` usage indicator (`全表 N / cap`)

The janitor purges audit_log above `security.audit_log_keep` (cap
default 10000). Admins running long-lived deploys want to know
when they're approaching the cap so they can bump it before
interesting history gets evicted.

UI: a small "全表 N / 10000" suffix in the audit page crumbs. Past
80% the percentage flips red. Backed by new `DB.CountAudit`
(cheap COUNT(*)).

### `/admin/audit` 手动添加备注 — free-text audit entry

For out-of-band actions where there's no specific handler:
"refund issued via Aliyun console directly", "customer called
confirming lost phone". A collapsed `<details>` form posts to
`/admin/audit/note` which writes `action=manual_note` with the
admin's username attribution + IP.

Rejects empty / whitespace-only. Caps text at 1000 chars (truncates
rather than 4xx-ing on long input).

4 tests including the attribution + truncation cases.

### Stats
- 17 packages tested
- 385 test functions (was 370 in v0.23)

## v0.23 — 每日运营日报短信

Adds a daily-summary SMS to the configured admin phone — completes
the proactive-SMS surface alongside expiry reminders + login
alerts.

### `sms.admin_digest_hour` — opt-in daily digest

```yaml
sms:
  admin_digest_hour: 9                   # 1..24 UTC; 0 = off
  admin_login_alert_phone: "13800138000" # reused from v0.17
```

Once per day at the configured UTC hour, the background loop fires
a fire-and-forget SMS to the admin phone with:

  【router-billing 日报】昨日营收 ¥X.YZ（N 单）· 未来 3 天 M 个 MAC 到期 · 今日 K 单失败

Sections after 营收 only appear when their count is non-zero so the
SMS stays compact on quiet days.

Skips silently when any of: digest_hour=0, no SMS provider, empty/
invalid admin_login_alert_phone — same defensive pattern as the
expiry-reminder loop.

### `/admin/sms-log` 立即发送日报 button

Manual trigger of the same code path — useful to verify the
digest content + provider reachability without waiting for the
daily cron. Errors map to specific flash codes:
sms_disabled / digest_no_phone / sms_failed.

### DB helper `AdminDigestStats`

Four count queries via QueryRowContext — yesterday's revenue +
paid orders, today's failed orders, MACs expiring within 3 days.
Uses the `start of day` datetime pattern the rest of the time-
window code adopted in v0.16 (modernc.org/sqlite quirk avoidance).

### Tests
- AdminDigestStats aggregation (seeded yesterday/two-days-ago/
  today/expiring-tomorrow rows; assert each field).
- sendAdminDigest end-to-end (Console captures the body, audit row
  written).
- formatAdminDigestBody pure-function (4 body shapes including
  ¥0.50 cent-padding).
- Loop short-circuits when digest_hour=0.
- Loop short-circuits when SMS provider missing.
- /admin/sms-log/digest button: success path, no-SMS error,
  no-phone error.

### Stats
- 17 packages tested
- 370 test functions (was 362 in v0.22)

## v0.22 — 用户偏好 + 30 天面板 + 严格密码策略

Three additive bits — small but each enables a real customer
workflow.

### 用户级 SMS 到期提醒 opt-out

v0.17 shipped the auto-reminder loop with no way to turn it off.
Some users want it off (privacy, signal issues, auto-renewal
elsewhere). New `users.notify_expiry` column (default 1) +
checkbox on `/user/me` 通知偏好 card. Schema migration is
additive via `addColumnIfMissing`. The
`ListExpiringMACsWithoutRecentReminder` query gains an EXISTS
clause that joins on `users.notify_expiry = 1`, so opted-out
users drop out of the candidate set entirely. Toggle audited as
`notify_expiry_on` / `notify_expiry_off`.

5 tests including the SMS-loop-skips-opted-out regression guard.

### `/admin/dashboard` 最近 30 天 panel

The dashboard had today + 7 days + cumulative but no month-window.
Admins doing monthly bookkeeping had to dig into /admin/orders?
since=... Now there's a 最近 30 天 panel with 30 天营收 +
30 天新增用户 tiles between 最近 7 天 and 累计.

DashboardSnapshot gains Month30RevenueCents / Month30PaidOrders /
Month30NewUsers. Same single-round-trip helper pattern.

2 tests covering page render + the 30-day window math.

### Strict password policy (opt-in)

```yaml
security:
  password_strength: strict   # default "" / "lax"
```

`ValidPasswordStrong` is the new strict checker:
- Length 6..72 (same).
- Long passphrases (10+ chars) bypass — passphrase users
  shouldn't be forced to add a digit.
- Short passwords (6-9 chars): letter+digit required AND must not
  be in a small 18-item commons dictionary
  (`123456`, `password`, `qwerty`, etc.).

`a.passwordValidatorFor()` helper picks the right function from
the config. Three call sites updated: register, password change,
forgot-password reset. Default = lax preserves the v0.0 behavior
so no existing deployment / test breaks.

9 tests total across the models + server packages.

### Stats
- 17 packages tested
- 362 test functions (was 348 in v0.21)

## v0.21 — 审计 CSV 导出 + README 刷新

Small but useful: rounds out the v0.18 reporting story.

### `/admin/export/audit.csv`

Completes the CSV-export trio (users + orders + audit). Accepts
the same filter params as `/admin/audit` (actor / action / target /
since / until / limit) so admins can dump exactly the slice they
just filtered to.

Default limit 1000 (vs the HTML page's 300) — CSV exports feed
compliance dumps where higher row counts matter. Capped at 10000
so a single request can't OOM the router on a 1M-row audit table.

UI: 导出 CSV button on `/admin/audit` carries the current filter
query so "filter then export" is one click.

3 tests covering shape + content, filter-respected, and the link
on the audit page.

### README feature list refreshed for v0.13–v0.20

The README had been frozen since ~v0.9 and falsely advertised
"no SMS, phone is just a username". v0.13 onwards is heavily SMS-
integrated. Reorganized:

- User system now lists 2FA + backup codes + trusted devices +
  forgot-password SMS + data export + self-delete.
- Admin lists the dashboard, search/filter, drill-down, refund,
  batch stats, API-tokens viewer, panic logout.
- Proactive SMS (expiry reminders + admin login alerts) gets its
  own subsection.
- API surface gets a complete read/write list including readonly +
  per-token rate limits.
- Firewall backends section (nftables + iptables/ipset for
  OpenWrt 21.02).

### Stats
- 17 packages tested
- 348 test functions (was 345 in v0.20)

## v0.20 — Webhook 测试按钮 + 应急下线

Two operational additions on top of v0.19.

### Webhook 测试按钮 (/admin/maintenance)

Mirrors the v0.16 /admin/sms-log/test pattern. The /admin/maintenance
page gains a Webhook section showing the configured URL + whether
HMAC-SHA256 signing is enabled. A 发送测试事件 button enqueues
a `{"type":"test","actor":"admin",...}` event through the existing
v0.14 exp-backoff Notifier so the admin can verify their receiving
service is wired before relying on it.

  POST /admin/maintenance/test-webhook
  - 503-ish redirect (err=webhook_not_configured) when URL is empty.
  - Otherwise fire-and-forget via a.Notifier.Send.
  - Audited as `admin / webhook_test` with the URL + IP.

When no URL is configured the section shows a config snippet so
the admin knows what to add.

4 tests: end-to-end with a capture server, no-URL error,
section-renders-when-configured, section-shows-example-when-not.

### 应急下线 (/admin/sessions)

Emergency response button for confirmed breach: signs out EVERY
user session AND every admin session except the calling one.

  POST /admin/sessions/panic
  - DeleteAllAdminSessionsExcept(my_token)
  - DeleteAllUserSessions()   (new DB helper)
  - Audited as `panic_logout` with admin_killed=N user_killed=N + IP.

UI sits below the existing "lost-my-laptop" yellow card as a
red-bordered "🆘 应急" card. The confirm() dialog spells out the
exact consequences (kept session, kicked admin sessions, kicked
user sessions).

A user getting kicked from /user/me doesn't affect their device's
firewall whitelist — the nftables set is MAC-keyed, not session-
keyed. Panic logout is purely a web-auth event.

3 tests: end-to-end (2 users + 1 other admin all killed, caller
survives, audit detail has the counts), page renders the
section, DeleteAllUserSessions helper preserves admin-kind rows.

### Stats
- 17 packages tested
- 345 test functions (was 338 in v0.19)

## v0.19 — 数据自助 + API 限流 + 审计保留

Five commits, mostly user-side privacy + admin-side ops:

### 自助数据导出 + 注销账号 (/user/me)

GDPR-style 数据可携 (`/user/account/export`) + 删除权
(`/user/account/delete`):

- `GET /user/account/export` returns an indented JSON file
  (`router-billing-data-<phone>.json`) with the user's account
  profile, MACs, last 500 orders, and last 100 audit entries.
  Secrets (password hash, TOTP secret, trust tokens) are
  excluded — a regression test deliberately seeds a leaky-named
  TOTP secret and asserts it never appears in the response.
- `POST /user/account/delete` requires the current password,
  runs `DeleteUser` (cascades to sessions via the existing
  helper, nulls out macs.user_id / orders.user_id via FK ON
  DELETE SET NULL), wipes cookies, redirects to /portal.
- Audited as `account_export` / `account_self_deleted` /
  `account_delete_failed`. Audit history survives deletion (keyed
  by phone, not user_id) so fraud investigations still work.

UI: two new cards on /user/me — neutral "我的数据" and
red-bordered "注销账号". The delete card includes a `confirm()`
with the phone visible.

7 tests across the two endpoints + the FK cascade behavior.

### 每个 API token 独立限速

```yaml
api_tokens:
  - token: "rb_dashboard"
    label: "grafana"
    readonly: true
    rate_limit_per_min: 30
```

`config.APIToken.RateLimitPerMin` (default 0 = unlimited) caps
how many requests per minute one token can make. Hitting the cap
returns 429. Per-token (label) buckets, lazily allocated on first
use, sliding 60s window via the existing rateLimiter.

The counter is per-token, not per-path — a script that hits
/health + /macs both costs against the same bucket. Matches the
"this is one consumer" intent.

4 tests covering the cap, the unlimited default, independence
between tokens, and per-token-across-paths.

### /admin/api-tokens 只读查看页

A sidebar entry (between SMS and 维护) showing every configured
Bearer token's label / 4-char prefix / readonly / rate-limit.
Intentionally read-only — the actual token value never leaves
the DB. Regression test seeds a deliberately-leaky token name and
confirms only the 4-char prefix renders. Config typos (empty
token field) get a 空 token warning pill.

5 tests covering render, no-full-token-leak, empty-state,
empty-token flag, sidebar link.

### audit_log 保留可配置

```yaml
security:
  audit_log_keep: 100000   # default 10000; clamped 1000..1000000
```

Previously hardcoded to 10000 rows in the janitor. Long-running
deploys want longer retention for compliance. Clamps instead of
failing: 100 → 1000 (min), 9999999 → 1000000 (max). No
"unlimited" — query latency starts to bite past ~1M rows.

4 config-package tests covering default + custom + min/max
clamp.

### Stats
- 17 packages tested
- 338 test functions (was 318 in v0.18)

## v0.18 — 库存盘点 + 报表筛选

Operational tooling continuation of v0.15. Three commits, all
admin-side reporting improvements.

### 充值码按 batch 库存 (/admin/vouchers)

Adds a top-of-page summary table aggregating vouchers by batch:

  total · 可用 · 已用 · 已撤销 · 已过期 · 最早创建 · CSV button

Each batch name links to a filtered per-row view; the 导出 CSV
button per row mirrors the existing /admin/vouchers/export.csv
path. NULL/empty batch names roll up under "(no batch)" so
vouchers that escaped a labeled generation stay visible.

New DB helper `VoucherBatchStats` — single GROUP BY query, returns
`[]VoucherBatchStat`.

Wrinkle worth flagging for future me: `MIN(created_at)` over a
DATETIME column comes back as TEXT in modernc.org/sqlite even
though the column type is DATETIME. The scan goes through a string
+ multi-layout time.Parse. Same pattern would apply for MAX, MIN,
or any other aggregate over a time column.

3 tests covering 3-A + 1-B + 1-no-batch aggregation, page render,
and the section-hidden-on-empty regression guard.

### 订单日期范围筛选 (/admin/orders)

Monthly reconciliation wants "all orders in November". Existing
filter only knew about substring + status. Two new params:

  /admin/orders?since=2026-05-01&until=2026-05-19

YYYY-MM-DD shape (HTML5 date-input native format), UTC, inclusive
both ends. The 已过滤 indicator + 清除 link react to date filters
too.

API addition: `db.OrderFilter` struct + `SearchOrdersFiltered`.
Old `SearchOrders(q, status, limit)` kept as a 3-arg shim so the
existing /api/admin/orders endpoint doesn't break.

4 tests: window inclusion, since-only, status+date+substring
combined, /admin/orders honors ?since= end-to-end.

### CSV 导出按筛选条件

Closes the obvious gap from the date-range commit:
`/admin/export/orders.csv` now accepts the same q/status/since/
until params as the page. The 导出 CSV button on /admin/orders
carries the current filter query so "filter then export" is one
click. Button label flips to "导出筛选结果" when a filter is
active so admins notice the export will be narrower.

3 tests covering filter-respected, no-filter-returns-all, and the
template-link-carries-query path.

### Stats
- 17 packages tested
- 318 test functions (was 308 in v0.17)

## v0.17 — 主动短信通知（到期提醒 + 管理员登录告警）

The first version that uses SMS for outbound notifications instead
of just reset-codes. Two opt-in flows, both gated on a configured
SMS provider.

### 套餐到期提醒 (auto + manual)

Active MACs with a phone-owning user get a "您的套餐 N 天后到期"
SMS in the 3 days before their `expires_at`. The window + on/off
state are configurable:

```yaml
sms:
  expiry_reminder_days: 7      # default 3; range 1..30
  expiry_reminder_disable: false   # set true to keep ONLY manual sends
```

How it works:
- `expiryReminderLoop` runs every hour from `App.Run` (silently
  no-ops when SMS is missing OR when `expiry_reminder_disable: true`).
- `ListExpiringMACsWithoutRecentReminder` SQL query: active MAC,
  user_id IS NOT NULL, `expires_at` between now and
  `+N days`, no `expiry_reminder` audit entry in the last 22h.
- For each hit: send SMS, audit row. Suspended users + ownerless
  MACs are skipped.
- The 22h audit-row dedup means a daily cron-like cadence can't
  double-text the same user.

Admin manual trigger: 立即扫描发送 button on `/admin/sms-log`
(under a new 套餐到期提醒 section). Same DB query + same audit
shape as the loop, so manual sends don't double-text MACs the
loop just handled.

11 tests covering the loop, dedup, suspended-user skip, ownerless
MAC, custom window, the disable flag, and the manual-trigger
endpoint.

### 管理员登录告警 SMS

```yaml
sms:
  admin_login_alert_phone: "13800138000"
```

Every successful `issueAdminSession` fires a fire-and-forget SMS
to the configured phone: "管理员 <user> 于 MM-DD HH:MM 从 <IP>
登录。若非本人请立即修改密码。"

Detached goroutine with 8s budget so an upstream provider hiccup
doesn't slow the admin's own login response. No-ops cleanly when
phone is empty, SMS provider is missing, or phone fails
`models.ValidPhone` (config typo guard).

Audited as `admin_login_alert_sent` / `admin_login_alert_failed`.

While here: every successful admin login now also writes a generic
`admin / login` audit entry (pre-v0.17 only failed-login was
audited — confusing gap).

5 tests including the panic-free no-SMS-provider path and the
audit-entry-always-fires regression guard.

### Stats
- 17 packages tested
- 308 test functions (was 292 in v0.16)

## v0.16 — 仪表盘 · 测试短信 (UI + API) · 可配置 HSTS · 可逆封禁 · 会话 TTL

Polish round, mostly admin-side. The dashboard is the big one — a
proper landing page replacing the redirect-to-macs that's shipped
with every prior release. Plus five smaller items: programmatic
SMS, reversible MAC ban, configurable session lifetimes, HSTS
preload knobs, and a verify-your-SMS-provider button.

### `/admin/dashboard` landing page

Mornings get an actual morning view. /admin now lands here instead
of /admin/macs. Sidebar gets a 仪表盘 entry at the top.

Tiles:
- Today: revenue (with 30-day sparkline) + paid-order count + new
  users (sparkline) + new MACs (sparkline) + active sessions.
- 7 days: revenue + paid orders.
- Cumulative: MAC total / active / expired, registered users,
  total revenue.

Below: plan-sales breakdown (last 30 days) + most-recent 10 audit
entries with "查看完整审计 →" link + 5 quick-link buttons.

New DB helper `DashboardSnapshot` — one SQL round-trip per stat,
all in one Go call. Uses `paid_at >= datetime('now','start of day')`
style comparisons instead of `date(...)` because modernc.org/sqlite
writes time.Time in an RFC3339 format that the date() function
doesn't parse cleanly (caught by a flaky test on first attempt —
the test catches the format-drift regression now).

Sparklines reuse the existing /static/sparkline.js +
/admin/charts.json pipeline. No new endpoints, no new JS, just
`<svg class="spark" data-metric="...">` elements.

5 tests covering page render, root → dashboard redirect, sidebar
link, DashboardSnapshot reflects seeded data, empty-DB → zeros.

### `/admin/sms-log` — 发送测试短信

When a provider is wired (`Available()==true`), the page shows a
form at the top: phone + optional message → POST to a new
`/admin/sms-log/test` handler that calls `a.SMS.Send` and writes
`sms_test` or `sms_test_failed` to the audit log.

The point is verification — admins can confirm their Aliyun
signature / template / API key actually works WITHOUT triggering a
real user-facing flow (reset-password, forgot-password, etc.).
Default message is "router-billing test message from <IP>" so an
admin who just hits send sees something useful.

5 tests including the disabled-provider error, bad-phone validation,
form-visibility gating, and the audit-entry shape.

### 可逆封禁 (`/admin/macs/revoke`)

The missing middle ground between "extend" (still active) and
"delete" (gone forever). `MACSvc.Revoke` already existed but no
admin handler exposed it.

POST `/admin/macs/revoke {mac}`:
- Sets status = blocked
- Removes from the firewall set
- Keeps the row (and any associated orders) so the audit trail
  stays intact

UI: 封禁 button next to 续费 + 删除 on each /admin/macs row.
Only shown when status != "blocked" so a duplicate click can't loop.

Reversible — a fresh /admin/macs/extend (or a user-side voucher
redemption / payment) flips status back to active and re-adds to
the firewall via the existing `MACSvc.Extend` path.

4 tests covering the status flip, audit-entry shape, invalid-MAC
error, and the template-level visibility guard.

### `POST /api/admin/sms/send` — programmatic ops alerts

Pairs with the readonly-token model in v0.14. Monitoring scripts
that detect anomalies (DB-corruption probe failed, repeated admin
login_failed entries, etc.) can now text the operator via the same
provider that powers /user/forgot-password and admin reset-password.

Requires a NON-readonly Bearer token.

  POST /api/admin/sms/send  Bearer <write-token>
  { "phone": "13800138000", "message": "..." }
  -> 200 { "status": "sent", "provider": "aliyun" }

Errors: 400 (bad phone / empty msg), 403 (readonly token), 503 (no
provider), 502 (upstream failed). All paths audit. Successful
sends record `via=api` in the audit detail so reviewers can tell
API-originated SMS from admin-UI SMS.

6 tests including the read-only-token regression guard.

### Configurable session TTLs

Previously hardcoded — admin 12h, user 30d. Now opt-in overrides:

```yaml
security:
  admin_session_hours: 4    # default 12; range 1..168 (1w)
  user_session_days: 90     # default 30; range 1..365 (1y)
```

Defaults stay safe. Out-of-range values fall back to the defaults
(an unbounded TTL is a worse footgun than a typo). The previous
package consts are gone — call sites go through
`Security.AdminSessionTTL()` / `Security.UserSessionTTL()` which
bake in the validation.

Drive-by: post-login redirect now points to /admin/dashboard
(matches the v0.16 root-redirect change).

6 tests covering defaults, custom values, and out-of-range fallback
for both knobs.

### Configurable HSTS

The existing security middleware emitted a hardcoded
`max-age=31536000` on TLS requests. Now configurable:

```yaml
security:
  hsts_max_age_seconds: 63072000   # 2 years; default 31536000
  hsts_include_subdomains: true    # default false (safe)
  hsts_preload: true               # default false; one-way trip
```

Defaults stay safe. HSTS is still only emitted on TLS-detected
requests (TLS!=nil OR X-Forwarded-Proto contains https), so HTTP-
only deploys get nothing burned. `securityHeaders` became an
`*App` method so it can read `a.Cfg.Security` once at construction
and capture the precomputed header string in the closure (zero
per-request cost).

5 tests including the safety-by-default regression guard
(plain-HTTP request gets no HSTS header even with security config
set).

### Stats
- 17 packages tested
- 292 test functions (was 258 in v0.15)

## v0.15 — 退款 · 用户详情页 · 搜索过滤 · 审计盲区清零 · 充值码 API

Operational tooling round — the things admins actually do every day
get faster. Plus closes the two state-mutators that weren't going
to the audit log, and finishes the JSON API surface with a
code-leak-safe voucher listing.

### Refund flow (`/admin/orders/refund`)

The big one — there was no way to record a refund. Admins had to
either delete the order (losing the audit trail) or let it sit as
"paid" while the gateway showed it as refunded.

Flow:
1. Admin processes the actual refund in WeChat/Alipay's own console
   (we deliberately don't auto-call the refund API — that would need
   another credentials set + a new failure surface).
2. Admin clicks "退款" on /admin/orders, which opens a confirm
   dialog showing order_no / MAC / days / amount.
3. They type the full order_no into a confirm box to dodge fat-
   finger mistakes, optionally note a reason.
4. POST /admin/orders/refund runs MarkOrderRefunded in one
   transaction: status → "refunded", trade_no appends "refund:
   <reason>", MAC.expires_at rolls back by the order's `days`.
5. If the rollback puts expires_at in the past, MAC status flips
   to "expired" and a background a.MACSvc.Resync() pulls it from
   the firewall set.

`models.OrderRefunded = "refunded"` is the new status value.
`MarkOrderRefunded` rejects pending / refunded orders ("only paid
orders can be refunded"), so a fat-fingered double-click can't loop.
Refunds audit as `order_refunded` with the reason + IP.

9 tests covering DB rollback math, MAC expiry transition, error
shape for unpaid/missing/already-refunded, confirm-box mismatch,
audit-entry written, and the 已退款 pill rendering.

### Per-user drill-down (`/admin/users/detail?id=N`)

Support workflow win: a customer calls, admin clicks their phone on
/admin/users, lands on ONE page with everything relevant.

- Profile (phone, suspended pill, 2FA pill, backup-codes remaining).
- Account actions card (suspend, reset password ± SMS, reset 2FA,
  delete — all the /admin/users buttons consolidated here).
- MAC table (all owned MACs + status + expiry).
- Order table (last 50 with amount + status).
- Active session table (token-prefix + expires).
- Trusted device table (only when 2FA is enrolled).
- Last 30 audit-log entries with IP extracted.

Phone + ID cells on /admin/users now link to the detail page.

New DB helper: `ListSessionsForUser(userID)` — symmetric to the
existing `ListActiveSessions` but filtered to one user's live
user-kind rows.

7 tests covering full-profile render, TOTP/backup-codes display,
missing/nonexistent-id redirects, trusted-device section only when
enrolled, list-page links to detail, and session helper filters
correctly.

### Search + status filter on /admin/macs and /admin/orders

Once a deploy has 50+ MACs or 500+ orders, the flat list becomes
unworkable. Both pages now have a search box + status dropdown
above the table:

- /admin/macs: q matches MAC OR label; status=active/expired/blocked.
- /admin/orders: q matches order_no OR mac OR trade_no;
  status=pending/paid/failed/expired/refunded (the last value is
  v0.15-new from the refund flow).
- 已过滤 indicator + 清除 link when a filter is active.

New DB helpers: `SearchMACs(q, status, limit)` and
`SearchOrders(q, status, limit)`. Single parameterized SELECT.
Empty q + empty status falls through to the un-filtered path so
the common case stays a single index scan. Limits default 200,
cap 1000 (matches SearchAudit).

7 tests across the two endpoints + their DB helpers.

### `/api/admin/vouchers` (read-only, code-leak-safe)

Last piece of the JSON API completion (after /users, /orders,
/audit in v0.14). Returns `apiVoucher`: same fields as
`models.Voucher` MINUS the raw `code` — instead a 4-char prefix
+ ellipsis (e.g. "BATC…").

The truncation is the whole point: a leaked monitoring token must
not be able to scrape unredeemed voucher codes (which would equal
free MAC time). A test asserts the raw 12-char code never appears
in the response body even when seeded directly in the DB.

  GET /api/admin/vouchers?batch=<batch>&limit=<1..1000>
  -> { "vouchers": [...] }

6 new tests including the no-leak red-line.

### Audit gaps closed

Two state-changing admin actions weren't going to the audit log.
Found via a sweep: `grep "^func.*handleAdmin"` + check for
`DB.Audit` calls in body.

- POST /admin/macs/extend (per-row "续期" button) — now logs
  `admin / extend / <MAC> / days=N ip=...`.
- POST /admin/resync (sidebar "重建防火墙") — logs
  `admin / firewall_resync` on success or
  `admin / firewall_resync_failed / err=...` on failure.

Other mutators were already audited: plan_save / plan_delete /
schedule_set / schedule_clear / backup / restore_staged / suspend /
delete / reset_password / reset_2fa / refunded / register / grant /
revoke. Re-running the grep should now return zero unaudited
mutators.

2 tests POST each endpoint then ListAudit + assert the expected
shape.

### Stats
- 17 packages tested
- 258 test functions (was 226 in v0.14)

## v0.14 — API surface complete + reliability polish

Five small improvements that round out what v0.13 started: complete
the JSON API so monitoring scripts can read everything they need
without scraping HTML, harden the webhook so a flaky consumer
doesn't lose payment notifications, and tidy up the janitor so the
new v0.13 tables don't accumulate stale rows.

### `/api/admin/users` (read-only) + `/admin/export/users.csv`

Same data shape on both endpoints (id, phone, suspended,
totp_enabled, macs, created_at). Designed for the readonly-token
use case shipped in v0.13:

  GET /api/admin/users?q=<phone-substring>&limit=<1..500>
  -> { "users": [...] }

`apiUserSummary` is deliberately a SUBSET of `models.User` — no
`password_hash` / `totp_secret` / `totp_pending` fields, so a leaked
read-only token can't exfiltrate auth material. A test confirms the
response bytes never contain those strings even when the row has
them set.

`/admin/export/users.csv` has the same columns. UI: 导出 CSV button
on /admin/users next to the search box.

8 new tests, including the "leaked-token-can't-exfil-secrets"
regression guard.

### `/api/admin/orders` (read-only)

  GET /api/admin/orders?limit=<1..500>&status=<paid|pending|...>
  -> { "orders": [ models.Order, ... ] }

`status=` does in-memory filtering — fine for the 100-500-row
datasets the monitoring use-case actually queries; no new DB helper
needed. 5 new tests.

### `/api/admin/audit` (read-only)

Full audit log queryable via the same filters as `/admin/audit`:
actor / action / target / since / until / limit.

  GET /api/admin/audit?actor=&action=&target=&since=&until=&limit=
  -> { "entries": [ {id, at, actor, action, target, detail}, ... ] }

`apiAuditEntry` uses explicit JSON tags so the API contract stays
stable even if `db.AuditEntry` changes. Useful for SIEM / Splunk
consumers that periodic-poll with since/until pagination. 4 new
tests.

### Webhook: exponential-backoff retries (was: 1 retry then drop)

`notify.Notifier` gains a `BackoffSchedule []time.Duration` field.
Default schedule is **3 retries at 2s / 30s / 5m**, so a transient
500 or a 30-second consumer outage no longer loses the event.

Semantics:
- `nil` (default) → `DefaultBackoffSchedule`
- `[]` (explicit empty) → no retries, 1 attempt only
- `[...]` → use as-is

Legacy `RetryDelay` still works when `BackoffSchedule == nil` — the
schedule() helper folds it into a 1-element slice. Existing
`TestRetriesOnceOn5xx` still passes unchanged.

Each retry logs "attempt N failed; retrying in <delay>" so ops can
trace flakiness in real time. Final drop logs the total attempt
count. 4 new tests including a legacy-RetryDelay regression guard.

### Janitor: wire v0.13 purge helpers into the 2-hour sweep

`PurgeExpiredPasswordResets` / `PurgeExpiredTrustedDevices` shipped
in v0.13 but no scheduler ever called them — stale rows accumulated
until the user manually re-triggered the flow. `purgeLoop` in
`server.go` now runs both alongside the existing
`PurgeExpiredSessions` / `PurgeAuditLog` every 2 hours.

2 new DB tests confirming both helpers drop stale rows while
keeping active ones intact.

### Stats
- 17 packages tested
- 226 test functions (was 203 in v0.13)

## v0.13 — 账号安全大改造（SMS · TOTP · 备用码 · 信任设备 · 只读 API token · 活动审计）

Nine flows that all share the same trust model: prove control of a
second factor before something sensitive happens. Plus recovery
paths so the second factor never becomes a permanent lock-out, the
"trust this device" bypass so daily logins aren't painful, the
"sign out other devices" + 最近活动 panel so users can spot + react
to compromise themselves, and least-privilege API tokens so
monitoring scripts can't accidentally revoke a paying user.

### Quick tour (in CHANGELOG order)

1. **Admin reset-password SMS** — `via_sms=1` on `/admin/users/reset-password` texts the temp password instead of bouncing it through the query string.
2. **`/user/forgot-password`** — self-service two-stage SMS reset (phone → code → new password). Bcrypt-hashed codes, 5-attempt cap, anti-enumeration.
3. **User TOTP enrollment** — `/user/2fa` lets users opt in to RFC 6238 TOTP via QR. Login-time gate mirrors the admin flow.
4. **Admin reset-2fa** — `/admin/users/reset-2fa` unblocks a user who lost both phone + backup codes.
5. **10 backup codes** — generated at enrollment, displayed once, bcrypt-stored, usable in place of TOTP at login. "重新生成备用码" regenerates.
6. **Trusted devices** — opt-in "信任此设备 30 天" checkbox bypasses 2FA on the same browser after successful enrollment.
7. **Readonly API tokens** — `readonly: true` in `api_tokens` limits a token to GET endpoints.
8. **最近活动 panel** — last 10 login + security audit entries visible on `/user/me`, with IP extracted from detail strings.
9. **Sign out other devices** — `/user/sessions/sign-out-others` kills every session except the calling one.

### Sign out other devices (`/user/sessions/sign-out-others`)

For when the user looks at the new "最近活动" panel and sees a
session they don't recognize. The button appears on `/user/me`
when more than one session is active for the user.

- `POST /user/sessions/sign-out-others` calls
  `DeleteUserSessionsExcept(uid, currentToken)` so every other
  rb_user cookie is invalidated immediately.
- The calling browser keeps its session — no surprise log-out.
- Audit log records `sessions_revoked_others` with `killed=N`.

New DB helpers:
- `CountUserSessions(userID)` — cheap COUNT(*) for the badge.
- `DeleteUserSessionsExcept(userID, keep)` — symmetric to the
  existing `DeleteAllAdminSessionsExcept`.

3 new tests:
- Sign-out-others kills only other sessions (caller still works,
  others now redirect to login).
- Button is hidden when only one session exists, shown when 2+.
- `CountUserSessions` returns 2 after two fresh `CreateSession`.

### 最近活动 on `/user/me` (login + security audit visible to user)

A new "最近活动" table at the bottom of `/user/me` shows the last 10
audit_log entries belonging to the user (actor = `user:<phone>` OR
`user-attempt:<phone>`). For each: timestamp, human-readable
Chinese label, IP if present in the detail string. Designed so a
non-technical user can spot "我没在那个时间登录" and react fast.

Implementation:
- `SearchAudit` filtered by Actor (LIKE-matched on `:<phone>` so both
  successful and failed events surface).
- `activityLabel(action)` translates ~24 action codes to user-facing
  Chinese labels; unknown actions pass through as-is so we never
  silently lose data.
- `extractIPFromDetail(detail)` pulls "ip=10.0.0.5" out of the
  audit-log detail string (the convention used by every handler
  that writes it).
- Section only renders when there are entries — silent for fresh
  accounts.

5 new tests in `user_activity_test.go`:
- /user/me shows 最近活动 with register + failed-login rows.
- `activityLabel` covers every security action with a Chinese label
  (regression guard: adding a new audit action without a label is
  caught immediately).
- Unknown actions pass through.
- `extractIPFromDetail` table test (5 cases incl. IPv6).
- `formatActivity` shape test.

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
- 203 test functions (was 143)

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
