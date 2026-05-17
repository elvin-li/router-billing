# Changelog

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
