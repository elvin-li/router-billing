# 路由器计费系统（router-billing）

[![CI](https://github.com/elvin-li/router-billing/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/elvin-li/router-billing/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/elvin-li/router-billing?include_prereleases&sort=semver)](https://github.com/elvin-li/router-billing/releases)
[![Go](https://img.shields.io/badge/go-1.22-00ADD8?logo=go)](go.mod)
[![Platform](https://img.shields.io/badge/platform-OpenWrt%20aarch64-1e293b)](deploy/openwrt)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

OpenWrt（aarch64）上运行的 MAC 地址计费认证系统。**只对收费 SSID 上的客户端执行 MAC 白名单准入**；熟人/管理 SSID（Free_WiFi · WPA2 加密）完全不受计费逻辑影响。

## 三套 SSID

| SSID | 加密 | 网段 | 受 MAC 白名单 | 用途 |
|---|---|---|---|---|
| `Free_WiFi` | **WPA2 加密**（v0.9+） | lan | 否 | **熟人 / 管理 WiFi** — 给家人朋友 + 管理员自己用，不计费、不走门户 |
| `Paid_WiFi` | 开放 | paid (192.168.5.0/24) | 是 | 主收费入口 — 客户连这个，浏览器自动跳付费页 |
| `Paid_Secure_WiFi` | WPA2 | paid (同上) | 是 | VIP 通道 — 已付费设备 + 知道密码 → 双重门槛 |

> v0.9 把 Free_WiFi 改成强制加密：之前它是开放的，意味着隔壁咖啡馆任何人都能蹭网 + 触达 `:8080/admin/login`（虽然有密码但暴露面没必要）。
> 现在 install.sh 没传 `FREE_KEY` 时会**自动生成** 12 位密码写到 `/etc/router-billing/wifi-keys.txt`（mode 0600）。安装后 `sudo cat` 一次取出来分给家人即可。

两个 paid SSID 共用同一个 `br-paid` 网桥和同一份 `mac_paid` 白名单。

## 功能

- 强制门户：未授权 MAC 访问 HTTP → 自动跳付费页
- 套餐：¥1/月、¥10/年（可改）
- 支付：微信 Native + 支付宝当面付，**支持纯出站轮询（无需公网 HTTPS）**
- 用户系统（手机号 + 密码）:
  - 我的设备、订单、活动日志、付款收据
  - 一键绑定本设备 / 替换设备（A→B 时长转移）
  - **二步验证**：TOTP（RFC 6238） + 10 个一次性备用码 + 信任此设备 30 天
  - **找回密码**：手机短信验证码（Aliyun / Console）
  - **数据可携 + 注销账号**：JSON 导出 / 密码确认后注销
  - 自助 sign-out-others（踢其他登录设备）
- 管理后台（一处看全）:
  - **仪表盘**：今日 / 7 天 / 30 天 营收，**月环比 (MoM) 标签**（v0.28），累计 + 活跃 session
  - **关注事项面板**：即将到期 MAC、滞留 pending 订单、停用用户、今日失败订单；侧边栏对应位置显示徽章数字（v0.58）
  - **过去 24 小时投递失败面板**：SMS / Webhook 失败计数（v0.59）
  - **MAC 管理**：搜索过滤、批量续费 / 删除、按状态筛选、可逆封禁；点 MAC 进**详情时间线**（订单 + 审计，v0.48）
  - **在线设备**：实时 ARP + dnsmasq lease + 主机名，一键授权 IoT
  - **订单**：搜索（含 q / 状态 / 日期 / **user_id**，v0.33）+ CSV 导出 + 单笔退款 + **取消按钮**（v0.53）+ **一键清理过期订单**（v0.56）；点订单号进**详情时间线**（v0.42）
  - **用户**：详情下钻（MAC + 订单 + session + 信任设备 + 30 条审计）
  - **充值码**：按 batch 库存 + 打印卡片（QR）+ **整批作废**（v0.26）+ **CSV 导出按状态过滤**（v0.41）
  - **SMS log**：DB 持久化记录（**所有 provider，跨重启可见**，v0.43）+ Console ring buffer + 立即裁剪
  - **Webhook log**：投递历史（每次重试一行 + HTTP code + duration_ms，v0.49）+ 仅显示失败筛选 + 立即裁剪
  - **审计日志**：搜索 + 日期范围 + **详情关键字 q** （v0.54）
  - **维护**：备份下载 / 恢复 / Webhook 测试 / Session 应急下线 / **立即执行到期扫描** / **立即裁剪审计日志** / **PRAGMA optimize** (v0.35 / v0.39)
  - **API Tokens**：只读查看 / 4 位前缀 / readonly 标记 / 速率限制
- 主动 SMS:
  - 套餐到期提醒（3 天前；每个 MAC 22h 去重）
  - 管理员登录告警（可选；发到 ops 手机）
  - **每日运营日报**（v0.23）
- **后台维护循环**：每 2 小时清理 sessions / audit / sms_log / webhook_deliveries / 过期 MAC / **可选 auto-cancel-stale-orders**（v0.60）；每周 PRAGMA optimize + VACUUM
- API 完整覆盖（`/api/admin/*` Bearer token）:
  - **读端点**: `/health` `/dashboard` `/macs` `/users` `/orders` `/orders/get` `/audit` `/vouchers` `/sms/log` `/webhook/log` `/plans` `/backup` — 全部支持 `readonly` token
  - **写端点 (mutate)**: `/macs/grant` `/macs/revoke` `/macs/import` `/users/grant` `/users/grant-by-phone` `/vouchers/generate` `/vouchers/batch/revoke` `/orders/refund` `/orders/cancel` `/orders/cancel-stale` `/sms/send` `/audit/note` `/webhook/test` `/maintenance/expire-now` `/maintenance/audit-trim` `/maintenance/optimize-now` `/plans/save` `/plans/delete`
  - 字段级安全：用户列表不暴露 password_hash / totp_secret；充值码列表仅前 4 位；订单详情不带 trade_no 流水
  - **`/health` 端点**：无 auth，简单 200/503（`SELECT 1` 探测，v0.30）—— 给负载均衡器和 uptime monitor 用
  - **`/metrics` 端点**：Prometheus exposition（v0.13+），支持 `metrics_token` 限制
- **观测能力**:
  - **持久化 SMS 投递记录** `sms_log` 表（v0.43，跨重启）
  - **持久化 Webhook 投递记录** `webhook_deliveries` 表（v0.49，每次重试一行）
  - 失败的投递在 `/admin/health` 响应里出现（24 小时滚动窗口，v0.61）
- 防火墙后端：nftables（默认）+ iptables/ipset（OpenWrt 21.02 兼容）
- IoT/充电桩友好：完全不用浏览器也能加白名单
- 体积：单个 ARM64 静态二进制 ≈ 13 MB

## 中国没有 HTTPS 域名怎么办

微信/支付宝的 webhook 必须 HTTPS 公网；但本系统支持**主动查单**回退：

- 浏览器照常每 2 秒轮询 `/api/pay/status`
- 服务器发现订单 pending → **从路由器主动出站** 调用：
  - 微信：`GET /v3/pay/transactions/out-trade-no/...?mchid=...`
  - 支付宝：`alipay.trade.query`
- 上游回 SUCCESS 就标记已付、写白名单、返回浏览器
- **完全不需要入站 HTTPS、不需要域名、不需要备案**

只要路由器能访问 `api.mch.weixin.qq.com` 和 `openapi.alipay.com` 即可。`notify_url` 字段填占位即可（不会被调用）。

## 充电桩 / IoT 设备工作流

1. 让设备先连 `Paid_WiFi`（任意一个 paid SSID 都行，加密那个需要密码）
2. 管理员浏览器开 `http://router-ip:8080/admin/devices`
3. 设备会出现在"在线设备"表里（带主机名，比如 `chargepile-01`）—— **未授权的在线设备有绿色边框高亮**
4. 选时长（30 天 / 1 年 / 5 年 / 10 年）→ 「授权」
5. MAC 立即进 `mac_paid` nftables 集合 → 设备马上联网

页面每 30 秒自动刷新；设备离线后 10 分钟内仍然显示，方便统一录入。

设备没上电？从机身贴纸抄 MAC，用底部的"添加未在线的 MAC"表单。

## 用户系统（手机号账号）

- 用户在门户上点"登录" → 手机号 + 密码
- 登录后访问 `/user/me`：
  - 看到所有自己买的 MAC + 到期时间
  - **「转给本设备」**：把 MAC 的剩余时长原样转移给当前访问页面的设备的 MAC（自动 ARP 检测）
  - 「续费」：跳到门户页，预填 MAC
  - 改密码、订单历史

如果用户已登录后再去付费，订单自动 link 到他的账号，付出来的 MAC 也自动归他名下。

> v0.13 起手机号是真的手机号 —— 配 SMS provider 后可走找回密码 / 到期提醒 / 二步验证 SMS 通道。

## 架构

```
[手机/IoT] ─Paid_WiFi/Paid_Secure_WiFi─▶ [OpenWrt br-paid]
                                          │
                ┌─────────────────────────┴─────────────────────────┐
                │  nftables inet billing                            │
                │                                                   │
                │  chain pre  (NAT):  ether saddr ∈ mac_paid → ok   │
                │                     else tcp 80 → :8080 (portal)  │
                │                          tcp 443 → reject         │
                │                                                   │
                │  chain fwd  (filter): ∈ mac_paid → forward        │
                │                       else drop                   │
                └────────────────────────┬──────────────────────────┘
                                         │
                       ┌─────────────────┴────────────────┐
                       │  Go 进程 (HTTPS-not-required)    │
                       │                                  │
                       │  /portal          付费/绑定页    │
                       │  /api/pay/create  下单+precreate │
                       │  /api/pay/status  轮询(+查单)    │
                       │  /notify/{wx,ali} webhook(可选)  │
                       │  /user/*          用户中心       │
                       │  /admin/*         管理后台       │
                       └──────────────────────────────────┘
```

## 编译 + 部署

```bash
# 本机要装 Go 1.21+
brew install go   # 或对应平台

cd /Users/elvin/Developer/路由器计费
make deps         # tidy
make pack-arm64   # 出 build/router-billing-arm64.tar.gz

# 拷到路由器
scp build/router-billing-arm64.tar.gz root@router:/tmp/
ssh root@router '
  cd /tmp && tar xzf router-billing-arm64.tar.gz
  cd router-billing && sh install.sh
'
```

第一次安装自动建好 `Free_WiFi` + `Paid_WiFi`。要启用加密 SSID：

```sh
# 在路由器上
PAID_SECURE_KEY=12345678 PAID_SECURE_SSID=MyShop_Pro \
  sh /usr/share/router-billing/setup-secure-ssid.sh
```

## 项目结构

```
router-billing/
├── cmd/router-billing/        程序入口（main）
├── internal/
│   ├── arp/                   ip neigh 解析
│   ├── config/                YAML 配置
│   ├── db/                    SQLite + 自动迁移
│   ├── dnsmasq/               /tmp/dhcp.leases 解析
│   ├── firewall/              nftables 集合维护
│   ├── models/                MAC / User / Order / Sighting
│   ├── pay/                   微信 Native + 支付宝当面付 (含查单)
│   ├── scheduler/             过期清理
│   ├── server/                HTTP 路由 (portal/admin/user/pay)
│   ├── service/               MAC + 防火墙 联合事务
│   └── sightings/             后台 ARP 历史采集
├── web/                       模板 + 静态资源
└── deploy/openwrt/            UCI defaults / firewall / init / install
```

## 安全 note

- 用户密码 bcrypt cost 10
- 用户登录/注册有 IP 维度的 rate limit（登录 8 次/5 分钟，注册 4 次/小时）
- admin session: 12 小时，cookie path=/admin
- user session: 30 天，cookie path=/
- audit log 记录登录/付费/授权/替换/收回（保留最近 10000 条）

## 卸载

```sh
sh /tmp/router-billing/openwrt/uninstall.sh
```

会停服务、撤 nftables 表、删二进制和数据。Paid_WiFi 等 SSID UCI 配置不会动（脚本末尾有手动清理命令）。
