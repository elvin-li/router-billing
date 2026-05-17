#!/bin/sh
# 把当前目录的产物安装到 OpenWrt。
# 在 router 上 cd 到解压目录后执行：sh install.sh
set -e

PKG_DIR="$(cd "$(dirname "$0")" && pwd)"

log() { echo "==> $*"; }
die() { echo "[ERR] $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "需要 root 权限"
[ -f "${PKG_DIR}/router-billing" ] || die "二进制 ${PKG_DIR}/router-billing 不存在"

# 依赖检查
for c in nft uci ip; do
    command -v "$c" >/dev/null 2>&1 || die "缺少 $c（请 opkg install nftables uci iproute2）"
done

log "创建目录"
install -d /usr/bin /etc/router-billing /var/lib/router-billing \
           /usr/share/router-billing/web/templates \
           /usr/share/router-billing/web/static \
           /etc/init.d /etc/uci-defaults

log "复制二进制 -> /usr/bin/router-billing"
install -m 0755 "${PKG_DIR}/router-billing" /usr/bin/router-billing

log "复制 web 资源 -> /usr/share/router-billing/web/"
cp -r "${PKG_DIR}/web/templates/." /usr/share/router-billing/web/templates/
cp -r "${PKG_DIR}/web/static/."    /usr/share/router-billing/web/static/

if [ -f /etc/router-billing/config.yaml ]; then
    log "已存在 /etc/router-billing/config.yaml，跳过覆盖"
else
    log "首装：写入默认 config.yaml（请立即修改 admin.password）"
    install -m 0644 "${PKG_DIR}/config.example.yaml" /etc/router-billing/config.yaml
fi

log "安装 init 脚本"
install -m 0755 "${PKG_DIR}/openwrt/etc/init.d/router-billing" /etc/init.d/router-billing

log "安装 firewall 辅助脚本 + secure-SSID 工具"
install -d /usr/share/router-billing
install -m 0755 "${PKG_DIR}/openwrt/usr/share/router-billing/firewall-billing.sh" \
                /usr/share/router-billing/firewall-billing.sh
install -m 0755 "${PKG_DIR}/openwrt/usr/share/router-billing/setup-secure-ssid.sh" \
                /usr/share/router-billing/setup-secure-ssid.sh

UCI_DEFAULT=/etc/uci-defaults/99-router-billing-ssid
if [ -f /etc/router-billing/.ssid_applied ]; then
    log "SSID 已配置过，跳过 uci-defaults"
else
    log "安装 uci-defaults 脚本（首次启动将创建双 SSID）"
    install -m 0755 "${PKG_DIR}/openwrt/etc/uci-defaults/99-router-billing-ssid" "$UCI_DEFAULT"
    # 立刻应用一次
    "$UCI_DEFAULT" && touch /etc/router-billing/.ssid_applied || \
        log "warn: uci-defaults 失败，下次开机会重试"
fi

log "应用 nftables 规则"
/usr/share/router-billing/firewall-billing.sh apply

log "enable + 启动服务"
/etc/init.d/router-billing enable
/etc/init.d/router-billing restart

cat <<EOF

==================================================================
  router-billing 已安装。

  下一步：
    1. 修改管理员密码：vi /etc/router-billing/config.yaml
    2. 重启服务：     /etc/init.d/router-billing restart
    3. 后台地址：     http://<router-lan-ip>:8080/admin/login
    4. 用户中心：     http://<router-lan-ip>:8080/user/login

  SSID：
    Free_WiFi         (开放，跟 lan 同网段，免费直通)
    Paid_WiFi         (开放，受 MAC 白名单)
    Paid_Secure_WiFi  (WPA2 加密，受相同 MAC 白名单)
                      启用：PAID_SECURE_KEY=超过8位 sh /usr/share/router-billing/setup-secure-ssid.sh

  日志：       logread -e router-billing -f
  防火墙集合： nft list set inet billing mac_paid
  卸载：       sh ${PKG_DIR}/openwrt/uninstall.sh
==================================================================
EOF
