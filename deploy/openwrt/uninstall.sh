#!/bin/sh
# 卸载 router-billing。不会自动删除 Paid_WiFi 的 UCI 配置 — 如果想清，看脚本末尾。
set -e

log() { echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || { echo "需要 root" >&2; exit 1; }

log "停止服务"
/etc/init.d/router-billing stop 2>/dev/null || true
/etc/init.d/router-billing disable 2>/dev/null || true

log "撤销 nftables 表"
/usr/share/router-billing/firewall-billing.sh purge 2>/dev/null || true

log "删除文件"
rm -f /usr/bin/router-billing
rm -f /etc/init.d/router-billing
rm -rf /usr/share/router-billing
rm -f /etc/uci-defaults/99-router-billing-ssid

if [ "${KEEP_DATA:-0}" = "1" ]; then
    log "保留 /etc/router-billing 和 /var/lib/router-billing（KEEP_DATA=1）"
else
    rm -rf /etc/router-billing
    rm -rf /var/lib/router-billing
fi

cat <<EOF
卸载完成。

如需移除 Paid_WiFi 的 SSID/网络/防火墙区域，手动执行：
  uci delete network.paid
  uci delete dhcp.paid
  # 删除 ssid 为 Paid_WiFi 的 wifi-iface：
  for i in \$(uci show wireless | awk -F'[].[]' '/ssid=.Paid_WiFi./ {print \$2}'); do
      uci delete wireless.@wifi-iface[\$i]
  done
  uci commit && /etc/init.d/network reload && /etc/init.d/firewall reload && wifi reload
EOF
