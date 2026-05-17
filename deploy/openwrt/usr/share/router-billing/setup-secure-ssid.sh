#!/bin/sh
# 事后添加加密收费 SSID：
#   PAID_SECURE_SSID=Paid_Secure_WiFi PAID_SECURE_KEY=超过8位的密码 sh setup-secure-ssid.sh
# 同一份 paid 区域，跟开放的收费 SSID 共用 MAC 白名单。
set -e

PAID_SECURE_SSID="${PAID_SECURE_SSID:-Paid_Secure_WiFi}"
PAID_SECURE_KEY="${PAID_SECURE_KEY:-}"

[ -n "$PAID_SECURE_KEY" ] || { echo "请先 export PAID_SECURE_KEY=至少8位密码" >&2; exit 2; }
[ ${#PAID_SECURE_KEY} -ge 8 ] || { echo "密码至少 8 位" >&2; exit 2; }

WIFI_DEV=$(uci -q show wireless | sed -n "s/^wireless\.\([^.]*\)=wifi-device$/\1/p" | head -n1)
[ -n "$WIFI_DEV" ] || { echo "找不到 wifi-device" >&2; exit 1; }

if uci -q show wireless | grep -q "ssid='${PAID_SECURE_SSID}'"; then
    echo "SSID ${PAID_SECURE_SSID} 已存在，仅更新密码"
    SECTION=$(uci -q show wireless | awk -F'[].[]' "/ssid='${PAID_SECURE_SSID}'/ {print \$2; exit}")
    uci set wireless.@wifi-iface[${SECTION}].encryption='psk2'
    uci set wireless.@wifi-iface[${SECTION}].key="${PAID_SECURE_KEY}"
else
    echo "新增 ${PAID_SECURE_SSID}"
    uci add wireless wifi-iface >/dev/null
    uci set wireless.@wifi-iface[-1].device="${WIFI_DEV}"
    uci set wireless.@wifi-iface[-1].network='paid'
    uci set wireless.@wifi-iface[-1].mode='ap'
    uci set wireless.@wifi-iface[-1].ssid="${PAID_SECURE_SSID}"
    uci set wireless.@wifi-iface[-1].ifname='wl-paidsec'
    uci set wireless.@wifi-iface[-1].encryption='psk2'
    uci set wireless.@wifi-iface[-1].key="${PAID_SECURE_KEY}"
fi

uci commit wireless
wifi reload
echo "完成。$(echo $PAID_SECURE_SSID) (psk2) 已上线。"
