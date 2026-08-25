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
    # 提取 @wifi-iface[N] 的数字下标。旧版 awk -F'[].[]' 取的是 $2 ——
    # 那是字面量 "@wifi-iface" 而不是下标，随后的 uci set 必然报错，
    # set -e 让"更新已有 SSID 密码"路径从未成功过。
    SECTION=$(uci -q show wireless | sed -n "s/^wireless\.@wifi-iface\[\([0-9]*\)\]\.ssid='${PAID_SECURE_SSID}'$/\1/p" | head -n1)
    [ -n "${SECTION}" ] || { echo "找不到 ${PAID_SECURE_SSID} 的 wifi-iface 下标" >&2; exit 1; }
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

# 与 install.sh 保持一致：密码记录到 root-only 的 wifi-keys.txt。
WIFI_KEYS=/etc/router-billing/wifi-keys.txt
mkdir -p /etc/router-billing
if [ ! -f "${WIFI_KEYS}" ]; then
    touch "${WIFI_KEYS}"
    echo "# router-billing wifi keys" >> "${WIFI_KEYS}"
fi
chmod 0600 "${WIFI_KEYS}"
echo "paid_secure_key=${PAID_SECURE_KEY}" >> "${WIFI_KEYS}"

echo "完成。${PAID_SECURE_SSID} (psk2) 已上线。密码已记录到 ${WIFI_KEYS} (0600)。"
