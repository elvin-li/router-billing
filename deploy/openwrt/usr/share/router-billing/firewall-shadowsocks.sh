#!/bin/sh
# Optional: open the built-in Shadowsocks proxy port on the LAN interface
# only. Use this when shadowsocks.enabled: true in config.yaml AND you want to
# manage the port with a dedicated nftables chain instead of /etc/config/firewall.
#
#   apply  - add an input-accept rule for the SS port, scoped to $SS_IFACE
#   purge  - remove the dedicated chain
#
# Defaults bind the accept to br-lan (the trusted/management network). NEVER
# open the SS port on the paid SSID interface — that would let unpaid clients
# tunnel out and bypass the captive portal. Exposing on WAN is possible but
# discouraged; if you do, use a long password + shadowsocks.allowed_cidrs.
#
# Equivalent to setting `shadowsocks.open_firewall: true` +
# `shadowsocks.firewall_iface: br-lan` in config.yaml, which makes the daemon
# manage this same chain automatically at startup.

set -e

TABLE_FAMILY="inet"
TABLE_NAME="billing"
CHAIN_NAME="ss_in"
SS_IFACE="${SS_IFACE:-br-lan}"
SS_PORT="${SS_PORT:-8388}"

cmd_apply() {
    nft add table ${TABLE_FAMILY} ${TABLE_NAME} 2>/dev/null || true
    nft add chain ${TABLE_FAMILY} ${TABLE_NAME} ${CHAIN_NAME} \
        '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
    nft flush chain ${TABLE_FAMILY} ${TABLE_NAME} ${CHAIN_NAME}
    if [ -n "${SS_IFACE}" ]; then
        nft add rule ${TABLE_FAMILY} ${TABLE_NAME} ${CHAIN_NAME} \
            iifname "\"${SS_IFACE}\"" tcp dport ${SS_PORT} accept
    else
        nft add rule ${TABLE_FAMILY} ${TABLE_NAME} ${CHAIN_NAME} \
            tcp dport ${SS_PORT} accept
    fi
    echo "shadowsocks: opened tcp/${SS_PORT} on iface='${SS_IFACE:-any}'"
}

cmd_purge() {
    nft delete chain ${TABLE_FAMILY} ${TABLE_NAME} ${CHAIN_NAME} 2>/dev/null || true
}

case "${1:-apply}" in
    apply) cmd_apply ;;
    purge) cmd_purge ;;
    *) echo "usage: SS_IFACE=br-lan SS_PORT=8388 $0 {apply|purge}" >&2; exit 2 ;;
esac
