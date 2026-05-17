#!/bin/sh
# 维护 router-billing 用的 nftables 表 inet billing。
#   apply  - 创建 table/set/chain（幂等）
#   purge  - 删除整个 table
# 服务启动前会调用 apply；卸载脚本会调用 purge。

set -e

TABLE_FAMILY="inet"
TABLE_NAME="billing"
SET_NAME="mac_paid"
PAID_IFACE="${PAID_IFACE:-br-paid}"
PORTAL_PORT="${PORTAL_PORT:-8080}"

cmd_apply() {
    # mac_paid : per-MAC allowlist, per-element bytes/packets counters
    # wg_paid  : per-IP walled-garden allowlist for unpaid devices
    #            (so they can reach WeChat/Alipay servers to actually pay)
    nft -f - <<NFT
table ${TABLE_FAMILY} ${TABLE_NAME} {
    set ${SET_NAME} {
        type ether_addr
        counter
    }
    set wg_paid {
        type ipv4_addr
        flags timeout
    }

    chain pre {
        type nat hook prerouting priority -1; policy accept;
        # 已付费 MAC：放行（不重定向）
        iifname "${PAID_IFACE}" ether saddr @${SET_NAME} return
        # 未付费但目标在 walled garden：放行（让支付/captive-portal 探测包通过）
        iifname "${PAID_IFACE}" ip daddr @wg_paid return
        # 未付费：HTTP → 门户；HTTPS → reject 触发 CP 探测
        iifname "${PAID_IFACE}" tcp dport 80  redirect to :${PORTAL_PORT}
        iifname "${PAID_IFACE}" tcp dport 443 reject
    }

    chain fwd {
        type filter hook forward priority -1; policy accept;
        iifname "${PAID_IFACE}" ether saddr @${SET_NAME} return
        iifname "${PAID_IFACE}" ip daddr @wg_paid return
        iifname "${PAID_IFACE}" drop
    }
}
NFT
}

cmd_purge() {
    nft delete table ${TABLE_FAMILY} ${TABLE_NAME} 2>/dev/null || true
}

case "${1:-apply}" in
    apply) cmd_apply ;;
    purge) cmd_purge ;;
    *) echo "usage: $0 {apply|purge}" >&2; exit 2 ;;
esac
