package firewall

import (
	"fmt"
	"strings"
)

// NewBackend builds the right API impl based on the config backend name.
// Defaults to nftables when empty/unknown (the modern OpenWrt default).
//
// `family` and `tableName` are only used by the nftables backend. `set` and
// `iface` are shared by both. `dryRun` propagates to whichever backend.
func NewBackend(backend, family, tableName, set, iface string, dryRun bool) (API, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", "nft", "nftables":
		m := New(family, tableName, set, iface)
		m.SetDryRun(dryRun)
		return m, nil
	case "ipt", "iptables", "ipset":
		m := NewIPSet(set, iface)
		m.SetDryRun(dryRun)
		return m, nil
	default:
		return nil, fmt.Errorf("unknown firewall.backend: %q (want nftables|iptables)", backend)
	}
}
