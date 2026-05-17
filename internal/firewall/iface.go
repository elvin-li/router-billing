package firewall

import "context"

// API is the slice of *Manager's surface that the rest of the codebase
// consumes. Defining it here (rather than at each consumer) keeps the
// nftables-specific *Manager swappable for fakes in tests and for a future
// iptables backend without changing every callsite.
//
// *Manager satisfies API trivially (each method is on *Manager).
//
// SetDryRun is intentionally NOT here — it's a configuration knob on the
// concrete type, called once at startup from main.go.
type API interface {
	EnsureSet(ctx context.Context) error
	Add(ctx context.Context, mac string) error
	Remove(ctx context.Context, mac string) error
	Sync(ctx context.Context, macs []string) error
	List(ctx context.Context) ([]string, error)
	Counters(ctx context.Context) (map[string]MACCounter, error)
}

// Compile-time check.
var _ API = (*Manager)(nil)
