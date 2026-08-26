package shadowsocks

import "sync/atomic"

// Metrics holds cumulative counters for the running Shadowsocks server. All
// fields are updated with atomic ops so /metrics can read them concurrently
// with active relays. Snapshot() returns a consistent-enough copy for
// exposition (individual counters are monotonic; a torn read across fields
// is harmless for Prometheus gauges/counters).
type Metrics struct {
	connectionsTotal atomic.Uint64 // accepted connections (post-handshake)
	activeConns      atomic.Int64  // currently-open relays
	bytesIn          atomic.Uint64 // client → target
	bytesOut         atomic.Uint64 // target → client
	handshakeErrors  atomic.Uint64 // bad password / malformed header / replay
	dialErrors       atomic.Uint64 // could not connect to target
	replayRejected   atomic.Uint64 // subset of handshake errors: salt replays
	blockedByACL     atomic.Uint64 // rejected by allowed_cidrs / private-net guard
}

// MetricsSnapshot is a plain-value copy for the /metrics exposition.
type MetricsSnapshot struct {
	ConnectionsTotal uint64
	ActiveConns      int64
	BytesIn          uint64
	BytesOut         uint64
	HandshakeErrors  uint64
	DialErrors       uint64
	ReplayRejected   uint64
	BlockedByACL     uint64
}

// Snapshot reads all counters into a value struct.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		ConnectionsTotal: m.connectionsTotal.Load(),
		ActiveConns:      m.activeConns.Load(),
		BytesIn:          m.bytesIn.Load(),
		BytesOut:         m.bytesOut.Load(),
		HandshakeErrors:  m.handshakeErrors.Load(),
		DialErrors:       m.dialErrors.Load(),
		ReplayRejected:   m.replayRejected.Load(),
		BlockedByACL:     m.blockedByACL.Load(),
	}
}
