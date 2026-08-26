package shadowsocks

import (
	"encoding/binary"
	"sync"
	"time"
)

// replayFilter rejects reused connection salts within a time window. Salt
// reuse in AEAD constructions is catastrophic (nonce/keystream reuse), so a
// well-behaved client never repeats one; an attacker replaying a captured
// handshake will, and we drop it.
//
// The filter is memory-bounded: entries older than the window are evicted
// lazily on insert, and a hard cap prevents unbounded growth under a flood
// of unique salts (when the cap is hit the oldest half is dropped — this can
// only *shorten* the effective window, never accept a true replay within the
// retained set).
type replayFilter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	seen   map[uint64]time.Time
	now    func() time.Time // injectable for tests
}

// newReplayFilter builds a filter with the given window. A window <= 0
// disables replay protection (the filter always accepts).
func newReplayFilter(window time.Duration, max int) *replayFilter {
	if max <= 0 {
		max = 1 << 16
	}
	return &replayFilter{
		window: window,
		max:    max,
		seen:   make(map[uint64]time.Time),
		now:    time.Now,
	}
}

// key folds a salt into a uint64 map key. Salts are 16 or 32 random bytes;
// XOR-folding to 64 bits keeps memory small while the collision probability
// stays astronomically low for the retained set sizes we allow. A collision
// can only cause a false *reject* of a fresh connection, never a false
// accept of a real replay of a different salt — acceptable and rare.
func key(salt []byte) uint64 {
	var k uint64
	for len(salt) >= 8 {
		k ^= binary.LittleEndian.Uint64(salt[:8])
		salt = salt[8:]
	}
	if len(salt) > 0 {
		var tail [8]byte
		copy(tail[:], salt)
		k ^= binary.LittleEndian.Uint64(tail[:])
	}
	return k
}

// check returns nil if the salt is fresh (and records it), or errReplay if
// it was seen within the window.
func (f *replayFilter) check(salt []byte) error {
	if f == nil || f.window <= 0 {
		return nil
	}
	k := key(salt)
	now := f.now()
	cutoff := now.Add(-f.window)

	f.mu.Lock()
	defer f.mu.Unlock()

	if ts, ok := f.seen[k]; ok && ts.After(cutoff) {
		return errReplay
	}

	// Opportunistic eviction of expired entries so the map doesn't grow
	// without bound during steady traffic.
	if len(f.seen) >= f.max {
		f.evictLocked(cutoff)
	}
	f.seen[k] = now
	return nil
}

func (f *replayFilter) evictLocked(cutoff time.Time) {
	for k, ts := range f.seen {
		if ts.Before(cutoff) {
			delete(f.seen, k)
		}
	}
	// If still over the cap (many fresh salts inside the window), drop
	// arbitrary entries down to half. This shortens the effective window
	// for the dropped keys but can't admit a replay that's still tracked.
	if len(f.seen) >= f.max {
		target := f.max / 2
		for k := range f.seen {
			if len(f.seen) <= target {
				break
			}
			delete(f.seen, k)
		}
	}
}

// size reports the current number of tracked salts (test helper).
func (f *replayFilter) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}
