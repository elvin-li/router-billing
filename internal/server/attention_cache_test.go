package server

import (
	"context"
	"testing"
	"time"
)

// TestAttentionCacheServesWithinTTL — a second call inside the TTL returns
// the cached counters without re-reading the DB (proved by mutating the DB
// between calls and seeing the stale value), and a call after the TTL
// expires picks up the change.
func TestAttentionCacheServesWithinTTL(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	// First read: clean install → all counters zero, cache primed.
	att := app.attention(ctx)
	if att.SuspendedUsers != 0 {
		t.Fatalf("fresh install should have 0 suspended users, got %d", att.SuspendedUsers)
	}

	// Mutate: suspend a user. A cached read must NOT see it yet.
	u, err := app.DB.CreateUser(ctx, "13800270001", "h")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.DB.SuspendUser(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if got := app.attention(ctx); got.SuspendedUsers != 0 {
		t.Errorf("within TTL the cached value should be served; got SuspendedUsers=%d", got.SuspendedUsers)
	}

	// Expire the cache and confirm the refresh sees the new state.
	app.attMu.Lock()
	app.attAt = time.Now().Add(-attentionCacheTTL - time.Second)
	app.attMu.Unlock()
	if got := app.attention(ctx); got.SuspendedUsers != 1 {
		t.Errorf("after TTL expiry the refresh should see SuspendedUsers=1; got %d", got.SuspendedUsers)
	}
}
