package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

// v0.126: a transient FW.Add failure during Extend surfaced as an error
// even though UpsertMAC had already committed — and because UpsertMAC
// stacks days on top of the current expiry, the caller's natural retry
// granted the days twice. Extend must self-heal (resync) and report the
// success it is.
func TestExtendSelfHealsOnFirewallFailure(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	fw.mu.Lock()
	fw.addErr = errors.New("nft timeout")
	fw.mu.Unlock()

	m, err := svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "x", 30, nil)
	if err != nil {
		t.Fatalf("extend must succeed once the DB committed; got %v", err)
	}
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("MAC should be in the fw set via the resync fallback")
	}
	wantExpiry := m.ExpiresAt

	// The old behavior provoked a retry — make sure a *not* retried
	// grant kept exactly 30 days (i.e. the error the caller used to see
	// was the only reason days ever stacked).
	got, _ := dbx.GetMAC(ctx, "AA:BB:CC:DD:EE:FF")
	if !got.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("expiry drifted: %v != %v", got.ExpiresAt, wantExpiry)
	}
	if until := time.Until(got.ExpiresAt); until > 31*24*time.Hour || until < 29*24*time.Hour {
		t.Errorf("expected ~30 days of validity; got %v", until)
	}
}

func TestExtendOwnedSelfHealsOnFirewallFailure(t *testing.T) {
	svc, dbx, fw := newTestSvc(t)
	ctx := context.Background()

	u, _ := dbx.CreateUser(ctx, "13800138000", "h")
	if _, err := svc.Extend(ctx, "AA:BB:CC:DD:EE:FF", "x", 30, &u.ID); err != nil {
		t.Fatal(err)
	}

	fw.mu.Lock()
	fw.addErr = errors.New("nft timeout")
	fw.mu.Unlock()

	if _, err := svc.ExtendOwned(ctx, "AA:BB:CC:DD:EE:FF", "", 30, u.ID); err != nil {
		t.Fatalf("extend-owned must succeed once the DB committed; got %v", err)
	}
	if !fw.set["AA:BB:CC:DD:EE:FF"] {
		t.Error("MAC should be in the fw set via the resync fallback")
	}
}
