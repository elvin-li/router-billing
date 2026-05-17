package firewall

import (
	"context"
	"testing"
)

func TestValidMAC(t *testing.T) {
	good := []string{
		"AA:BB:CC:DD:EE:FF",
		"00:11:22:33:44:55",
		"ff:ee:dd:cc:bb:aa",
	}
	for _, m := range good {
		if !validMAC(m) {
			t.Errorf("validMAC(%q) = false, want true", m)
		}
	}
	bad := []string{
		"AA:BB:CC:DD:EE",
		"AA-BB-CC-DD-EE-FF",
		"AABBCCDDEEFF",
		"AA:BB:CC:DD:EE:GG",
		"",
		"not-a-mac-address",
	}
	for _, m := range bad {
		if validMAC(m) {
			t.Errorf("validMAC(%q) = true, want false", m)
		}
	}
}

func TestDryRunSync(t *testing.T) {
	m := New("inet", "billing", "mac_paid", "br-paid")
	m.SetDryRun(true)
	ctx := context.Background()
	// These would otherwise shell out; with dry-run they're just logged.
	if err := m.EnsureSet(ctx); err != nil {
		t.Errorf("EnsureSet: %v", err)
	}
	if err := m.Add(ctx, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("Add: %v", err)
	}
	if err := m.Remove(ctx, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("Remove: %v", err)
	}
	if err := m.Sync(ctx, []string{"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "bad"}); err != nil {
		t.Errorf("Sync: %v", err)
	}
}
