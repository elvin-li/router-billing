package firewall

import (
	"context"
	"testing"
)

func TestEnsureInputAcceptDryRun(t *testing.T) {
	m := New("inet", "billing", "mac_paid", "br-lan")
	m.SetDryRun(true)
	if err := m.EnsureInputAccept(context.Background(), "ss_in", "br-lan", 8388); err != nil {
		t.Fatalf("EnsureInputAccept dry-run: %v", err)
	}
	// No iface scope is allowed too.
	if err := m.EnsureInputAccept(context.Background(), "ss_in", "", 8388); err != nil {
		t.Fatalf("EnsureInputAccept no-iface: %v", err)
	}
}

func TestEnsureInputAcceptRejectsBadInput(t *testing.T) {
	m := New("inet", "billing", "mac_paid", "br-lan")
	m.SetDryRun(true)
	ctx := context.Background()
	if err := m.EnsureInputAccept(ctx, "ss_in", "br-lan", 0); err == nil {
		t.Error("expected error for port 0")
	}
	if err := m.EnsureInputAccept(ctx, "ss_in", "br-lan", 70000); err == nil {
		t.Error("expected error for port > 65535")
	}
	if err := m.EnsureInputAccept(ctx, "bad chain!", "br-lan", 8388); err == nil {
		t.Error("expected error for invalid chain name")
	}
	if err := m.EnsureInputAccept(ctx, "ss_in", "bad iface;rm -rf", 8388); err == nil {
		t.Error("expected error for invalid iface")
	}
}

func TestValidTokens(t *testing.T) {
	if !validChainToken("ss_in") || validChainToken("has space") || validChainToken("") {
		t.Error("validChainToken wrong")
	}
	if !validIfaceToken("br-lan") || !validIfaceToken("eth0.10") || validIfaceToken("no;semi") {
		t.Error("validIfaceToken wrong")
	}
}
