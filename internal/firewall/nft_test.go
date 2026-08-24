package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

// Sync must be ONE atomic `nft -f -` invocation carrying both the flush
// and the repopulate — two separate invocations leave a window where the
// set is empty and every paid device gets portal-redirected.
func TestSyncIsSingleAtomicBatch(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	stdinFile := filepath.Join(dir, "stdin")
	fake := filepath.Join(dir, "fake-nft")
	script := "#!/bin/sh\necho \"$@\" >> " + argsFile + "\ncat >> " + stdinFile + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	m := New("inet", "billing", "mac_paid", "br-paid")
	m.NftBin = fake
	if err := m.Sync(context.Background(), []string{"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"}); err != nil {
		t.Fatal(err)
	}

	args, _ := os.ReadFile(argsFile)
	invocations := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(invocations) != 1 {
		t.Fatalf("want exactly 1 nft invocation, got %d: %v", len(invocations), invocations)
	}
	if strings.TrimSpace(invocations[0]) != "-f -" {
		t.Errorf("invocation = %q, want '-f -'", invocations[0])
	}
	stdin, _ := os.ReadFile(stdinFile)
	body := string(stdin)
	if !strings.Contains(body, "flush set inet billing mac_paid") {
		t.Errorf("script missing flush: %q", body)
	}
	if !strings.Contains(body, "add element inet billing mac_paid { AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66 }") {
		t.Errorf("script missing populate: %q", body)
	}
}

// Empty list still flushes (all MACs expired) in one batch.
func TestSyncEmptyListFlushesOnly(t *testing.T) {
	dir := t.TempDir()
	stdinFile := filepath.Join(dir, "stdin")
	fake := filepath.Join(dir, "fake-nft")
	script := "#!/bin/sh\ncat >> " + stdinFile + "\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	m := New("inet", "billing", "mac_paid", "br-paid")
	m.NftBin = fake
	if err := m.Sync(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	stdin, _ := os.ReadFile(stdinFile)
	if !strings.Contains(string(stdin), "flush set inet billing mac_paid") {
		t.Errorf("script missing flush: %q", string(stdin))
	}
	if strings.Contains(string(stdin), "add element") {
		t.Errorf("empty sync must not add elements: %q", string(stdin))
	}
}
