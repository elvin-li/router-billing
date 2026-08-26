package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// stubNft writes a shell script that impersonates the nft binary and returns
// its path. Lets us exercise run/runOut + output parsing without nftables.
func stubNft(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nft")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func stubbedManager(t *testing.T, script string) *Manager {
	t.Helper()
	m := New("inet", "billing", "mac_paid", "br-paid")
	m.NftBin = stubNft(t, script)
	return m
}

// List goes through `nft -j list set` JSON output. Regression guard for the
// pre-v0.107 text parser that anchored on the table's opening brace and
// silently dropped the first MAC of every listing.
func TestListParsesRealNftOutput(t *testing.T) {
	m := stubbedManager(t, `cat <<'EOF'
{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "mac_paid", "table": "billing", "type": "ether_addr", "handle": 3, "elem": [{"elem": {"val": "aa:bb:cc:dd:ee:ff", "counter": {"packets": 4, "bytes": 260}}}, {"elem": {"val": "11:22:33:44:55:66", "counter": {"packets": 0, "bytes": 0}}}], "stmt": [{"counter": null}]}}]}
EOF`)
	got, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"} // uppercase, sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List:\n got  %+v\n want %+v", got, want)
	}
}

// A single-element set must survive the round trip intact.
func TestListSingleElement(t *testing.T) {
	m := stubbedManager(t, `cat <<'EOF'
{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"set": {"family": "inet", "name": "mac_paid", "table": "billing", "type": "ether_addr", "elem": ["aa:bb:cc:dd:ee:ff"]}}]}
EOF`)
	got, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"AA:BB:CC:DD:EE:FF"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List:\n got  %+v\n want %+v", got, want)
	}
}

// Empty set: nft emits the set object without an "elem" key.
func TestListEmptySet(t *testing.T) {
	m := stubbedManager(t, `cat <<'EOF'
{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"set": {"family": "inet", "name": "mac_paid", "table": "billing", "type": "ether_addr"}}]}
EOF`)
	got, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("empty set should list nothing; got %+v", got)
	}
}

func TestListPropagatesExecError(t *testing.T) {
	m := stubbedManager(t, `echo "Error: No such file or directory" >&2; exit 1`)
	if _, err := m.List(context.Background()); err == nil {
		t.Error("List should surface nft failure")
	}
}

// EnsureSet first tries `{ type ether_addr; counter; }`; on old kernels that
// reject the counter flag it must fall back to the plain set.
func TestEnsureSetFallsBackWithoutCounter(t *testing.T) {
	m := stubbedManager(t, `case "$*" in
  *counter*) echo "Error: syntax error, unexpected counter" >&2; exit 1;;
esac
exit 0`)
	if err := m.EnsureSet(context.Background()); err != nil {
		t.Errorf("EnsureSet should fall back to plain set: %v", err)
	}
}

func TestEnsureSetTreatsExistingSetAsSuccess(t *testing.T) {
	m := stubbedManager(t, `case "$*" in
  "add table"*) exit 0;;
  *) echo "Error: set already exists" >&2; exit 1;;
esac`)
	if err := m.EnsureSet(context.Background()); err != nil {
		t.Errorf("existing set should not error: %v", err)
	}
}

func TestEnsureSetSurfacesRealFailure(t *testing.T) {
	m := stubbedManager(t, `echo "Error: Operation not permitted" >&2; exit 1`)
	if err := m.EnsureSet(context.Background()); err == nil {
		t.Error("hard nft failure should propagate")
	}
}

// Add/Remove are documented idempotent: duplicate add and missing delete are
// swallowed, anything else propagates.
func TestAddRemoveIdempotency(t *testing.T) {
	ctx := context.Background()

	dup := stubbedManager(t, `echo "Error: Could not process rule: File exists" >&2; exit 1`)
	if err := dup.Add(ctx, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("duplicate add should be nil: %v", err)
	}

	missing := stubbedManager(t, `echo "Error: Could not process rule: No such file or directory" >&2; exit 1`)
	if err := missing.Remove(ctx, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("removing absent element should be nil: %v", err)
	}

	hard := stubbedManager(t, `echo "Error: Operation not permitted" >&2; exit 1`)
	if err := hard.Add(ctx, "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Error("hard add failure should propagate")
	}
	if err := hard.Remove(ctx, "AA:BB:CC:DD:EE:FF"); err == nil {
		t.Error("hard remove failure should propagate")
	}
}

func TestCountersViaExec(t *testing.T) {
	m := stubbedManager(t, `cat <<'EOF'
{"nftables":[{"metainfo":{}},{"set":{"family":"inet","table":"billing","name":"mac_paid","type":"ether_addr","elem":[{"elem":{"val":"aa:bb:cc:dd:ee:ff","counter":{"packets":9,"bytes":512}}}]}}]}
EOF`)
	got, err := m.Counters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, ok := got["AA:BB:CC:DD:EE:FF"]
	if !ok || c.Packets != 9 || c.Bytes != 512 {
		t.Errorf("Counters = %+v", got)
	}
}

func TestWalledGardenOpsViaExec(t *testing.T) {
	ctx := context.Background()
	// Success path.
	ok := stubbedManager(t, `exit 0`)
	if err := ok.EnsureWalledGardenSet(ctx, "wg_paid"); err != nil {
		t.Errorf("EnsureWalledGardenSet: %v", err)
	}
	if err := ok.SyncWalledGardenIPs(ctx, "wg_paid", []string{"1.1.1.1", "2.2.2.2"}); err != nil {
		t.Errorf("SyncWalledGardenIPs: %v", err)
	}
	// Empty list still execs (flush-only transaction drains the set).
	if err := ok.SyncWalledGardenIPs(ctx, "wg_paid", nil); err != nil {
		t.Errorf("empty sync should succeed: %v", err)
	}
	// Hard nft failures propagate.
	boom := stubbedManager(t, `echo "Error: Operation not permitted" >&2; exit 1`)
	if err := boom.SyncWalledGardenIPs(ctx, "wg_paid", []string{"1.1.1.1"}); err == nil {
		t.Error("hard wg sync failure should propagate")
	}
}

func TestErrorClassifiers(t *testing.T) {
	if isExistsError(nil) || isNotFoundError(nil) {
		t.Error("nil error must classify as neither")
	}
	for _, msg := range []string{"nft add: File exists", "Error: set already exists"} {
		if !isExistsError(errors.New(msg)) {
			t.Errorf("%q should be an exists-error", msg)
		}
	}
	for _, msg := range []string{"No such file or directory", "element does not exist", "set not found"} {
		if !isNotFoundError(errors.New(msg)) {
			t.Errorf("%q should be a not-found error", msg)
		}
	}
	if isExistsError(errors.New("Operation not permitted")) ||
		isNotFoundError(errors.New("Operation not permitted")) {
		t.Error("unrelated errors must not be swallowed")
	}
}
