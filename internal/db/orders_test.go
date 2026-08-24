package db

import (
	"context"
	"testing"
)

func TestGetMACsIn(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:11:00:01", "one", 30, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:11:00:02", "two", 30, nil); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetMACsIn(ctx, []string{
		"AA:BB:CC:11:00:01", "AA:BB:CC:11:00:02", "AA:BB:CC:11:00:99", // last one unknown
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 hits; got %d", len(got))
	}
	if m := got["AA:BB:CC:11:00:01"]; m == nil || m.Label != "one" {
		t.Errorf("wrong row for :01: %+v", m)
	}
	if _, ok := got["AA:BB:CC:11:00:99"]; ok {
		t.Error("unknown MAC must not appear in result")
	}

	// Empty input: no query, empty map, no error.
	got, err = d.GetMACsIn(ctx, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty input: got %v, %v", got, err)
	}

	// Above the 500-per-chunk limit: exercise the chunked path.
	big := make([]string, 0, 1200)
	for i := 0; i < 1200; i++ {
		big = append(big, "DE:AD:00:00:"+string(rune('A'+i%26))+string(rune('A'+(i/26)%26))+":00")
	}
	big = append(big, "AA:BB:CC:11:00:01")
	got, err = d.GetMACsIn(ctx, big)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["AA:BB:CC:11:00:01"] == nil {
		t.Fatalf("chunked lookup should find exactly the one real MAC; got %d", len(got))
	}
}

func TestCountMACsByUser(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()

	u1, _ := d.CreateUser(ctx, "13800138001", "h")
	u2, _ := d.CreateUser(ctx, "13800138002", "h")
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:01", "", 30, &u1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:02", "", 30, &u1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:03", "", 30, &u2.ID); err != nil {
		t.Fatal(err)
	}
	// Ownerless MAC must not appear in the map.
	if _, err := d.UpsertMAC(ctx, "AA:BB:CC:00:00:04", "", 30, nil); err != nil {
		t.Fatal(err)
	}

	counts, err := d.CountMACsByUser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts[u1.ID] != 2 || counts[u2.ID] != 1 {
		t.Errorf("counts = %v, want {%d:2, %d:1}", counts, u1.ID, u2.ID)
	}
	if len(counts) != 2 {
		t.Errorf("unexpected extra entries: %v", counts)
	}
}
