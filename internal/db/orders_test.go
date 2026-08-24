package db

import (
	"context"
	"testing"
)

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
