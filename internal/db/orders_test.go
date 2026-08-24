package db

import (
	"context"
	"testing"

	"router-billing/internal/models"
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

func TestLatestPaidOrderForMAC(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	mac := "AA:BB:CC:DD:EE:FF"

	// No orders yet → nil, no error.
	o, err := d.LatestPaidOrderForMAC(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if o != nil {
		t.Fatalf("expected nil for MAC with no orders; got %+v", o)
	}

	mkOrder := func(no string) *models.Order {
		ord := &models.Order{
			OrderNo: no, Mac: mac, Plan: "month", Days: 30,
			AmountCents: 100, Status: models.OrderPending, PaymentMethod: "wechat",
		}
		if err := d.CreateOrder(ctx, ord); err != nil {
			t.Fatal(err)
		}
		return ord
	}

	mkOrder("B-pending") // stays pending — must never surface
	mkOrder("B-paid-1")
	mkOrder("B-paid-2")
	if _, _, err := d.MarkOrderPaid(ctx, "B-paid-1", "trade-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.MarkOrderPaid(ctx, "B-paid-2", "trade-2"); err != nil {
		t.Fatal(err)
	}

	o, err = d.LatestPaidOrderForMAC(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if o == nil || o.OrderNo != "B-paid-2" {
		t.Fatalf("want latest paid B-paid-2; got %+v", o)
	}

	// Other MACs don't leak in.
	o, err = d.LatestPaidOrderForMAC(ctx, "11:22:33:44:55:66")
	if err != nil {
		t.Fatal(err)
	}
	if o != nil {
		t.Fatalf("unexpected order for foreign MAC: %+v", o)
	}
}
