package server

import (
	"context"
	"strings"
	"testing"
)

func TestDistinctAuditActorsReturnsSortedUnique(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin:bob", "login", "", "")
	app.DB.Audit(ctx, "admin:alice", "login", "", "")
	app.DB.Audit(ctx, "admin:bob", "grant", "AA:BB:CC:00:1E:01", "")
	app.DB.Audit(ctx, "user:13800360001", "login", "", "")

	actors, err := app.DB.DistinctAuditActors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"admin:bob":        true,
		"admin:alice":      true,
		"user:13800360001": true,
	}
	for _, a := range actors {
		delete(want, a)
	}
	if len(want) > 0 {
		t.Errorf("missing actors: %v; got %+v", want, actors)
	}
	// Sorted.
	for i := 1; i < len(actors); i++ {
		if actors[i-1] > actors[i] {
			t.Errorf("not sorted: %s > %s", actors[i-1], actors[i])
		}
	}
}

// /admin/audit should embed the distinct actors as a datalist for the
// actor input autocomplete.
func TestAdminAuditPageEmbedsActorDatalist(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	app.DB.Audit(ctx, "admin:autocomplete-test", "login", "", "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/audit", nil, jar)
	if !strings.Contains(body, `id="audit-actors"`) {
		t.Error("page should include the audit-actors datalist")
	}
	if !strings.Contains(body, "admin:autocomplete-test") {
		t.Error("seeded actor should appear as a datalist option")
	}
	// The input should reference the datalist.
	if !strings.Contains(body, `list="audit-actors"`) {
		t.Error("actor input should reference the datalist")
	}
}
