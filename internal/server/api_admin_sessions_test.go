package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"router-billing/internal/config"
)

func TestAPISessionsListsActive(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()

	// Seed one admin + one user session.
	_ = app.DB.CreateSession(ctx, "tok-a", "admin", "alice", nil, time.Hour)
	u, _ := app.DB.CreateUser(ctx, "13800380001", "h")
	_ = app.DB.CreateSession(ctx, "tok-b", "user", u.Phone, &u.ID, time.Hour)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sessions", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Sessions []struct {
			Kind    string `json:"kind"`
			Subject string `json:"subject"`
		} `json:"sessions"`
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count < 2 {
		t.Errorf("expected at least 2 sessions; got %d", resp.Count)
	}
}

func TestAPISessionsKindFilter(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	_ = app.DB.CreateSession(ctx, "tok-a2", "admin", "bob", nil, time.Hour)
	u, _ := app.DB.CreateUser(ctx, "13800380002", "h")
	_ = app.DB.CreateSession(ctx, "tok-b2", "user", u.Phone, &u.ID, time.Hour)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sessions?kind=admin", "rb_w", "")
	var resp struct {
		Sessions []struct {
			Kind string `json:"kind"`
		} `json:"sessions"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, s := range resp.Sessions {
		if s.Kind != "admin" {
			t.Errorf("filter let non-admin through: %+v", s)
		}
	}
}

// Critical anti-leak: response must NEVER include the session token.
func TestAPISessionsNeverLeaksToken(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	ctx := context.Background()
	leakyTok := "this-token-must-not-leak-ever-1234"
	_ = app.DB.CreateSession(ctx, leakyTok, "admin", "alice", nil, time.Hour)

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sessions", "rb_w", "")
	if strings.Contains(rr.Body.String(), leakyTok) {
		t.Errorf("response leaks session token! body=%s", rr.Body.String())
	}
}

func TestAPISessionsBadKindIs400(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sessions?kind=guest", "rb_w", "")
	if rr.Code != 400 {
		t.Errorf("unknown kind should be 400; got %d", rr.Code)
	}
}

func TestAPISessionsReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sessions", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly should be 200; got %d", rr.Code)
	}
}
