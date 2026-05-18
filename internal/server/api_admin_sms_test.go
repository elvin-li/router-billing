package server

import (
	"context"
	"strings"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/sms"
)

func TestAPISMSSendDeliversAndAudits(t *testing.T) {
	app := setupTestApp(t)
	console := sms.NewConsole(50)
	app.SMS = &sms.Sender{P: console}
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_full", Label: "ops"}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/sms/send", "rb_full",
		`{"phone":"13800142000","message":"DB backup failed"}`)
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"sent"`) {
		t.Errorf("body: %s", rr.Body.String())
	}

	recs := console.Recent()
	if len(recs) != 1 || recs[0].Phone != "13800142000" || recs[0].Message != "DB backup failed" {
		t.Errorf("console didn't record send: %+v", recs)
	}

	entries, _ := app.DB.ListAudit(context.Background(), 50)
	found := false
	for _, e := range entries {
		if e.Action == "sms_test" && e.Target == "13800142000" {
			found = true
			if !strings.Contains(e.Detail, "via=api") {
				t.Errorf("audit detail should mention via=api; got %q", e.Detail)
			}
			if !strings.Contains(e.Actor, "api:") {
				t.Errorf("actor should start with api:; got %q", e.Actor)
			}
		}
	}
	if !found {
		t.Error("audit entry missing for api sms send")
	}
}

func TestAPISMSSendReadonlyTokenRejected(t *testing.T) {
	// Read-only tokens must NOT be able to send SMS.
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()

	rr := apiReq(t, h, "POST", "/api/admin/sms/send", "rb_ro",
		`{"phone":"13800142001","message":"x"}`)
	if rr.Code != 403 {
		t.Errorf("readonly should get 403; got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAPISMSSendBadPhone(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_full", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/sms/send", "rb_full",
		`{"phone":"abc","message":"x"}`)
	if rr.Code != 400 {
		t.Errorf("bad phone: %d", rr.Code)
	}
}

func TestAPISMSSendEmptyMessageRejected(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_full", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/sms/send", "rb_full",
		`{"phone":"13800142002","message":""}`)
	if rr.Code != 400 {
		t.Errorf("empty message: %d", rr.Code)
	}
}

func TestAPISMSSendNoProviderReturns503(t *testing.T) {
	app := setupTestApp(t)
	// app.SMS is the no-op Sender — Available()==false.
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_full", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/sms/send", "rb_full",
		`{"phone":"13800142003","message":"x"}`)
	if rr.Code != 503 {
		t.Errorf("no provider: %d", rr.Code)
	}
}

func TestAPISMSSendRejectsGET(t *testing.T) {
	app := setupTestApp(t)
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_full", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sms/send", "rb_full", "")
	if rr.Code != 405 {
		t.Errorf("GET should be 405; got %d", rr.Code)
	}
}
