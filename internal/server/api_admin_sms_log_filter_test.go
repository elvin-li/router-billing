package server

import (
	"context"
	"encoding/json"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/sms"
)

func TestAPISMSLogFilterByPhone(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}

	_ = app.SendSMS(context.Background(), "13800210001", "for-A-1")
	_ = app.SendSMS(context.Background(), "13800210002", "for-B-1")
	_ = app.SendSMS(context.Background(), "13800210001", "for-A-2")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sms/log?phone=13800210001", "rb_w", "")
	var resp struct {
		Logs []struct {
			Phone   string `json:"phone"`
			Message string `json:"message"`
		} `json:"logs"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Logs) != 2 {
		t.Errorf("expected 2 rows for that phone; got %d", len(resp.Logs))
	}
	for _, l := range resp.Logs {
		if l.Phone != "13800210001" {
			t.Errorf("filter leaked other phone: %+v", l)
		}
	}
}

func TestAPISMSLogFilterOnlyFailed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}

	// Mix success + failure rows.
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	_ = app.SendSMS(context.Background(), "13800210010", "ok-row-1")
	_ = app.SendSMS(context.Background(), "13800210010", "ok-row-2")
	app.SMS = &sms.Sender{P: &failingProvider{msg: "boom"}}
	_ = app.SendSMS(context.Background(), "13800210010", "fail-row-1")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sms/log?only_failed=1", "rb_w", "")
	var resp struct {
		Logs []struct {
			Message string `json:"message"`
			Success bool   `json:"success"`
		} `json:"logs"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Logs) != 1 {
		t.Errorf("expected only the 1 failure; got %d", len(resp.Logs))
	}
	if resp.Logs[0].Success {
		t.Error("filter let a success row through")
	}
	if resp.Logs[0].Message != "fail-row-1" {
		t.Errorf("unexpected row content: %q", resp.Logs[0].Message)
	}
}

// Compose filters: phone + only_failed together must intersect.
func TestAPISMSLogFilterCompose(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	_ = app.SendSMS(context.Background(), "13800210020", "ok-for-A")
	app.SMS = &sms.Sender{P: &failingProvider{msg: "boom"}}
	_ = app.SendSMS(context.Background(), "13800210020", "fail-for-A")
	_ = app.SendSMS(context.Background(), "13800210021", "fail-for-B")

	h := app.Routes()
	rr := apiReq(t, h, "GET",
		"/api/admin/sms/log?phone=13800210020&only_failed=1", "rb_w", "")
	var resp struct {
		Logs []struct {
			Phone   string `json:"phone"`
			Message string `json:"message"`
			Success bool   `json:"success"`
		} `json:"logs"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Logs) != 1 {
		t.Errorf("compose filter: expected 1; got %d", len(resp.Logs))
	}
	if len(resp.Logs) > 0 {
		l := resp.Logs[0]
		if l.Phone != "13800210020" || l.Success || l.Message != "fail-for-A" {
			t.Errorf("compose filter returned wrong row: %+v", l)
		}
	}
}
