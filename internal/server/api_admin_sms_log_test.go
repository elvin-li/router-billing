package server

import (
	"context"
	"encoding/json"
	"testing"

	"router-billing/internal/config"
	"router-billing/internal/sms"
)

func TestAPISMSLogReturnsRecent(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}

	for _, msg := range []string{"first", "second", "third"} {
		_ = app.SendSMS(context.Background(), "13800200001", msg)
	}

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sms/log", "rb_w", "")
	if rr.Code != 200 {
		t.Fatalf("status: %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Logs []struct {
			Provider string `json:"provider"`
			Phone    string `json:"phone"`
			Message  string `json:"message"`
			Success  bool   `json:"success"`
		} `json:"logs"`
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count < 3 || len(resp.Logs) < 3 {
		t.Fatalf("expected at least 3 logs; got count=%d len=%d", resp.Count, len(resp.Logs))
	}
	// Newest first.
	if resp.Logs[0].Message != "third" {
		t.Errorf("expected newest-first ordering; got %q first", resp.Logs[0].Message)
	}
	if resp.Logs[0].Provider != "console" || !resp.Logs[0].Success {
		t.Errorf("provider/success not captured: %+v", resp.Logs[0])
	}
}

func TestAPISMSLogLimitRespected(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.SMS = &sms.Sender{P: sms.NewConsole(50)}
	for i := 0; i < 25; i++ {
		_ = app.SendSMS(context.Background(), "13800200002", "spam")
	}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sms/log?limit=5", "rb_w", "")
	var resp struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Count != 5 {
		t.Errorf("limit=5 should yield 5 logs; got %d", resp.Count)
	}
}

func TestAPISMSLogReadonlyAllowed(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_ro", Label: "monitor", ReadOnly: true}}
	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sms/log", "rb_ro", "")
	if rr.Code != 200 {
		t.Errorf("readonly GET should be 200; got %d", rr.Code)
	}
}

func TestAPISMSLogRejectsPOST(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	h := app.Routes()
	rr := apiReq(t, h, "POST", "/api/admin/sms/log", "rb_w", "")
	if rr.Code != 405 {
		t.Errorf("POST should be 405; got %d", rr.Code)
	}
}

// Failure rows must be visible too — the whole point of the API is
// catching FAIL streaks. Anti-regression that the success bool is wired.
func TestAPISMSLogIncludesFailures(t *testing.T) {
	app := setupTestApp(t)
	app.Cfg.APITokens = []config.APIToken{{Token: "rb_w", Label: "ops"}}
	app.SMS = &sms.Sender{P: &failingProvider{msg: "creds expired"}}
	_ = app.SendSMS(context.Background(), "13800200003", "bound to fail")

	h := app.Routes()
	rr := apiReq(t, h, "GET", "/api/admin/sms/log", "rb_w", "")
	var resp struct {
		Logs []struct {
			Success  bool   `json:"success"`
			ErrorMsg string `json:"error_msg"`
		} `json:"logs"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Logs) == 0 {
		t.Fatal("expected at least one row")
	}
	if resp.Logs[0].Success {
		t.Error("first row should be marked failed")
	}
	if resp.Logs[0].ErrorMsg == "" {
		t.Error("error_msg should be populated for FAIL rows")
	}
}
