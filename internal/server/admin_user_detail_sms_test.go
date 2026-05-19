package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// /admin/users/detail should surface the user's SMS history so support
// can answer "what messages did we send them" without page-hopping.
func TestAdminUserDetailRendersSMSLogs(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800350001", "h")
	_ = app.DB.LogSMS(ctx, "console", "13800350001", "your verification code is 123456", true, "")
	_ = app.DB.LogSMS(ctx, "console", "13800350001", "your service expires in 3 days", false, "upstream timeout")
	// Unrelated user's row — should NOT appear in this detail page.
	_ = app.DB.LogSMS(ctx, "console", "13800350002", "should not appear", true, "")

	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/users/detail?id="+strconv.FormatInt(u.ID, 10), nil, jar)

	if !strings.Contains(body, "your verification code is 123456") {
		t.Error("OK SMS should appear")
	}
	if !strings.Contains(body, "your service expires in 3 days") {
		t.Error("FAIL SMS should appear")
	}
	if strings.Contains(body, "should not appear") {
		t.Error("other user's SMS leaked into detail page")
	}
	// Link to filtered sms-log.
	if !strings.Contains(body, "/admin/sms-log?phone=13800350001") {
		t.Error("page should link to the user-filtered sms-log view")
	}
	// FAIL row should render with the FAIL pill + error tooltip.
	if !strings.Contains(body, `title="upstream timeout"`) {
		t.Error("FAIL row should expose error_msg via title attribute")
	}
}

// User with no SMS history: section is hidden (no empty card noise).
func TestAdminUserDetailHidesSMSSectionWhenEmpty(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()
	u, _ := app.DB.CreateUser(ctx, "13800350010", "h")
	h := app.Routes()
	jar := loginAdmin(t, h)
	_, body := do(t, h, "GET", "/admin/users/detail?id="+strconv.FormatInt(u.ID, 10), nil, jar)
	if strings.Contains(body, "最近 30 条 SMS 投递") {
		t.Error("SMS section should be hidden when there are no rows")
	}
}
