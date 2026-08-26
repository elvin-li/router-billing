package sms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAliyunSignatureDeterministic pins one canonical input → signature
// pair so any accidental change to the signing logic shows up immediately.
// Inputs match the worked example from Aliyun's signing doc style.
func TestAliyunSignatureDeterministic(t *testing.T) {
	params := map[string]string{
		"AccessKeyId":      "testid",
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     "13800138000",
		"SignName":         "AliyunSMS",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   "abc-fixed-nonce",
		"SignatureVersion": "1.0",
		"TemplateCode":     "SMS_1001",
		"TemplateParam":    `{"code":"123456"}`,
		"Timestamp":        "2025-01-01T00:00:00Z",
		"Version":          "2017-05-25",
	}
	got := signAliyun("POST", "/", params, "testsecret")
	// Pinned; if you intentionally change signAliyun, regenerate this with
	// `go test -run=Deterministic -v` once and paste the new value back in.
	// Captured from this implementation. If you intentionally change the
	// signing logic, regenerate by running this test, copying the `got`
	// value here, and re-running. A change to the canonical string format
	// or HMAC alphabet → this drifts immediately, which is the point.
	const want = "Tyr+aXwY2MpVRTeW4+n2mcHNUpM="
	if got != want {
		t.Errorf("signature drift\n got  %s\n want %s", got, want)
	}
}

func TestAliyunEscapeFollowsSpec(t *testing.T) {
	cases := map[string]string{
		"hello world":   "hello%20world", // space → %20, not +
		"a*b":           "a%2Ab",         // asterisk encoded
		"a~b":           "a~b",           // tilde left alone
		`{"code":"42"}`: "%7B%22code%22%3A%2242%22%7D",
		"":              "",
	}
	for in, want := range cases {
		if got := aliyunEscape(in); got != want {
			t.Errorf("escape(%q)\n got  %q\n want %q", in, got, want)
		}
	}
}

func TestAliyunSendHitsEndpoint(t *testing.T) {
	got := struct {
		method, contentType, action, phone, signName, tmplCode, tmplParam string
		hasSignature                                                      bool
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got.method = r.PostFormValue("Action")
		got.contentType = r.Header.Get("Content-Type")
		got.action = r.PostFormValue("Action")
		got.phone = r.PostFormValue("PhoneNumbers")
		got.signName = r.PostFormValue("SignName")
		got.tmplCode = r.PostFormValue("TemplateCode")
		got.tmplParam = r.PostFormValue("TemplateParam")
		got.hasSignature = r.PostFormValue("Signature") != ""
		_, _ = w.Write([]byte(`{"Code":"OK","Message":"OK","RequestId":"req-1","BizId":"biz-1"}`))
	}))
	defer srv.Close()

	a := NewAliyun("ak", "secret", "MyApp", "SMS_TEMPLATE")
	a.Endpoint = srv.URL
	a.nowFn = func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) }
	a.nonceFn = func() string { return "fixed-nonce" }

	if err := a.Send(context.Background(), "13800138000", "123456"); err != nil {
		t.Fatal(err)
	}

	if got.action != "SendSms" {
		t.Errorf("action = %q", got.action)
	}
	if got.phone != "13800138000" {
		t.Errorf("phone = %q", got.phone)
	}
	if got.signName != "MyApp" {
		t.Errorf("signName = %q", got.signName)
	}
	if got.tmplCode != "SMS_TEMPLATE" {
		t.Errorf("template code = %q", got.tmplCode)
	}
	// Plain "123456" gets wrapped as {"code":"123456"}.
	if !strings.Contains(got.tmplParam, `"code":"123456"`) {
		t.Errorf("template param = %q", got.tmplParam)
	}
	if !got.hasSignature {
		t.Error("Signature field missing")
	}
	if !strings.HasPrefix(got.contentType, "application/x-www-form-urlencoded") {
		t.Errorf("content-type = %q", got.contentType)
	}
}

func TestAliyunSendPassesJSONThrough(t *testing.T) {
	gotParam := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotParam = r.PostFormValue("TemplateParam")
		_, _ = w.Write([]byte(`{"Code":"OK","Message":"OK","RequestId":"r"}`))
	}))
	defer srv.Close()

	a := NewAliyun("ak", "secret", "MyApp", "T1")
	a.Endpoint = srv.URL
	a.nowFn = func() time.Time { return time.Now() }
	a.nonceFn = func() string { return "n" }

	// Looks-like-JSON → use as-is.
	if err := a.Send(context.Background(), "1", `{"code":"42","name":"Alice"}`); err != nil {
		t.Fatal(err)
	}
	if gotParam != `{"code":"42","name":"Alice"}` {
		t.Errorf("template param = %q", gotParam)
	}
}

func TestAliyunSendReturnsErrorOnAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Code":"isv.SMS_TEMPLATE_ILLEGAL","Message":"bad template","RequestId":"r"}`))
	}))
	defer srv.Close()

	a := NewAliyun("ak", "secret", "MyApp", "BAD")
	a.Endpoint = srv.URL
	a.nowFn = func() time.Time { return time.Now() }
	a.nonceFn = func() string { return "n" }

	err := a.Send(context.Background(), "1", "x")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "SMS_TEMPLATE_ILLEGAL") {
		t.Errorf("error doesn't surface upstream code: %v", err)
	}
}

func TestAliyunNameAndDefaults(t *testing.T) {
	a := NewAliyun("ak", "sec", "S", "T")
	if a.Name() != "aliyun" {
		t.Errorf("name = %q", a.Name())
	}
	if a.Endpoint != aliyunEndpoint {
		t.Errorf("default endpoint = %q", a.Endpoint)
	}
	if a.HTTPClient == nil || a.HTTPClient.Timeout <= 0 {
		t.Error("HTTPClient defaults missing")
	}
}

func TestAliyunZeroValueSendDoesNotPanic(t *testing.T) {
	// A literal &Aliyun{...} (bypassing NewAliyun) leaves nowFn/nonceFn
	// nil — pre-v0.108 Send dereferenced them unguarded and the panic
	// escaped in whatever background goroutine sent the SMS, killing the
	// whole process.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Code":"OK","Message":"","RequestId":"r"}`))
	}))
	t.Cleanup(srv.Close)

	a := &Aliyun{
		AccessKeyID:     "ak",
		AccessKeySecret: "sec",
		SignName:        "S",
		TemplateCode:    "T",
		Endpoint:        srv.URL,
	}
	if err := a.Send(context.Background(), "13800138000", "1234"); err != nil {
		t.Fatalf("zero-value Send: %v", err)
	}
}

func TestAliyunConcurrentSendsNoRace(t *testing.T) {
	// Send is invoked concurrently in production (expiry-reminder loop,
	// digest loop, login-alert goroutines). The old lazy `a.HTTPClient =`
	// / `a.Endpoint =` writes inside Send were a data race — run under
	// `go test -race` this test pins the fix.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Code":"OK","Message":"","RequestId":"r"}`))
	}))
	t.Cleanup(srv.Close)

	a := &Aliyun{
		AccessKeyID:     "ak",
		AccessKeySecret: "sec",
		SignName:        "S",
		TemplateCode:    "T",
		Endpoint:        srv.URL,
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.Send(context.Background(), "13800138000", "1234"); err != nil {
				t.Errorf("concurrent Send: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestLooksLikeJSON(t *testing.T) {
	yes := []string{`{"a":1}`, `  { "x": "y" }  `, "{}"}
	no := []string{"", "abc", "[1,2]", "{abc"}
	for _, s := range yes {
		if !looksLikeJSON(s) {
			t.Errorf("looksLikeJSON(%q) = false", s)
		}
	}
	for _, s := range no {
		if looksLikeJSON(s) {
			t.Errorf("looksLikeJSON(%q) = true", s)
		}
	}
}
