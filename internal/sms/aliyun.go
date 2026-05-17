package sms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // Aliyun SMS API mandates HMAC-SHA1 — not our choice.
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Aliyun is the Provider implementation for Aliyun (Alibaba Cloud) SMS.
//
// API reference: https://help.aliyun.com/document_detail/101414.html
//
// Aliyun SMS templates contain placeholders like ${code}. The `message`
// arg to Send is expected to be JSON-encoded template params, e.g.
//
//	{"code": "123456"}
//
// SignName + TemplateCode are baked into the adapter so the caller doesn't
// have to know which template they're hitting (one adapter per use case).
type Aliyun struct {
	AccessKeyID     string
	AccessKeySecret string
	SignName        string
	TemplateCode    string

	HTTPClient *http.Client
	Endpoint   string

	// Injectable for testing — defaults to real time.Now / crypto/rand.
	nowFn   func() time.Time
	nonceFn func() string
}

const aliyunEndpoint = "https://dysmsapi.aliyuncs.com"

// NewAliyun returns an Aliyun SMS provider ready to send. Set HTTPClient if
// you need to override the default 10s timeout.
func NewAliyun(accessKeyID, accessKeySecret, signName, templateCode string) *Aliyun {
	return &Aliyun{
		AccessKeyID:     accessKeyID,
		AccessKeySecret: accessKeySecret,
		SignName:        signName,
		TemplateCode:    templateCode,
		HTTPClient:      &http.Client{Timeout: 10 * time.Second},
		Endpoint:        aliyunEndpoint,
		nowFn:           func() time.Time { return time.Now().UTC() },
		nonceFn:         defaultNonce,
	}
}

func (a *Aliyun) Name() string { return "aliyun" }

// Send POSTs to dysmsapi.aliyuncs.com with the canonical-params signing.
// `message` should be JSON-encoded template params; if it's a plain string
// we wrap it as `{"code": "<string>"}` for the common code-template case.
func (a *Aliyun) Send(ctx context.Context, phone, message string) error {
	if a == nil {
		return ErrNotConfigured
	}
	if a.HTTPClient == nil {
		a.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if a.Endpoint == "" {
		a.Endpoint = aliyunEndpoint
	}

	// Normalise message into JSON template params.
	tmplParams := message
	if !looksLikeJSON(message) {
		b, _ := json.Marshal(map[string]string{"code": message})
		tmplParams = string(b)
	}

	now := a.nowFn()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nonce := a.nonceFn()
	if nonce == "" {
		nonce = defaultNonce()
	}

	params := map[string]string{
		// Common
		"AccessKeyId":      a.AccessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   nonce,
		"Timestamp":        now.UTC().Format("2006-01-02T15:04:05Z"),
		"Format":           "JSON",
		"Version":          "2017-05-25",
		// Business
		"Action":        "SendSms",
		"PhoneNumbers":  phone,
		"SignName":      a.SignName,
		"TemplateCode":  a.TemplateCode,
		"TemplateParam": tmplParams,
	}
	params["Signature"] = signAliyun("POST", "/", params, a.AccessKeySecret)

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("aliyun sms: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("aliyun sms: http %d: %s", resp.StatusCode, string(body))
	}
	var r struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("aliyun sms: parse response: %w; body=%s", err, string(body))
	}
	if r.Code != "OK" {
		return fmt.Errorf("aliyun sms: %s/%s (request_id=%s)", r.Code, r.Message, r.RequestID)
	}
	return nil
}

// --- signing helpers ---------------------------------------------------------

// signAliyun produces the Signature value per
// https://help.aliyun.com/document_detail/101343.html
//
//	StringToSign = HTTPMethod + "&" +
//	               percentEncode("/") + "&" +
//	               percentEncode(canonical-sorted-form-params-without-Signature)
//	Signature   = base64(HMAC-SHA1(StringToSign, AccessKeySecret + "&"))
//
// Aliyun uses RFC 3986 percent-encoding with a custom tweak: spaces are %20,
// asterisks are %2A, '~' is left as-is, and '+' is escaped as %20.
func signAliyun(method, canonicalURI string, params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(aliyunEscape(k))
		sb.WriteByte('=')
		sb.WriteString(aliyunEscape(params[k]))
	}
	canonical := sb.String()
	str2sign := method + "&" + aliyunEscape(canonicalURI) + "&" + aliyunEscape(canonical)
	mac := hmac.New(sha1.New, []byte(secret+"&")) //nolint:gosec // Aliyun mandates HMAC-SHA1
	mac.Write([]byte(str2sign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// aliyunEscape: RFC 3986 with Aliyun's small modifications.
func aliyunEscape(s string) string {
	esc := url.QueryEscape(s)
	// QueryEscape uses + for spaces; Aliyun wants %20.
	esc = strings.ReplaceAll(esc, "+", "%20")
	// QueryEscape doesn't touch * but Aliyun says encode it.
	esc = strings.ReplaceAll(esc, "*", "%2A")
	// QueryEscape encodes ~ as %7E; Aliyun wants raw ~.
	esc = strings.ReplaceAll(esc, "%7E", "~")
	return esc
}

func defaultNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func looksLikeJSON(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")
}
