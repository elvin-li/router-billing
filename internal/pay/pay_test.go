package pay

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- helpers -----------------------------------------------------------------

// writePEMKey makes a fresh RSA key, writes PKCS#8 private + PKIX public PEMs
// to a tmp dir, and returns (privPath, pubPath, *rsa.PrivateKey).
func writePEMKey(t *testing.T) (privPath, pubPath string, k *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privPath = filepath.Join(dir, "priv.pem")
	pubPath = filepath.Join(dir, "pub.pem")

	privBytes, _ := x509.MarshalPKCS8PrivateKey(k)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)

	if err := os.WriteFile(privPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), 0o600); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath, k
}

// --- randomHex ---------------------------------------------------------------

func TestRandomHexLengthAndAlphabet(t *testing.T) {
	for _, n := range []int{1, 8, 16, 32} {
		got := randomHex(n)
		if len(got) != n*2 {
			t.Errorf("randomHex(%d) len=%d; want %d", n, len(got), n*2)
		}
		for _, c := range got {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("non-hex char %q in %s", c, got)
				break
			}
		}
	}
}

// --- WeChat authHeader -------------------------------------------------------

func TestWeChatAuthHeaderFormat(t *testing.T) {
	privPath, _, _ := writePEMKey(t)
	w, err := NewWeChat("MCH123", "wx-app", "abcd-api-v3-key-32chars-padding!", "SERIAL-9", privPath, "http://x")
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := w.authHeader("POST", "/v3/pay/transactions/native", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hdr, "WECHATPAY2-SHA256-RSA2048 ") {
		t.Errorf("wrong scheme prefix: %s", hdr)
	}
	for _, want := range []string{
		`mchid="MCH123"`,
		`serial_no="SERIAL-9"`,
		`nonce_str="`, // followed by 32 hex chars
		`timestamp="`, // followed by unix seconds
		`signature="`, // followed by base64 RSA-SHA256
	} {
		if !strings.Contains(hdr, want) {
			t.Errorf("header missing %q\n→ %s", want, hdr)
		}
	}
}

// --- WeChat AES-GCM notify decode --------------------------------------------

// craftWxNotifyEnvelope builds a valid v3 notification envelope using the
// provided APIv3 key. Mirrors the WeChat server behavior.
func craftWxNotifyEnvelope(t *testing.T, apiV3Key []byte, mchID, appID string) []byte {
	t.Helper()
	res := wxNotifyResource{
		MchID: mchID, AppID: appID, OutTradeNo: "B123456",
		TransactionID: "WX-TX-001", TradeState: "SUCCESS",
	}
	plain, _ := json.Marshal(res)

	nonce := []byte("123456789012") // 12 bytes
	assoc := []byte("transaction")

	block, _ := aes.NewCipher(apiV3Key)
	aead, _ := cipher.NewGCM(block)
	ct := aead.Seal(nil, nonce, plain, assoc)

	env := wxNotifyEnvelope{
		ID: "ev-1", EventType: "TRANSACTION.SUCCESS", ResourceType: "encrypt-resource",
	}
	env.Resource.Algorithm = "AEAD_AES_256_GCM"
	env.Resource.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	env.Resource.Nonce = string(nonce)
	env.Resource.AssociatedData = string(assoc)
	body, _ := json.Marshal(env)
	return body
}

func TestWeChatDecodeNotifyRoundtrip(t *testing.T) {
	privPath, _, _ := writePEMKey(t)
	apiV3 := []byte("01234567890123456789012345678901") // 32 bytes
	w, _ := NewWeChat("MCH-X", "APP-Y", string(apiV3), "S", privPath, "http://x")

	body := craftWxNotifyEnvelope(t, apiV3, "MCH-X", "APP-Y")
	notice, err := w.DecodeNotify(body)
	if err != nil {
		t.Fatal(err)
	}
	if notice.OrderNo != "B123456" || notice.TradeNo != "WX-TX-001" || notice.Provider != "wechat" {
		t.Errorf("notice mismatch: %+v", notice)
	}
}

func TestWeChatDecodeNotifyRejectsForeignMchOrApp(t *testing.T) {
	privPath, _, _ := writePEMKey(t)
	apiV3 := []byte("01234567890123456789012345678901")
	w, _ := NewWeChat("MCH-X", "APP-Y", string(apiV3), "S", privPath, "http://x")

	body := craftWxNotifyEnvelope(t, apiV3, "OTHER-MCH", "APP-Y")
	if _, err := w.DecodeNotify(body); err == nil {
		t.Error("expected mismatched mchid to fail")
	}
}

func TestWeChatDecodeNotifyRejectsBadKey(t *testing.T) {
	privPath, _, _ := writePEMKey(t)
	good := []byte("01234567890123456789012345678901")
	bad := []byte("99999999999999999999999999999999")

	w, _ := NewWeChat("M", "A", string(bad), "S", privPath, "http://x")
	body := craftWxNotifyEnvelope(t, good, "M", "A")
	if _, err := w.DecodeNotify(body); err == nil {
		t.Error("expected AEAD failure for wrong key")
	}
}

// --- Alipay sign() / DecodeNotify -------------------------------------------

func TestAlipaySignDeterministic(t *testing.T) {
	privPath, pubPath, _ := writePEMKey(t)
	a, err := NewAlipay("ali-app", privPath, pubPath, "http://x", "")
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]string{
		"app_id":      "ali-app",
		"method":      "alipay.trade.precreate",
		"timestamp":   "2025-01-01 12:00:00",
		"biz_content": `{"out_trade_no":"O1"}`,
		"":            "skip-empty-value-key", // empty value → skipped
	}
	s1, err := a.sign(params)
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := a.sign(params)
	if s1 != s2 {
		t.Error("sign should be deterministic for same input")
	}
	if _, err := base64.StdEncoding.DecodeString(s1); err != nil {
		t.Errorf("signature should be base64: %v", err)
	}
}

func TestAlipayDecodeNotifyRoundtrip(t *testing.T) {
	privPath, pubPath, k := writePEMKey(t)
	a, err := NewAlipay("ali-app-42", privPath, pubPath, "http://x", "")
	if err != nil {
		t.Fatal(err)
	}

	// Build a form that mimics what Alipay would POST to /notify/ali.
	form := url.Values{}
	form.Set("app_id", "ali-app-42")
	form.Set("trade_status", "TRADE_SUCCESS")
	form.Set("out_trade_no", "ORDER-7")
	form.Set("trade_no", "ALI-TX-7")
	form.Set("notify_id", "n-1")
	form.Set("notify_time", "2025-01-01 00:00:00")
	form.Set("sign_type", "RSA2")

	// Compute the canonical sign-base ourselves and produce sign with k.
	signBase := canonicalForSigning(form)
	h := sha256.Sum256([]byte(signBase))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	form.Set("sign", base64.StdEncoding.EncodeToString(sig))

	notice, err := a.DecodeNotify(form)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if notice.OrderNo != "ORDER-7" || notice.TradeNo != "ALI-TX-7" || notice.Provider != "alipay" {
		t.Errorf("notice mismatch: %+v", notice)
	}
}

func TestAlipayDecodeNotifyRejectsBadSig(t *testing.T) {
	privPath, pubPath, _ := writePEMKey(t)
	a, _ := NewAlipay("ali-app-42", privPath, pubPath, "http://x", "")

	form := url.Values{}
	form.Set("app_id", "ali-app-42")
	form.Set("trade_status", "TRADE_SUCCESS")
	form.Set("out_trade_no", "x")
	form.Set("sign", base64.StdEncoding.EncodeToString([]byte("not-a-real-rsa-sig"))) // wrong size
	form.Set("sign_type", "RSA2")

	if _, err := a.DecodeNotify(form); err == nil {
		t.Error("expected bad signature to be rejected")
	}
}

func TestAlipayDecodeNotifyRejectsAppIdMismatch(t *testing.T) {
	privPath, pubPath, k := writePEMKey(t)
	a, _ := NewAlipay("OURS", privPath, pubPath, "http://x", "")

	form := url.Values{}
	form.Set("app_id", "SOMEONE-ELSE")
	form.Set("trade_status", "TRADE_SUCCESS")
	form.Set("out_trade_no", "O")
	form.Set("trade_no", "T")
	form.Set("sign_type", "RSA2")
	h := sha256.Sum256([]byte(canonicalForSigning(form)))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	form.Set("sign", base64.StdEncoding.EncodeToString(sig))

	if _, err := a.DecodeNotify(form); err == nil {
		t.Error("expected app_id mismatch to be rejected")
	}
}

// canonicalForSigning replicates the spec: all fields except sign + sign_type,
// sorted by key, joined with `=` / `&`.
func canonicalForSigning(form url.Values) string {
	keys := make([]string, 0, len(form))
	for k := range form {
		if k == "sign" || k == "sign_type" {
			continue
		}
		keys = append(keys, k)
	}
	// stable sort
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(form.Get(k))
	}
	return sb.String()
}

// --- Alipay Precreate against a fake gateway --------------------------------

func TestAlipayPrecreateHitsGateway(t *testing.T) {
	privPath, pubPath, _ := writePEMKey(t)
	got := struct {
		method      string
		contentType string
		bizContent  string
		signSeen    bool
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.PostFormValue("method")
		got.contentType = r.Header.Get("Content-Type")
		got.bizContent = r.PostFormValue("biz_content")
		got.signSeen = r.PostFormValue("sign") != ""
		_, _ = w.Write([]byte(`{"alipay_trade_precreate_response":{"code":"10000","msg":"Success","qr_code":"https://qr.alipay.com/bax01234","out_trade_no":"O1"}}`))
	}))
	defer srv.Close()

	a, _ := NewAlipay("ali", privPath, pubPath, "http://notify", srv.URL)
	res, err := a.Precreate(context.Background(), "O1", "test order", 100)
	if err != nil {
		t.Fatal(err)
	}
	if res.QRCode != "https://qr.alipay.com/bax01234" {
		t.Errorf("qr_code wrong: %q", res.QRCode)
	}
	if got.method != "alipay.trade.precreate" {
		t.Errorf("method = %q", got.method)
	}
	if !strings.HasPrefix(got.contentType, "application/x-www-form-urlencoded") {
		t.Errorf("content-type = %q", got.contentType)
	}
	if !got.signSeen {
		t.Error("expected sign param")
	}
	if !strings.Contains(got.bizContent, `"out_trade_no":"O1"`) {
		t.Errorf("biz_content missing order no: %s", got.bizContent)
	}
}

func TestAlipayQueryReturnsSuccessTradeNo(t *testing.T) {
	privPath, pubPath, _ := writePEMKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"alipay_trade_query_response":{"code":"10000","trade_no":"TX-9","out_trade_no":"O-9","trade_status":"TRADE_SUCCESS"}}`))
	}))
	defer srv.Close()
	a, _ := NewAlipay("ali", privPath, pubPath, "http://notify", srv.URL)

	notice, paid, err := a.Query(context.Background(), "O-9")
	if err != nil || !paid {
		t.Fatalf("expected paid=true err=nil; got %v %v", paid, err)
	}
	if notice.TradeNo != "TX-9" {
		t.Errorf("trade_no = %q", notice.TradeNo)
	}
}

func TestAlipayQueryHandlesTradeNotExist(t *testing.T) {
	privPath, pubPath, _ := writePEMKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"alipay_trade_query_response":{"code":"40004","sub_code":"ACQ.TRADE_NOT_EXIST","msg":"Business Failed"}}`))
	}))
	defer srv.Close()
	a, _ := NewAlipay("ali", privPath, pubPath, "http://notify", srv.URL)

	notice, paid, err := a.Query(context.Background(), "O-404")
	if err != nil || paid || notice != nil {
		t.Errorf("expected (nil, false, nil); got (%v, %v, %v)", notice, paid, err)
	}
}

// --- key loaders -------------------------------------------------------------

func TestLoadRSAPrivateKeyRejectsNonPEM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(p, []byte("not a pem"), 0o600)
	if _, err := loadRSAPrivateKey(p); err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func TestLoadRSAPublicKeyRoundtrip(t *testing.T) {
	_, pubPath, _ := writePEMKey(t)
	pk, err := loadRSAPublicKey(pubPath)
	if err != nil || pk == nil {
		t.Fatalf("expected key; got %v %v", pk, err)
	}
}

// --- elapsed-time sanity (HTTPClient timeouts wouldn't fire here, but make
// sure we don't accidentally introduce one that's < 1s in the future).
func TestAlipayHTTPClientTimeoutReasonable(t *testing.T) {
	privPath, pubPath, _ := writePEMKey(t)
	a, _ := NewAlipay("ali", privPath, pubPath, "http://x", "")
	if a.HTTPClient.Timeout < time.Second {
		t.Errorf("client timeout too aggressive: %s", a.HTTPClient.Timeout)
	}
}
