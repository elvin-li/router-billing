package pay

import (
	"bytes"
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
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WeChat implements the v3 Native (扫码) flow.
//
// Reference: https://pay.weixin.qq.com/wiki/doc/apiv3/apis/chapter3_4_1.shtml
type WeChat struct {
	MchID     string
	AppID     string
	APIv3Key  []byte
	SerialNo  string
	PrivKey   *rsa.PrivateKey
	NotifyURL string

	HTTPClient *http.Client

	// platformCerts is the auto-fetched, AES-GCM-decrypted set of WeChat
	// platform certificates used to verify notify-webhook signatures.
	// Refreshed lazily; cached in memory only.
	certMu        sync.Mutex
	platformCerts map[string]*x509.Certificate
	certsFetched  time.Time
}

const wxPayBase = "https://api.mch.weixin.qq.com"

func NewWeChat(mchID, appID, apiV3Key, serialNo, privKeyPath, notifyURL string) (*WeChat, error) {
	pk, err := loadRSAPrivateKey(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("wechat: load private key: %w", err)
	}
	return &WeChat{
		MchID:      mchID,
		AppID:      appID,
		APIv3Key:   []byte(apiV3Key),
		SerialNo:   serialNo,
		PrivKey:    pk,
		NotifyURL:  notifyURL,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

type wxNativeReq struct {
	AppID       string      `json:"appid"`
	MchID       string      `json:"mchid"`
	Description string      `json:"description"`
	OutTradeNo  string      `json:"out_trade_no"`
	NotifyURL   string      `json:"notify_url"`
	Amount      wxNativeAmt `json:"amount"`
}

type wxNativeAmt struct {
	Total    int    `json:"total"`    // 分
	Currency string `json:"currency"` // CNY
}

type wxNativeResp struct {
	CodeURL string `json:"code_url"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Precreate calls /v3/pay/transactions/native and returns the QR code URI.
func (w *WeChat) Precreate(ctx context.Context, outTradeNo, desc string, totalCents int) (*PrecreateResult, error) {
	body := wxNativeReq{
		AppID:       w.AppID,
		MchID:       w.MchID,
		Description: desc,
		OutTradeNo:  outTradeNo,
		NotifyURL:   w.NotifyURL,
		Amount:      wxNativeAmt{Total: totalCents, Currency: "CNY"},
	}
	buf, _ := json.Marshal(body)
	const path = "/v3/pay/transactions/native"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wxPayBase+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	auth, err := w.authHeader("POST", path, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := w.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("wechat precreate: http %d: %s", resp.StatusCode, string(respBody))
	}
	var nr wxNativeResp
	if err := json.Unmarshal(respBody, &nr); err != nil {
		return nil, fmt.Errorf("wechat precreate: parse: %w", err)
	}
	if nr.CodeURL == "" {
		return nil, fmt.Errorf("wechat precreate: empty code_url: %s", string(respBody))
	}
	return &PrecreateResult{OrderNo: outTradeNo, QRCode: nr.CodeURL}, nil
}

// Query polls /v3/pay/transactions/out-trade-no/{out_trade_no} to learn an
// order's true state. Use this when you don't have an HTTPS notify_url —
// from the client's QR-polling, kick this off and consider the order paid
// when the API replies SUCCESS. Outbound HTTPS only; no inbound required.
func (w *WeChat) Query(ctx context.Context, outTradeNo string) (*PaidNotice, bool, error) {
	path := "/v3/pay/transactions/out-trade-no/" + outTradeNo + "?mchid=" + w.MchID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wxPayBase+path, nil)
	if err != nil {
		return nil, false, err
	}
	auth, err := w.authHeader("GET", path, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")

	resp, err := w.HTTPClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if resp.StatusCode == 404 {
		// Order exists locally but WeChat doesn't know it yet (user hasn't scanned).
		return nil, false, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, false, fmt.Errorf("wechat query: http %d: %s", resp.StatusCode, string(body))
	}
	var q struct {
		MchID         string `json:"mchid"`
		AppID         string `json:"appid"`
		OutTradeNo    string `json:"out_trade_no"`
		TransactionID string `json:"transaction_id"`
		TradeState    string `json:"trade_state"`
		Amount        struct {
			Total int `json:"total"`
		} `json:"amount"`
	}
	if err := json.Unmarshal(body, &q); err != nil {
		return nil, false, fmt.Errorf("wechat query: parse: %w", err)
	}
	if q.TradeState != "SUCCESS" {
		return nil, false, nil
	}
	return &PaidNotice{
		OrderNo:     q.OutTradeNo,
		TradeNo:     q.TransactionID,
		Provider:    "wechat",
		AmountCents: q.Amount.Total,
	}, true, nil
}

// authHeader builds the WECHATPAY2-SHA256-RSA2048 Authorization header.
func (w *WeChat) authHeader(method, path string, body []byte) (string, error) {
	nonce := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	src := strings.Join([]string{method, path, ts, nonce, string(body)}, "\n") + "\n"
	h := sha256.Sum256([]byte(src))
	sig, err := rsa.SignPKCS1v15(rand.Reader, w.PrivKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	enc := base64.StdEncoding.EncodeToString(sig)
	return fmt.Sprintf(`WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"`,
		w.MchID, nonce, enc, ts, w.SerialNo), nil
}

// ---- Notification handling ----

type wxNotifyEnvelope struct {
	ID           string `json:"id"`
	CreateTime   string `json:"create_time"`
	EventType    string `json:"event_type"`
	ResourceType string `json:"resource_type"`
	Resource     struct {
		Algorithm      string `json:"algorithm"`
		Ciphertext     string `json:"ciphertext"`
		AssociatedData string `json:"associated_data"`
		Nonce          string `json:"nonce"`
	} `json:"resource"`
	Summary string `json:"summary"`
}

type wxNotifyResource struct {
	MchID         string `json:"mchid"`
	AppID         string `json:"appid"`
	OutTradeNo    string `json:"out_trade_no"`
	TransactionID string `json:"transaction_id"`
	TradeState    string `json:"trade_state"`
	TradeType     string `json:"trade_type"`
	SuccessTime   string `json:"success_time"`
	Amount        struct {
		Total int `json:"total"`
	} `json:"amount"`
}

// VerifyNotifyHeaders checks the Wechatpay-Signature header against the
// platform cert identified by Wechatpay-Serial. Returns nil on success.
//
// This is defense-in-depth on top of the AES-GCM authentication of the body:
// AES-GCM proves the body wasn't tampered with by anyone lacking our APIv3
// key, but the platform signature proves the request actually came from
// WeChat (and not, e.g., a previously-compromised APIv3 key that's been
// rotated). Both checks are run in handleNotifyWeChat for production safety.
//
// If the cache is empty, fetches /v3/certificates lazily.
func (w *WeChat) VerifyNotifyHeaders(ctx context.Context, headers http.Header, body []byte) error {
	serial := headers.Get("Wechatpay-Serial")
	sigB64 := headers.Get("Wechatpay-Signature")
	ts := headers.Get("Wechatpay-Timestamp")
	nonce := headers.Get("Wechatpay-Nonce")
	if serial == "" || sigB64 == "" || ts == "" || nonce == "" {
		return fmt.Errorf("%w: missing Wechatpay-* headers", ErrBadSignature)
	}
	// Replay window: timestamp must be within 5 minutes.
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: bad timestamp", ErrBadSignature)
	}
	if d := time.Since(time.Unix(tsInt, 0)); d > 5*time.Minute || d < -5*time.Minute {
		return fmt.Errorf("%w: timestamp out of window (%s)", ErrBadSignature, d)
	}
	cert, err := w.platformCert(ctx, serial)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: signature base64", ErrBadSignature)
	}
	src := ts + "\n" + nonce + "\n" + string(body) + "\n"
	hash := sha256.Sum256([]byte(src))
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: cert not RSA", ErrBadSignature)
	}
	if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return nil
}

// platformCert returns the cached cert for serial, fetching the certificate
// list from /v3/certificates if cache is empty or the serial isn't known.
// Refetches at most every 6h (WeChat rotates certs every ~12 months).
func (w *WeChat) platformCert(ctx context.Context, serial string) (*x509.Certificate, error) {
	w.certMu.Lock()
	c, ok := w.platformCerts[serial]
	stale := time.Since(w.certsFetched) > 6*time.Hour
	w.certMu.Unlock()
	if ok && !stale {
		return c, nil
	}
	if err := w.refreshPlatformCerts(ctx); err != nil {
		// If we have a stale-but-present cert, fall back rather than failing
		// entirely (so a temporary WeChat outage doesn't break webhook).
		if ok {
			return c, nil
		}
		return nil, err
	}
	w.certMu.Lock()
	c = w.platformCerts[serial]
	w.certMu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("%w: unknown cert serial %s", ErrBadSignature, serial)
	}
	return c, nil
}

func (w *WeChat) refreshPlatformCerts(ctx context.Context) error {
	const path = "/v3/certificates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wxPayBase+path, nil)
	if err != nil {
		return err
	}
	auth, err := w.authHeader("GET", path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")

	resp, err := w.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch certs: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("fetch certs: http %d: %s", resp.StatusCode, string(body))
	}
	var doc struct {
		Data []struct {
			SerialNo           string `json:"serial_no"`
			EffectiveTime      string `json:"effective_time"`
			ExpireTime         string `json:"expire_time"`
			EncryptCertificate struct {
				Algorithm      string `json:"algorithm"`
				Nonce          string `json:"nonce"`
				AssociatedData string `json:"associated_data"`
				Ciphertext     string `json:"ciphertext"`
			} `json:"encrypt_certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse certs: %w", err)
	}
	out := map[string]*x509.Certificate{}
	block, err := aes.NewCipher(w.APIv3Key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	for _, d := range doc.Data {
		if d.EncryptCertificate.Algorithm != "AEAD_AES_256_GCM" {
			continue
		}
		ct, err := base64.StdEncoding.DecodeString(d.EncryptCertificate.Ciphertext)
		if err != nil {
			continue
		}
		if len(d.EncryptCertificate.Nonce) != aead.NonceSize() {
			continue // wrong-size nonce would panic aead.Open
		}
		plain, err := aead.Open(nil, []byte(d.EncryptCertificate.Nonce), ct,
			[]byte(d.EncryptCertificate.AssociatedData))
		if err != nil {
			continue
		}
		pblk, _ := pem.Decode(plain)
		if pblk == nil {
			continue
		}
		cert, err := x509.ParseCertificate(pblk.Bytes)
		if err != nil {
			continue
		}
		out[d.SerialNo] = cert
	}
	if len(out) == 0 {
		return fmt.Errorf("no certs decoded")
	}
	w.certMu.Lock()
	w.platformCerts = out
	w.certsFetched = time.Now()
	w.certMu.Unlock()
	return nil
}

// DecodeNotify parses the v3 notification body and returns the inner resource.
// AES-GCM authentication proves the body wasn't forged without our APIv3 key.
// Callers should ALSO call VerifyNotifyHeaders for full safety.
func (w *WeChat) DecodeNotify(body []byte) (*PaidNotice, error) {
	var env wxNotifyEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	// Only payment-success events may finalize an order. Other event types
	// (e.g. REFUND.SUCCESS) carry differently-shaped resources; don't even
	// try to interpret them as a payment.
	if env.EventType != "TRANSACTION.SUCCESS" {
		return nil, fmt.Errorf("%w: unexpected event_type %q", ErrInvalidPayload, env.EventType)
	}
	if env.Resource.Algorithm != "AEAD_AES_256_GCM" {
		return nil, fmt.Errorf("%w: unsupported algo %q", ErrInvalidPayload, env.Resource.Algorithm)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Resource.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: ciphertext base64: %v", ErrInvalidPayload, err)
	}
	block, err := aes.NewCipher(w.APIv3Key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// GCM Open panics (not errors) on a wrong-size nonce, and the nonce here is
	// attacker-controlled input from the notification body. Reject early.
	if len(env.Resource.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: bad nonce length %d", ErrInvalidPayload, len(env.Resource.Nonce))
	}
	plain, err := aead.Open(nil, []byte(env.Resource.Nonce), ct, []byte(env.Resource.AssociatedData))
	if err != nil {
		return nil, fmt.Errorf("%w: aes-gcm open: %v", ErrBadSignature, err)
	}
	var res wxNotifyResource
	if err := json.Unmarshal(plain, &res); err != nil {
		return nil, fmt.Errorf("%w: inner json: %v", ErrInvalidPayload, err)
	}
	if res.MchID != w.MchID || res.AppID != w.AppID {
		return nil, fmt.Errorf("%w: mismatched merchant/app", ErrBadSignature)
	}
	if res.TradeState != "SUCCESS" {
		return nil, fmt.Errorf("trade_state=%s", res.TradeState)
	}
	return &PaidNotice{
		OrderNo:     res.OutTradeNo,
		TradeNo:     res.TransactionID,
		Provider:    "wechat",
		AmountCents: res.Amount.Total,
	}, nil
}

// ---- helpers ----

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not RSA", path)
	}
	return rsaKey, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const hex = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, x := range b {
		out[i*2] = hex[x>>4]
		out[i*2+1] = hex[x&0xf]
	}
	return string(out)
}
