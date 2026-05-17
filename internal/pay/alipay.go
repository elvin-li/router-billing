package pay

import (
	"context"
	"crypto"
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
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Alipay implements 当面付 / alipay.trade.precreate.
//
// Reference: https://opendocs.alipay.com/open/02ekfg
type Alipay struct {
	AppID       string
	PrivKey     *rsa.PrivateKey
	AliPubKey   *rsa.PublicKey
	NotifyURL   string
	Gateway     string
	HTTPClient  *http.Client
}

func NewAlipay(appID, privKeyPath, alipayPubKeyPath, notifyURL, gateway string) (*Alipay, error) {
	pk, err := loadRSAPrivateKey(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("alipay: load private key: %w", err)
	}
	pub, err := loadRSAPublicKey(alipayPubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("alipay: load public key: %w", err)
	}
	if gateway == "" {
		gateway = "https://openapi.alipay.com/gateway.do"
	}
	return &Alipay{
		AppID:      appID,
		PrivKey:    pk,
		AliPubKey:  pub,
		NotifyURL:  notifyURL,
		Gateway:    gateway,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Precreate returns the qr_code string to render.
func (a *Alipay) Precreate(ctx context.Context, outTradeNo, subject string, totalCents int) (*PrecreateResult, error) {
	biz := map[string]any{
		"out_trade_no": outTradeNo,
		"total_amount": fmt.Sprintf("%d.%02d", totalCents/100, totalCents%100),
		"subject":      subject,
	}
	bizContent, _ := json.Marshal(biz)

	params := map[string]string{
		"app_id":      a.AppID,
		"method":      "alipay.trade.precreate",
		"format":      "JSON",
		"charset":     "utf-8",
		"sign_type":   "RSA2",
		"timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		"version":     "1.0",
		"notify_url":  a.NotifyURL,
		"biz_content": string(bizContent),
	}
	sign, err := a.sign(params)
	if err != nil {
		return nil, err
	}
	params["sign"] = sign

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Gateway, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("alipay precreate: http %d: %s", resp.StatusCode, string(body))
	}

	var wrap struct {
		Resp struct {
			Code     string `json:"code"`
			Msg      string `json:"msg"`
			QRCode   string `json:"qr_code"`
			SubMsg   string `json:"sub_msg"`
			OutTrade string `json:"out_trade_no"`
		} `json:"alipay_trade_precreate_response"`
		Sign string `json:"sign"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, fmt.Errorf("alipay precreate: parse: %w; body=%s", err, string(body))
	}
	if wrap.Resp.Code != "10000" {
		return nil, fmt.Errorf("alipay precreate: %s/%s/%s", wrap.Resp.Code, wrap.Resp.Msg, wrap.Resp.SubMsg)
	}
	if wrap.Resp.QRCode == "" {
		return nil, fmt.Errorf("alipay precreate: empty qr_code")
	}
	return &PrecreateResult{OrderNo: outTradeNo, QRCode: wrap.Resp.QRCode}, nil
}

// Query polls alipay.trade.query to learn an order's true state — used when
// no public HTTPS notify_url is available. Returns (notice, paid, err).
func (a *Alipay) Query(ctx context.Context, outTradeNo string) (*PaidNotice, bool, error) {
	biz := map[string]any{"out_trade_no": outTradeNo}
	bizContent, _ := json.Marshal(biz)
	params := map[string]string{
		"app_id":      a.AppID,
		"method":      "alipay.trade.query",
		"format":      "JSON",
		"charset":     "utf-8",
		"sign_type":   "RSA2",
		"timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		"version":     "1.0",
		"biz_content": string(bizContent),
	}
	sign, err := a.sign(params)
	if err != nil {
		return nil, false, err
	}
	params["sign"] = sign

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Gateway, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, false, fmt.Errorf("alipay query: http %d: %s", resp.StatusCode, string(body))
	}
	var wrap struct {
		Resp struct {
			Code        string `json:"code"`
			Msg         string `json:"msg"`
			SubCode     string `json:"sub_code"`
			SubMsg      string `json:"sub_msg"`
			OutTradeNo  string `json:"out_trade_no"`
			TradeNo     string `json:"trade_no"`
			TradeStatus string `json:"trade_status"`
		} `json:"alipay_trade_query_response"`
	}
	if err := json.Unmarshal(body, &wrap); err != nil {
		return nil, false, fmt.Errorf("alipay query: parse: %w; body=%s", err, string(body))
	}
	r := wrap.Resp
	if r.Code != "10000" {
		// ACQ.TRADE_NOT_EXIST = order not yet created upstream (user hasn't scanned)
		if r.SubCode == "ACQ.TRADE_NOT_EXIST" {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("alipay query: %s/%s/%s", r.Code, r.Msg, r.SubMsg)
	}
	if r.TradeStatus != "TRADE_SUCCESS" && r.TradeStatus != "TRADE_FINISHED" {
		return nil, false, nil
	}
	return &PaidNotice{
		OrderNo:  r.OutTradeNo,
		TradeNo:  r.TradeNo,
		Provider: "alipay",
	}, true, nil
}

// DecodeNotify validates the form-encoded notification and returns the paid notice.
func (a *Alipay) DecodeNotify(form url.Values) (*PaidNotice, error) {
	sign := form.Get("sign")
	signType := form.Get("sign_type")
	if sign == "" {
		return nil, fmt.Errorf("%w: missing sign", ErrInvalidPayload)
	}
	if signType != "" && signType != "RSA2" {
		return nil, fmt.Errorf("%w: unsupported sign_type %q", ErrInvalidPayload, signType)
	}
	// Build the to-be-verified string per Alipay: all fields except sign/sign_type, sorted by key.
	keys := make([]string, 0, len(form))
	for k := range form {
		if k == "sign" || k == "sign_type" {
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
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(form.Get(k))
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return nil, fmt.Errorf("%w: sign base64: %v", ErrInvalidPayload, err)
	}
	h := sha256.Sum256([]byte(sb.String()))
	if err := rsa.VerifyPKCS1v15(a.AliPubKey, crypto.SHA256, h[:], sigBytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if form.Get("app_id") != a.AppID {
		return nil, fmt.Errorf("%w: app_id mismatch", ErrBadSignature)
	}
	tradeStatus := form.Get("trade_status")
	if tradeStatus != "TRADE_SUCCESS" && tradeStatus != "TRADE_FINISHED" {
		return nil, fmt.Errorf("trade_status=%s", tradeStatus)
	}
	return &PaidNotice{
		OrderNo:  form.Get("out_trade_no"),
		TradeNo:  form.Get("trade_no"),
		Provider: "alipay",
	}, nil
}

// sign builds the RSA2 signature over the sorted "k=v&..." form.
func (a *Alipay) sign(params map[string]string) (string, error) {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if v == "" || k == "sign" {
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
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(params[k])
	}
	h := sha256.Sum256([]byte(sb.String()))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.PrivKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not RSA public key", path)
	}
	return pub, nil
}
