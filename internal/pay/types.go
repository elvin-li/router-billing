package pay

import (
	"errors"
	"strconv"
	"strings"
)

// PaidNotice is emitted by either provider when a webhook confirms a payment.
type PaidNotice struct {
	OrderNo  string
	TradeNo  string
	Provider string // "wechat" / "alipay"
	// AmountCents is the amount the provider says was actually paid, in 分.
	// 0 means the provider response didn't carry a parseable amount, in
	// which case the caller skips the cross-check rather than failing.
	AmountCents int
}

// yuanToCents parses a decimal-yuan string ("12.34", "5", "0.50") into 分
// without going through float64. Returns (0, false) on malformed input.
func yuanToCents(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	intPart, fracPart, _ := strings.Cut(s, ".")
	if len(fracPart) > 2 {
		return 0, false
	}
	for len(fracPart) < 2 {
		fracPart += "0"
	}
	yuan, err := strconv.Atoi(intPart)
	if err != nil || yuan < 0 {
		return 0, false
	}
	cents, err := strconv.Atoi(fracPart)
	if err != nil || cents < 0 {
		return 0, false
	}
	return yuan*100 + cents, true
}

// PrecreateResult is what we return to the portal for rendering a QR.
type PrecreateResult struct {
	OrderNo string // our order id
	QRCode  string // qrcode payload (URL or URI)
}

var (
	ErrDisabled       = errors.New("provider not enabled")
	ErrBadSignature   = errors.New("bad signature")
	ErrBadAmount      = errors.New("amount mismatch")
	ErrInvalidPayload = errors.New("invalid payload")
)
