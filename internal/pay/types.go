package pay

import "errors"

// PaidNotice is emitted by either provider when a webhook confirms a payment.
type PaidNotice struct {
	OrderNo  string
	TradeNo  string
	Provider string // "wechat" / "alipay"
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
