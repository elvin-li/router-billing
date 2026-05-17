// Package voucher generates and normalizes redemption codes.
//
// Format: 12 chars from an unambiguous alphabet (no 0/O/1/I/L), displayed
// grouped 4-4-4 with dashes (e.g. "7K8M-XQNR-3HJP"). DB stores the canonical
// dashless uppercase form.
//
//	collision space ≈ 31^12 ≈ 7.9e17 — safe for millions of codes
package voucher

import (
	"crypto/rand"
	"errors"
	"strings"
)

// 31 chars — picked to avoid 0/O/1/I/L which users misread/mistype.
const alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// New returns a fresh canonical (dashless, uppercase) 12-char code.
func New() (string, error) {
	buf := make([]byte, 12)
	idx := make([]byte, 12)
	if _, err := rand.Read(idx); err != nil {
		return "", err
	}
	for i, b := range idx {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(buf), nil
}

// Pretty inserts dashes every 4 chars for display.
func Pretty(code string) string {
	c := Canon(code)
	if len(c) <= 4 {
		return c
	}
	var b strings.Builder
	for i, r := range c {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Canon returns the code stripped of dashes/spaces, upper-cased.
func Canon(code string) string {
	r := strings.NewReplacer("-", "", " ", "")
	return strings.ToUpper(r.Replace(strings.TrimSpace(code)))
}

// Validate checks length + alphabet.
func Validate(code string) error {
	c := Canon(code)
	if len(c) != 12 {
		return errors.New("充值码必须是 12 位")
	}
	for _, ch := range c {
		if !strings.ContainsRune(alphabet, ch) {
			return errors.New("充值码包含非法字符")
		}
	}
	return nil
}
