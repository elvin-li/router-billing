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
//
// Rejection sampling: len(alphabet) is 31 and 256 % 31 = 8, so a plain
// `b % 31` skewed the first 8 symbols to 9/256 probability vs 8/256 for
// the rest (+12.5%) — vouchers are cash-equivalent bearer tokens, so they
// get the same uniformity discipline randomPassword got in v0.121.
func New() (string, error) {
	const n = 12
	limit := byte(256 - 256%len(alphabet)) // 248
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, alphabet[int(b)%len(alphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
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
