// Package totp implements RFC 6238 (Time-based One-Time Password). Used to
// gate admin login with a second factor on top of password.
//
// Compatible with Google Authenticator, Authy, 1Password, Bitwarden, etc.
// The output is always a 6-digit code, period 30 seconds, HMAC-SHA1 — the
// defaults all the popular authenticators expect.
//
// Roll-your-own rather than pulling another module: the crypto is two dozen
// lines and the test vectors from RFC 6238 prove correctness.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	period = 30 // seconds per code, RFC 6238 default
	digits = 6
)

// GenerateSecret returns a fresh base32-encoded 160-bit secret (the size
// recommended by RFC 4226 §4). Strip padding so the displayed string is
// the same length authenticators show.
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
	return s, nil
}

// Code computes the 6-digit code for the given base32 secret + Unix time.
func Code(secretB32 string, unixTime int64) (string, error) {
	key, err := decodeSecret(secretB32)
	if err != nil {
		return "", err
	}
	return hotp(key, unixTime/period), nil
}

// Verify returns true if `code` matches Code(secret, now) with a ±1 step
// tolerance for clock skew between server and authenticator. Constant-time
// comparison so an attacker can't time-side-channel the right code.
func Verify(secretB32, code string, now time.Time) bool {
	if len(code) != digits {
		return false
	}
	key, err := decodeSecret(secretB32)
	if err != nil {
		return false
	}
	t := now.Unix() / period
	for skew := int64(-1); skew <= 1; skew++ {
		want := hotp(key, t+skew)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// ProvisioningURI returns an otpauth:// URL that, when encoded as a QR,
// every TOTP app on earth understands. issuer + accountName get URL-encoded.
//
//	otpauth://totp/router-billing:alice?secret=...&issuer=router-billing&period=30&digits=6&algorithm=SHA1
func ProvisioningURI(secretB32, accountName, issuer string) string {
	if issuer == "" {
		issuer = "router-billing"
	}
	label := url.PathEscape(issuer + ":" + accountName)
	v := url.Values{}
	v.Set("secret", strings.ToUpper(strings.ReplaceAll(secretB32, " ", "")))
	v.Set("issuer", issuer)
	v.Set("period", fmt.Sprintf("%d", period))
	v.Set("digits", fmt.Sprintf("%d", digits))
	v.Set("algorithm", "SHA1")
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// --- internals ---------------------------------------------------------------

func decodeSecret(s string) ([]byte, error) {
	// Authenticators are case-insensitive and people often paste spaces in.
	// Strip whitespace + dashes — authenticators are case-insensitive and
	// admins often paste display-formatted secrets (spaces/tabs/dashes).
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '-':
			return -1
		}
		return r
	}, s)
	clean = strings.ToUpper(clean)
	// Accept secrets with or without base32 padding.
	if rem := len(clean) % 8; rem != 0 {
		clean += strings.Repeat("=", 8-rem)
	}
	return base32.StdEncoding.DecodeString(clean)
}

func hotp(key []byte, counter int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	h := hmac.New(sha1.New, key)
	h.Write(buf)
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}
