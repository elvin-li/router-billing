// Package shadowsocks implements a minimal, self-contained Shadowsocks
// AEAD (SIP004) server so the router-billing binary can double as a local
// encrypted proxy. It ships OFF by default and is enabled only via explicit
// config (see internal/config).
//
// The wire format implemented here is the widely-supported "classic"
// Shadowsocks AEAD construction (a.k.a. SIP004), compatible with
// shadowsocks-rust, Outline, Clash, and the official iOS/Android clients.
// The newer Shadowsocks-2022 (blake3) framing is intentionally NOT
// implemented — it needs a different, heavier handshake and would pull in a
// blake3 dependency; classic AEAD has the broadest client reach with zero
// extra modules.
//
// Key derivation follows the reference implementation exactly:
//
//   - masterKey = EVP_BytesToKey(password, keyLen)  (OpenSSL MD5 KDF)
//   - per-connection random salt (len == keyLen)
//   - subkey    = HKDF-SHA1(masterKey, salt, "ss-subkey", keyLen)
//   - AEAD nonce = 12-byte little-endian counter, incremented per chunk
//
// TCP stream framing (after the leading salt):
//
//	[encrypted length (2B big-endian) + tag][encrypted payload + tag]...
//
// with each payload chunk capped at 0x3FFF bytes.
package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// maxPayloadChunk is the largest plaintext a single AEAD chunk may carry,
// per the Shadowsocks AEAD spec (the 2-byte length field's top two bits are
// reserved, so the max is 0x3FFF).
const maxPayloadChunk = 0x3FFF

// subkeyInfo is the fixed HKDF "info" string from the reference impl.
var subkeyInfo = []byte("ss-subkey")

// CipherSpec describes one supported AEAD method: its canonical name and the
// key/salt/nonce/tag sizes, plus a constructor for the underlying AEAD.
type CipherSpec struct {
	Name    string
	KeySize int // == SaltSize
	newAEAD func(key []byte) (cipher.AEAD, error)
}

// SaltSize returns the per-connection salt length, which equals the key size.
func (c *CipherSpec) SaltSize() int { return c.KeySize }

// specs is the registry of supported ciphers. All are AEAD; no stream
// ciphers (RC4/AES-CFB/etc.) are offered — they're deprecated and insecure.
var specs = map[string]*CipherSpec{
	"aes-128-gcm": {
		Name:    "aes-128-gcm",
		KeySize: 16,
		newAEAD: newAESGCM,
	},
	"aes-256-gcm": {
		Name:    "aes-256-gcm",
		KeySize: 32,
		newAEAD: newAESGCM,
	},
	"chacha20-ietf-poly1305": {
		Name:    "chacha20-ietf-poly1305",
		KeySize: 32,
		newAEAD: chacha20poly1305.New,
	},
}

// SupportedMethods returns the canonical cipher names, for docs/validation.
func SupportedMethods() []string {
	return []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
	}
}

// normalizeMethod lower-cases and accepts a couple of common aliases so
// operators aren't tripped up by client-side naming variants.
func normalizeMethod(method string) string {
	m := strings.ToLower(strings.TrimSpace(method))
	switch m {
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		return "chacha20-ietf-poly1305"
	case "aead_aes_128_gcm":
		return "aes-128-gcm"
	case "aead_aes_256_gcm":
		return "aes-256-gcm"
	case "aead_chacha20_poly1305":
		return "chacha20-ietf-poly1305"
	}
	return m
}

// LookupCipher returns the spec for a method name (case-insensitive, with a
// few aliases) or an error listing the supported set.
func LookupCipher(method string) (*CipherSpec, error) {
	if s, ok := specs[normalizeMethod(method)]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("unsupported shadowsocks method %q (supported: %s)",
		method, strings.Join(SupportedMethods(), ", "))
}

// ValidMethod reports whether method names a supported cipher.
func ValidMethod(method string) bool {
	_, ok := specs[normalizeMethod(method)]
	return ok
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// DeriveKey implements OpenSSL's EVP_BytesToKey with MD5 and no salt — the
// exact master-key derivation every Shadowsocks implementation uses so a
// password maps to the same key across clients.
func DeriveKey(password string, keyLen int) []byte {
	key := make([]byte, 0, keyLen)
	var prev []byte
	for len(key) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:keyLen]
}
