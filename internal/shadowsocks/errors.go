package shadowsocks

import (
	"crypto/sha1" //nolint:gosec // HKDF-SHA1 is mandated by the Shadowsocks AEAD spec; not used as a security hash on its own
	"errors"
	"hash"
)

// shaNew is the HKDF hash constructor. Shadowsocks AEAD (SIP004) fixes this
// to SHA-1 for subkey derivation — it's HMAC-SHA1 inside HKDF, not a bare
// digest, and interoperability requires exactly this choice.
func shaNew() hash.Hash { return sha1.New() } //nolint:gosec // HKDF-SHA1 is mandated by the SS AEAD spec; used inside HMAC, not as a bare digest

var (
	// errBadLength is returned when a decrypted chunk length is zero or
	// exceeds the protocol maximum — almost always a wrong password or a
	// non-Shadowsocks client probing the port.
	errBadLength = errors.New("shadowsocks: invalid chunk length")
	// errReplay is returned when a connection presents a salt we've already
	// seen inside the replay window (salt reuse — a classic AEAD attack).
	errReplay = errors.New("shadowsocks: replayed salt rejected")
	// errBadAddress is returned when the SOCKS5 target address in the
	// decrypted header is malformed or uses an unsupported ATYP.
	errBadAddress = errors.New("shadowsocks: malformed target address")
)
