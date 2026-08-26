package server

import (
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

// randomPassword generates a human-typeable temporary password.
// Mixed-case alphanumerics minus the visually confusing pairs (0/O, 1/I/l).
const pwAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randomPassword(n int) string {
	if n <= 0 {
		n = 10
	}
	// Rejection sampling: len(pwAlphabet) is 57 and 256 % 57 != 0, so a
	// plain `b % 57` would skew the first 28 symbols to 5/256 probability
	// vs 4/256 for the rest. Discard bytes above the largest multiple of
	// 57 so every symbol is exactly uniform (same discipline the backup
	// codes get for free from their 32-symbol alphabet).
	limit := byte(256 - 256%len(pwAlphabet)) // 228
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		_, _ = rand.Read(buf)
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, pwAlphabet[int(b)%len(pwAlphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out)
}

func bcryptHash(p string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(h), err
}
