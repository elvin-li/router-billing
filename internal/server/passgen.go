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
	out := make([]byte, n)
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	for i, b := range raw {
		out[i] = pwAlphabet[int(b)%len(pwAlphabet)]
	}
	return string(out)
}

func bcryptHash(p string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(h), err
}
