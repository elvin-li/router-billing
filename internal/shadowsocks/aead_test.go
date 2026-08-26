package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

// roundTrip encrypts plaintext through an aeadWriter and decrypts it back
// with an aeadReader using a freshly-derived subkey, asserting equality.
func roundTrip(t *testing.T, method string, plaintext []byte) {
	t.Helper()
	spec, err := LookupCipher(method)
	if err != nil {
		t.Fatal(err)
	}
	key := DeriveKey("correct horse battery staple", spec.KeySize)
	salt := make([]byte, spec.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	sub, err := deriveSubkey(key, salt, spec.KeySize)
	if err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	encAEAD, _ := spec.newAEAD(sub)
	w := newAEADWriter(&wire, encAEAD)
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}

	decAEAD, _ := spec.newAEAD(sub)
	r := newAEADReader(&wire, decAEAD)
	got, err := io.ReadAll(r)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

func TestAEADRoundTripAllCiphers(t *testing.T) {
	payloads := map[string][]byte{
		"empty-ish":   []byte("x"),
		"small":       []byte("hello shadowsocks"),
		"exact-chunk": bytes.Repeat([]byte("A"), maxPayloadChunk),
		"multi-chunk": bytes.Repeat([]byte("B"), maxPayloadChunk*2+123),
	}
	for _, method := range SupportedMethods() {
		for name, p := range payloads {
			t.Run(method+"/"+name, func(t *testing.T) {
				roundTrip(t, method, p)
			})
		}
	}
}

func TestAEADWrongKeyFailsToDecrypt(t *testing.T) {
	spec, _ := LookupCipher("chacha20-ietf-poly1305")
	salt := make([]byte, spec.SaltSize())
	_, _ = rand.Read(salt)

	subGood, _ := deriveSubkey(DeriveKey("right", spec.KeySize), salt, spec.KeySize)
	subBad, _ := deriveSubkey(DeriveKey("wrong", spec.KeySize), salt, spec.KeySize)

	var wire bytes.Buffer
	encAEAD, _ := spec.newAEAD(subGood)
	w := newAEADWriter(&wire, encAEAD)
	_, _ = w.Write([]byte("secret payload"))

	decAEAD, _ := spec.newAEAD(subBad)
	r := newAEADReader(&wire, decAEAD)
	buf := make([]byte, 64)
	if _, err := r.Read(buf); err == nil {
		t.Fatal("expected decryption failure with wrong key, got nil")
	}
}

func TestIncrementNonce(t *testing.T) {
	n := make([]byte, 12)
	increment(n)
	if n[0] != 1 {
		t.Fatalf("first increment: %v", n)
	}
	// Carry propagation: set low byte to 0xff so ++ rolls into the next.
	n[0] = 0xff
	increment(n)
	if n[0] != 0x00 || n[1] != 1 {
		t.Fatalf("carry increment: %v", n)
	}
}
