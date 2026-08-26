package shadowsocks

import (
	"encoding/hex"
	"testing"
)

func TestLookupCipherAndAliases(t *testing.T) {
	cases := map[string]string{
		"aes-128-gcm":            "aes-128-gcm",
		"AES-256-GCM":            "aes-256-gcm",
		"chacha20-ietf-poly1305": "chacha20-ietf-poly1305",
		"chacha20-poly1305":      "chacha20-ietf-poly1305",
		"AEAD_CHACHA20_POLY1305": "chacha20-ietf-poly1305",
	}
	for in, want := range cases {
		spec, err := LookupCipher(in)
		if err != nil {
			t.Fatalf("LookupCipher(%q): %v", in, err)
		}
		if spec.Name != want {
			t.Errorf("LookupCipher(%q).Name = %q, want %q", in, spec.Name, want)
		}
	}
	if _, err := LookupCipher("rc4-md5"); err == nil {
		t.Error("expected error for unsupported stream cipher rc4-md5")
	}
	if _, err := LookupCipher(""); err == nil {
		t.Error("expected error for empty method")
	}
}

func TestValidMethod(t *testing.T) {
	if !ValidMethod("aes-256-gcm") {
		t.Error("aes-256-gcm should be valid")
	}
	if ValidMethod("des-cbc") {
		t.Error("des-cbc should be invalid")
	}
}

func TestCipherKeySizes(t *testing.T) {
	want := map[string]int{
		"aes-128-gcm":            16,
		"aes-256-gcm":            32,
		"chacha20-ietf-poly1305": 32,
	}
	for m, size := range want {
		spec, _ := LookupCipher(m)
		if spec.KeySize != size {
			t.Errorf("%s KeySize = %d, want %d", m, spec.KeySize, size)
		}
		if spec.SaltSize() != size {
			t.Errorf("%s SaltSize = %d, want %d", m, spec.SaltSize(), size)
		}
		// Constructing the AEAD with a correctly-sized key must succeed.
		if _, err := spec.newAEAD(make([]byte, size)); err != nil {
			t.Errorf("%s newAEAD: %v", m, err)
		}
	}
}

// TestDeriveKeyKnownVector pins EVP_BytesToKey(MD5) output so we never drift
// from the reference derivation every Shadowsocks client uses.
//
// For password "test" and a 16-byte key, EVP_BytesToKey(MD5) yields
// MD5("test") = 098f6bcd4621d373cade4e832627b4f6.
func TestDeriveKeyKnownVector(t *testing.T) {
	got := DeriveKey("test", 16)
	want, _ := hex.DecodeString("098f6bcd4621d373cade4e832627b4f6")
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("DeriveKey(test,16) = %x, want %x", got, want)
	}

	// 32-byte key chains a second MD5 block: MD5(prev||password).
	got32 := DeriveKey("test", 32)
	if len(got32) != 32 {
		t.Fatalf("len = %d, want 32", len(got32))
	}
	// First 16 bytes must equal the 16-byte derivation.
	if hex.EncodeToString(got32[:16]) != hex.EncodeToString(want) {
		t.Errorf("first block mismatch: %x", got32[:16])
	}
}

func TestSupportedMethodsStable(t *testing.T) {
	got := SupportedMethods()
	if len(got) != 3 {
		t.Fatalf("expected 3 methods, got %d: %v", len(got), got)
	}
	for _, m := range got {
		if !ValidMethod(m) {
			t.Errorf("SupportedMethods lists %q but ValidMethod says no", m)
		}
	}
}
