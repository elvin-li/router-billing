package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// rfc6238Secret is the SHA-1 test secret from RFC 6238 Appendix B.
// The RFC uses the ASCII string "12345678901234567890" → 20 bytes.
var rfc6238SecretB32 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

// RFC 6238 Appendix B test vectors (SHA-1 only). Only the matching 6-digit
// truncated codes are listed in the spec; we use those.
func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		ts   int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		// 20000000000 overflows int32 but our int64 path handles it.
		{20000000000, "353130"},
	}
	for _, c := range cases {
		got, err := Code(rfc6238SecretB32, c.ts)
		if err != nil {
			t.Fatalf("ts=%d: %v", c.ts, err)
		}
		if got != c.want {
			t.Errorf("ts=%d: got %s, want %s", c.ts, got, c.want)
		}
	}
}

func TestVerifyAllowsClockSkewWithinOneStep(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	codeNow, _ := Code(secret, now.Unix())
	if !Verify(secret, codeNow, now) {
		t.Error("now-code should verify at now")
	}
	// Code generated for the previous step should still verify ~25s later
	// (within the 1-step skew tolerance).
	codePrev, _ := Code(secret, now.Add(-25*time.Second).Unix())
	if !Verify(secret, codePrev, now) {
		t.Error("previous-step code should verify within skew tolerance")
	}
	// 2 steps off → reject.
	codeFar, _ := Code(secret, now.Add(-90*time.Second).Unix())
	if Verify(secret, codeFar, now) {
		t.Error("2-step-old code must NOT verify")
	}
}

func TestVerifyRejectsWrongCode(t *testing.T) {
	secret, _ := GenerateSecret()
	if Verify(secret, "000000", time.Now()) {
		t.Error("zeroed code shouldn't verify")
	}
	if Verify(secret, "12345", time.Now()) {
		t.Error("wrong-length code shouldn't verify")
	}
	if Verify(secret, "1234567", time.Now()) {
		t.Error("wrong-length code shouldn't verify")
	}
}

func TestVerifyRejectsMalformedSecret(t *testing.T) {
	if Verify("not!base32!", "000000", time.Now()) {
		t.Error("garbage secret should fail decoding, return false")
	}
}

func TestGenerateSecretIsBase32_160Bit(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	// 20 bytes encodes to 32 base32 chars (no padding).
	if len(s) != 32 {
		t.Errorf("len=%d, want 32 (160-bit, no pad)", len(s))
	}
	if _, err := decodeSecret(s); err != nil {
		t.Errorf("decode roundtrip: %v", err)
	}
}

func TestSecretAcceptsSpacesDashesAndLowercase(t *testing.T) {
	// All these should decode to the same key + emit the same code.
	canonical := "JBSWY3DPEHPK3PXP"
	variants := []string{
		"jbswy3dpehpk3pxp",
		"JBSW Y3DP EHPK 3PXP",
		"jbswy3dp-ehpk3pxp",
		"  JBSWY3DP\tEHPK3PXP  ",
	}
	want, _ := Code(canonical, 1700000000)
	for _, v := range variants {
		got, err := Code(v, 1700000000)
		if err != nil {
			t.Errorf("%q: %v", v, err)
			continue
		}
		if got != want {
			t.Errorf("%q gave %s, want %s", v, got, want)
		}
	}
}

func TestProvisioningURIShape(t *testing.T) {
	uri := ProvisioningURI("JBSWY3DPEHPK3PXP", "alice", "")
	for _, want := range []string{
		"otpauth://totp/",
		"router-billing", // default issuer
		"secret=JBSWY3DPEHPK3PXP",
		"period=30",
		"digits=6",
		"algorithm=SHA1",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI missing %q\nURI=%s", want, uri)
		}
	}
}
