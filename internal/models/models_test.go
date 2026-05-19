package models

import "testing"

func TestNormalizeMAC(t *testing.T) {
	cases := []struct {
		in    string
		want  string
		valid bool
	}{
		{"aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", true},
		{"AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF", true},
		{"aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF", true},
		{"AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF", true},
		{"  aabbccddeeff  ", "AA:BB:CC:DD:EE:FF", true},
		{"AaBbCcDdEeFf", "AA:BB:CC:DD:EE:FF", true},
		{"00:00:00:00:00:00", "00:00:00:00:00:00", true},

		{"aa:bb:cc:dd:ee", "", false},
		{"aa:bb:cc:dd:ee:fg", "", false},
		{"AA:BB:CC:DD:EE:FF:00", "", false},
		{"", "", false},
		{"not a mac", "", false},
		{"aa:bb:cc:dd:ee:f", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeMAC(c.in)
		if ok != c.valid || got != c.want {
			t.Errorf("NormalizeMAC(%q) = (%q, %v); want (%q, %v)", c.in, got, ok, c.want, c.valid)
		}
	}
}

func TestValidPhone(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"13800138000", true},
		{"15912345678", true},
		{"19999999999", true},
		{"12000000000", false}, // 12-xxx is not a valid prefix
		{"10000000000", false},
		{"1380013800", false},     // 10 digits
		{"138001380000", false},   // 12 digits
		{"+8613800138000", false}, // with country code — not supported
		{"abcdefghijk", false},
		{"", false},
	}
	for _, c := range cases {
		if got := ValidPhone(c.in); got != c.want {
			t.Errorf("ValidPhone(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestValidPassword(t *testing.T) {
	if ValidPassword("12345") {
		t.Error("5 chars should be invalid")
	}
	if !ValidPassword("123456") {
		t.Error("6 chars should be valid under the default (lax) policy")
	}
	if !ValidPassword("a-very-strong-password!") {
		t.Error("normal password should be valid")
	}
	tooLong := make([]byte, 73)
	for i := range tooLong {
		tooLong[i] = 'x'
	}
	if ValidPassword(string(tooLong)) {
		t.Error("73 chars should exceed bcrypt limit")
	}
}

func TestValidPasswordStrongRejectsCommons(t *testing.T) {
	for _, bad := range []string{
		"123456", "password", "abc123", "qwerty", "111111",
		"admin123", "letmein", "12345678",
	} {
		if ValidPasswordStrong(bad) {
			t.Errorf("strong(%q) = true; should be rejected (commons)", bad)
		}
	}
}

func TestValidPasswordStrongRequiresLetterAndDigitWhenShort(t *testing.T) {
	cases := []struct {
		pw   string
		want bool
	}{
		{"abcdef", false},  // 6 letters, no digit
		{"123987", false},  // 6 digits, no letter
		{"abc987", true},   // 6 chars, letter+digit, not in commons
		{"Aa1xyz", true},   // mixed
		{"!!!!@@", false},  // symbols only
		{"abcd1234", true}, // 8 chars, mixed
	}
	for _, c := range cases {
		got := ValidPasswordStrong(c.pw)
		if got != c.want {
			t.Errorf("strong(%q) = %v; want %v", c.pw, got, c.want)
		}
	}
}

func TestValidPasswordStrongAcceptsLongPassphrases(t *testing.T) {
	// 10+ chars bypass the letter+digit + dictionary check.
	if !ValidPasswordStrong("correcthorsebatterystaple") {
		t.Error("long all-letter passphrase should be valid in strict mode")
	}
	if !ValidPasswordStrong("a-very-strong-password!") {
		t.Error("long mixed passphrase should be valid in strict mode")
	}
}
