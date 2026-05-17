package voucher

import (
	"strings"
	"testing"
)

func TestNewIsCanon(t *testing.T) {
	for i := 0; i < 100; i++ {
		c, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 12 {
			t.Errorf("len = %d", len(c))
		}
		for _, ch := range c {
			if !strings.ContainsRune(alphabet, ch) {
				t.Errorf("bad char %q in %s", ch, c)
			}
		}
		if err := Validate(c); err != nil {
			t.Errorf("Validate(%s): %v", c, err)
		}
	}
}

func TestPretty(t *testing.T) {
	cases := map[string]string{
		"7K8M-XQNR-3HJP":  "7K8M-XQNR-3HJP",
		"7k8mxqnr3hjp":    "7K8M-XQNR-3HJP",
		"7K 8M XQ NR3HJP": "7K8M-XQNR-3HJP",
	}
	for in, want := range cases {
		if got := Pretty(in); got != want {
			t.Errorf("Pretty(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	good := []string{"7K8MXQNR3HJP", "7K8M-XQNR-3HJP", "2345-6789-ABCD"}
	for _, c := range good {
		if err := Validate(c); err != nil {
			t.Errorf("good %q: %v", c, err)
		}
	}
	bad := []string{"", "ABC", "7K8MXQNR3HJP1", "7K8MXQNR3HJ0", "OOOOOOOOOOOO", "111111111111"}
	for _, c := range bad {
		if err := Validate(c); err == nil {
			t.Errorf("bad %q: expected error", c)
		}
	}
}
