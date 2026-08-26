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

// TestNewUniform is a coarse uniformity check on the rejection sampling.
// The pre-fix modulo bias (256 % 31 = 8) gave the first 8 alphabet symbols
// probability 9/256 (+12.5% vs uniform) and the rest 8/256. At 240k drawn
// symbols the per-symbol sampling noise is ~1.1% (1 sigma), so an 8%
// tolerance is ~7 sigma — essentially never flaky — while the old
// systematic +12.5% bias trips it reliably.
func TestNewUniform(t *testing.T) {
	counts := map[rune]int{}
	const rounds = 20000
	for i := 0; i < rounds; i++ {
		c, err := New()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range c {
			counts[r]++
		}
	}
	total := rounds * 12
	expected := float64(total) / float64(len(alphabet))
	for _, r := range alphabet {
		got := counts[r]
		if got == 0 {
			t.Errorf("symbol %q never appeared in %d draws", r, total)
		}
		if float64(got) > expected*1.08 || float64(got) < expected*0.92 {
			t.Errorf("symbol %q count %d deviates >8%% from expected %.0f", r, got, expected)
		}
	}
}
