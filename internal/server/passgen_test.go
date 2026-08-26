package server

import (
	"strings"
	"testing"
)

func TestRandomPasswordShape(t *testing.T) {
	for _, n := range []int{1, 10, 32} {
		p := randomPassword(n)
		if len(p) != n {
			t.Errorf("randomPassword(%d) length = %d", n, len(p))
		}
		for _, c := range p {
			if !strings.ContainsRune(pwAlphabet, c) {
				t.Errorf("randomPassword produced out-of-alphabet char %q", c)
			}
		}
	}
	if p := randomPassword(0); len(p) != 10 {
		t.Errorf("randomPassword(0) should default to 10 chars; got %d", len(p))
	}
}

// TestRandomPasswordUniform is a coarse uniformity check on the rejection
// sampling. The pre-fix modulo bias (256 % 57 != 0) gave the first 28
// alphabet symbols probability 5/256 (+11.3% vs uniform) and the rest
// 4/256 (-10.9%). At 200k samples the per-symbol sampling noise is ~1.7%
// (1 sigma), so an 8% tolerance is ~4.7 sigma — essentially never flaky —
// while the old systematic ±11% bias trips it reliably.
func TestRandomPasswordUniform(t *testing.T) {
	counts := map[rune]int{}
	const rounds = 20000
	for i := 0; i < rounds; i++ {
		for _, c := range randomPassword(10) {
			counts[c]++
		}
	}
	total := rounds * 10
	expected := float64(total) / float64(len(pwAlphabet))
	for _, c := range pwAlphabet {
		got := counts[c]
		if got == 0 {
			t.Errorf("symbol %q never appeared in %d draws", c, total)
		}
		if float64(got) > expected*1.08 || float64(got) < expected*0.92 {
			t.Errorf("symbol %q count %d deviates >8%% from expected %.0f", c, got, expected)
		}
	}
}
