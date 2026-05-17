package server

import "fmt"

// humanBytes formats byte counts as B / KB / MB / GB / TB with one decimal.
// Uses 1024 base (binary). Empty string for zero — keeps the device table tidy.
func humanBytes(n uint64) string {
	if n == 0 {
		return ""
	}
	const k = 1024
	if n < k {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	for _, unit := range []string{"KB", "MB", "GB", "TB", "PB"} {
		v /= k
		if v < k {
			if v >= 100 {
				return fmt.Sprintf("%.0f %s", v, unit)
			}
			return fmt.Sprintf("%.1f %s", v, unit)
		}
	}
	return fmt.Sprintf("%.1f EB", v/k)
}
