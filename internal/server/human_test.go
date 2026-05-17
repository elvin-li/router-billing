package server

import "testing"

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		0:                    "",
		1:                    "1 B",
		1023:                 "1023 B",
		1024:                 "1.0 KB",
		1536:                 "1.5 KB",
		1048576:              "1.0 MB",
		104857600:            "100 MB",
		1073741824:           "1.0 GB",
		1099511627776:        "1.0 TB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
