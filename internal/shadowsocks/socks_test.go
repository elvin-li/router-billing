package shadowsocks

import (
	"bytes"
	"testing"
)

func TestTargetAddrRoundTrip(t *testing.T) {
	cases := []struct {
		host string
		port int
	}{
		{"1.2.3.4", 80},
		{"93.184.216.34", 443},
		{"2606:2800:220:1:248:1893:25c8:1946", 8080},
		{"example.com", 443},
		{"a.very-long.subdomain.example.museum", 65535},
	}
	for _, c := range cases {
		enc, err := encodeTargetAddr(c.host, c.port)
		if err != nil {
			t.Fatalf("encode %s:%d: %v", c.host, c.port, err)
		}
		got, err := readTargetAddr(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("decode %s:%d: %v", c.host, c.port, err)
		}
		if got.port != c.port {
			t.Errorf("%s: port = %d, want %d", c.host, got.port, c.port)
		}
		// IPv6 canonicalizes; compare via re-encode to normalize.
		if got.host != c.host {
			// For IPv6, net.IP.String may canonicalize — re-encode and compare bytes.
			reenc, _ := encodeTargetAddr(got.host, got.port)
			if !bytes.Equal(enc, reenc) {
				t.Errorf("%s: host round-trip mismatch, got %q", c.host, got.host)
			}
		}
	}
}

func TestReadTargetAddrRejectsBadATYP(t *testing.T) {
	_, err := readTargetAddr(bytes.NewReader([]byte{0x09, 1, 2, 3}))
	if err == nil {
		t.Fatal("expected error for unknown ATYP 0x09")
	}
}

func TestReadTargetAddrRejectsEmptyDomain(t *testing.T) {
	// atyp=domain, len=0
	_, err := readTargetAddr(bytes.NewReader([]byte{atypDomain, 0x00, 0x00, 0x50}))
	if err == nil {
		t.Fatal("expected error for zero-length domain")
	}
}

func TestReadTargetAddrTruncated(t *testing.T) {
	// atyp=ipv4 but only 2 of the required 6 bytes present.
	_, err := readTargetAddr(bytes.NewReader([]byte{atypIPv4, 1, 2}))
	if err == nil {
		t.Fatal("expected error for truncated ipv4 address")
	}
}

func TestEncodeTargetAddrRejectsBadInput(t *testing.T) {
	if _, err := encodeTargetAddr("example.com", 70000); err == nil {
		t.Error("expected error for out-of-range port")
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := encodeTargetAddr(string(long), 80); err == nil {
		t.Error("expected error for 256-char domain")
	}
}
