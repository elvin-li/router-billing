package shadowsocks

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestShareURIFormat(t *testing.T) {
	uri, err := ShareURI("aes-256-gcm", "s3cr3t-pw", "192.168.5.1", 8388, "router-ss")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "ss://") {
		t.Fatalf("missing ss:// prefix: %q", uri)
	}
	if !strings.Contains(uri, "@192.168.5.1:8388") {
		t.Errorf("missing host:port: %q", uri)
	}
	if !strings.HasSuffix(uri, "#router-ss") {
		t.Errorf("missing tag fragment: %q", uri)
	}
	// Decode the userinfo and confirm method:password.
	body := strings.TrimPrefix(uri, "ss://")
	at := strings.Index(body, "@")
	userinfo := body[:at]
	dec, err := base64.RawURLEncoding.DecodeString(userinfo)
	if err != nil {
		t.Fatalf("userinfo not base64url: %v", err)
	}
	if string(dec) != "aes-256-gcm:s3cr3t-pw" {
		t.Errorf("userinfo = %q, want aes-256-gcm:s3cr3t-pw", dec)
	}
}

func TestShareURIIPv6Host(t *testing.T) {
	uri, err := ShareURI("chacha20-ietf-poly1305", "pw", "fe80::1", 1080, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uri, "@[fe80::1]:1080") {
		t.Errorf("IPv6 host must be bracketed: %q", uri)
	}
	if strings.Contains(uri, "#") {
		t.Errorf("empty tag should not add a fragment: %q", uri)
	}
}

func TestShareURITagEscaping(t *testing.T) {
	uri, err := ShareURI("aes-128-gcm", "pw", "host", 80, "My Router SS")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(uri, "#My%20Router%20SS") {
		t.Errorf("space in tag not escaped: %q", uri)
	}
}

func TestShareURIRejectsBadInput(t *testing.T) {
	if _, err := ShareURI("rc4-md5", "pw", "h", 80, ""); err == nil {
		t.Error("expected error for unsupported method")
	}
	if _, err := ShareURI("aes-256-gcm", "", "h", 80, ""); err == nil {
		t.Error("expected error for empty password")
	}
	if _, err := ShareURI("aes-256-gcm", "pw", "h", 0, ""); err == nil {
		t.Error("expected error for port 0")
	}
	if _, err := ShareURI("aes-256-gcm", "pw", "h", 70000, ""); err == nil {
		t.Error("expected error for port > 65535")
	}
}
