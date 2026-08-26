package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const baseAdmin = "admin:\n  username: admin\n  password: changeme\n"

func TestShadowsocksDefaultsOff(t *testing.T) {
	p := writeTempConfig(t, baseAdmin)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Shadowsocks.Enabled {
		t.Error("shadowsocks must default to disabled")
	}
	if c.Shadowsocks.Method != "chacha20-ietf-poly1305" {
		t.Errorf("default method = %q", c.Shadowsocks.Method)
	}
}

func TestShadowsocksEnabledValid(t *testing.T) {
	body := baseAdmin + `
shadowsocks:
  enabled: true
  listen: "192.168.5.1:8388"
  method: "aes-256-gcm"
  password: "a-strong-password"
  allowed_cidrs: ["192.168.0.0/16"]
  max_conns: 128
  timeout: 3m
  tag: "my-router"
`
	p := writeTempConfig(t, body)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if !c.Shadowsocks.Enabled {
		t.Fatal("expected enabled")
	}
	if c.Shadowsocks.ListenPort() != 8388 {
		t.Errorf("ListenPort = %d, want 8388", c.Shadowsocks.ListenPort())
	}
	if c.Shadowsocks.Timeout != 3*time.Minute {
		t.Errorf("timeout = %v", c.Shadowsocks.Timeout)
	}
	cidrs, err := c.Shadowsocks.ParsedCIDRs()
	if err != nil || len(cidrs) != 1 {
		t.Errorf("ParsedCIDRs = %v, %v", cidrs, err)
	}
}

func TestShadowsocksEnabledMissingPassword(t *testing.T) {
	body := baseAdmin + `
shadowsocks:
  enabled: true
  listen: "192.168.5.1:8388"
  method: "aes-256-gcm"
`
	p := writeTempConfig(t, body)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: enabled with empty password")
	}
}

func TestShadowsocksEnabledMissingListen(t *testing.T) {
	body := baseAdmin + `
shadowsocks:
  enabled: true
  method: "aes-256-gcm"
  password: "x-strong-pw"
`
	p := writeTempConfig(t, body)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: enabled with empty listen")
	}
}

func TestShadowsocksEnabledBadListenPort(t *testing.T) {
	body := baseAdmin + `
shadowsocks:
  enabled: true
  listen: "192.168.5.1:not-a-port"
  method: "aes-256-gcm"
  password: "x-strong-pw"
`
	p := writeTempConfig(t, body)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: non-numeric port")
	}
}

func TestShadowsocksBadMethodEvenWhenDisabled(t *testing.T) {
	body := baseAdmin + `
shadowsocks:
  enabled: false
  method: "rc4-md5"
`
	p := writeTempConfig(t, body)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: unsupported cipher should fail even when disabled")
	}
}

func TestShadowsocksBadCIDR(t *testing.T) {
	body := baseAdmin + `
shadowsocks:
  enabled: true
  listen: "192.168.5.1:8388"
  method: "aes-256-gcm"
  password: "x-strong-pw"
  allowed_cidrs: ["not-a-cidr"]
`
	p := writeTempConfig(t, body)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error: malformed CIDR")
	}
}

func TestShadowsocksAdvertiseHostFallback(t *testing.T) {
	s := Shadowsocks{}
	if got := s.AdvertiseHostOr("192.168.5.1"); got != "192.168.5.1" {
		t.Errorf("fallback = %q", got)
	}
	s.AdvertiseHost = "ss.example.com"
	if got := s.AdvertiseHostOr("192.168.5.1"); got != "ss.example.com" {
		t.Errorf("explicit = %q", got)
	}
}

func TestShadowsocksTagOr(t *testing.T) {
	s := Shadowsocks{}
	if got := s.TagOr(); got != "router-billing" {
		t.Errorf("default tag = %q", got)
	}
	s.Tag = "custom"
	if got := s.TagOr(); got != "custom" {
		t.Errorf("custom tag = %q", got)
	}
}
