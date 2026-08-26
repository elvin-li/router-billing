package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticateAdminPlaintext(t *testing.T) {
	c := &Config{Admin: Admin{Username: "alice", Password: "secret123"}}
	if !c.AuthenticateAdmin("alice", "secret123") {
		t.Error("correct creds rejected")
	}
	if c.AuthenticateAdmin("alice", "wrong") {
		t.Error("wrong password accepted")
	}
	if c.AuthenticateAdmin("bob", "secret123") {
		t.Error("wrong username accepted")
	}
}

func TestAuthenticateAdminHash(t *testing.T) {
	h, _ := bcrypt.GenerateFromPassword([]byte("p@ss"), 4) // cheap cost for test
	c := &Config{Admin: Admin{Username: "alice", PasswordHash: string(h)}}
	if !c.AuthenticateAdmin("alice", "p@ss") {
		t.Error("correct creds rejected")
	}
	if c.AuthenticateAdmin("alice", "wrong") {
		t.Error("wrong password accepted")
	}
}

func TestAuthenticateAdminMultiple(t *testing.T) {
	c := &Config{
		Admin: Admin{Username: "root", Password: "rootpw"},
		Admins: []Admin{
			{Username: "alice", Password: "alicepw"},
			{Username: "bob", Password: "bobpw"},
		},
	}
	for _, p := range []struct{ u, pw string }{
		{"root", "rootpw"}, {"alice", "alicepw"}, {"bob", "bobpw"},
	} {
		if !c.AuthenticateAdmin(p.u, p.pw) {
			t.Errorf("%s should authenticate", p.u)
		}
	}
	if c.AuthenticateAdmin("alice", "bobpw") {
		t.Error("cross-credential should not authenticate")
	}
}

func TestAdminListEmpty(t *testing.T) {
	c := &Config{}
	if got := c.AdminList(); len(got) != 0 {
		t.Errorf("empty config should have 0 admins, got %d", len(got))
	}
}

func TestSecurityAdminSessionTTLDefault(t *testing.T) {
	s := Security{}
	if got := s.AdminSessionTTL(); got != 12*time.Hour {
		t.Errorf("default admin TTL: got %s", got)
	}
}

func TestSecurityAdminSessionTTLCustom(t *testing.T) {
	s := Security{AdminSessionHours: 48}
	if got := s.AdminSessionTTL(); got != 48*time.Hour {
		t.Errorf("48h admin TTL: got %s", got)
	}
}

func TestSecurityAdminSessionTTLOutOfRange(t *testing.T) {
	cases := []int{-1, 0, 169, 1000}
	for _, h := range cases {
		got := Security{AdminSessionHours: h}.AdminSessionTTL()
		if got != 12*time.Hour {
			t.Errorf("out-of-range hours=%d should fallback to 12h; got %s", h, got)
		}
	}
}

func TestSecurityUserSessionTTLDefault(t *testing.T) {
	s := Security{}
	if got := s.UserSessionTTL(); got != 30*24*time.Hour {
		t.Errorf("default user TTL: got %s", got)
	}
}

func TestSecurityUserSessionTTLCustom(t *testing.T) {
	s := Security{UserSessionDays: 7}
	if got := s.UserSessionTTL(); got != 7*24*time.Hour {
		t.Errorf("7-day user TTL: got %s", got)
	}
}

func TestSecurityUserSessionTTLOutOfRange(t *testing.T) {
	cases := []int{-1, 0, 366, 10000}
	for _, d := range cases {
		got := Security{UserSessionDays: d}.UserSessionTTL()
		if got != 30*24*time.Hour {
			t.Errorf("out-of-range days=%d should fallback to 30d; got %s", d, got)
		}
	}
}

func TestSecurityAuditLogRetentionDefault(t *testing.T) {
	s := Security{}
	if got := s.AuditLogRetention(); got != 10000 {
		t.Errorf("default: got %d", got)
	}
}

func TestSecurityAuditLogRetentionCustom(t *testing.T) {
	s := Security{AuditLogKeep: 50000}
	if got := s.AuditLogRetention(); got != 50000 {
		t.Errorf("50000: got %d", got)
	}
}

func TestSecurityAuditLogRetentionClampsMin(t *testing.T) {
	s := Security{AuditLogKeep: 100}
	if got := s.AuditLogRetention(); got != 1000 {
		t.Errorf("100 should clamp to 1000; got %d", got)
	}
}

func TestSecurityAuditLogRetentionClampsMax(t *testing.T) {
	s := Security{AuditLogKeep: 9999999}
	if got := s.AuditLogRetention(); got != 1000000 {
		t.Errorf("9999999 should clamp to 1000000; got %d", got)
	}
}

// ---- Load() validation ------------------------------------------------------

// loadYAML writes the YAML to a temp file and runs the full Load pipeline
// (parse → applyDefaults → validate) — the same path --check-config takes.
func loadYAML(t *testing.T, yml string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

// validBase is the smallest config that must pass validation.
const validBase = "admin:\n  username: admin\n  password: changeme\n"

func TestLoadMinimalAppliesDefaults(t *testing.T) {
	c, err := loadYAML(t, validBase)
	if err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}
	if c.Listen != ":8080" || c.PortalPort != 8080 || c.Firewall.Backend != "nftables" {
		t.Errorf("defaults not applied: listen=%q portal_port=%d backend=%q",
			c.Listen, c.PortalPort, c.Firewall.Backend)
	}
	if len(c.Plans) == 0 || len(c.WalledGarden.Domains) == 0 {
		t.Error("default plans / walled-garden domains missing")
	}
}

// TestLoadExampleConfig pins the repo's example config as valid — the same
// guarantee CI's `--check-config config.example.yaml` step gives, but also
// enforced by plain `go test ./...` so a broken example can't slip through
// if the workflow step is ever reshuffled.
func TestLoadExampleConfig(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "config.example.yaml")); err != nil {
		t.Fatalf("config.example.yaml must always validate (CI is strict since v0.104): %v", err)
	}
}

func TestLoadRejections(t *testing.T) {
	bcryptHash, _ := bcrypt.GenerateFromPassword([]byte("p@ssw0rd!"), 4)
	cases := []struct {
		name string
		yml  string
		want string // substring of the expected error
	}{
		{"no admin", "listen: \":8080\"\n", "at least one admin"},
		{"admin missing username", "admins:\n  - password: longenough\n", "missing username"},
		{"admin no credentials", "admins:\n  - username: a\n", "no password or password_hash"},
		{"short plaintext password",
			"admin:\n  username: a\n  password: short7c\n",
			"at least 8 characters"},
		{"both password and hash",
			"admin:\n  username: a\n  password: longenough\n  password_hash: \"" + string(bcryptHash) + "\"\n",
			"both password and password_hash"},
		{"password_hash not bcrypt",
			"admin:\n  username: a\n  password_hash: \"5f4dcc3b5aa765d61d8327deb882cf99\"\n",
			"not a bcrypt hash"},
		{"totp_secret not base32",
			validBase + "admins:\n  - username: b\n    password: longenough\n    totp_secret: \"not!base32!\"\n",
			"totp_secret is not valid base32"},
		{"duplicate admin username",
			validBase + "admins:\n  - username: admin\n    password: longenough\n",
			"duplicate admin username"},
		{"empty api token",
			validBase + "api_tokens:\n  - label: monitor\n",
			"token is empty"},
		{"short api token",
			validBase + "api_tokens:\n  - token: shorttoken\n    label: monitor\n",
			"at least 16 characters"},
		{"duplicate api token",
			validBase + "api_tokens:\n  - token: aaaaaaaaaaaaaaaaaaaa\n  - token: aaaaaaaaaaaaaaaaaaaa\n",
			"duplicate token"},
		{"negative token rate limit",
			validBase + "api_tokens:\n  - token: aaaaaaaaaaaaaaaaaaaa\n    rate_limit_per_min: -5\n",
			"rate_limit_per_min"},
		{"short metrics token", validBase + "metrics_token: abc\n", "metrics_token"},
		{"listen without colon", validBase + "listen: \"8080\"\n", "listen"},
		{"listen port zero", validBase + "listen: \":0\"\n", "1..65535"},
		{"listen port huge", validBase + "listen: \":99999\"\n", "1..65535"},
		{"portal_port out of range", validBase + "portal_port: 70000\n", "portal_port"},
		{"portal_host with scheme", validBase + "portal_host: \"http://192.168.5.1\"\n", "portal_host"},
		{"plan zero days",
			validBase + "plans:\n  bad:\n    label: x\n    days: 0\n    price_cents: 100\n",
			"must be positive"},
		{"plan empty label",
			validBase + "plans:\n  bad:\n    label: \"\"\n    days: 30\n    price_cents: 100\n",
			"label must not be empty"},
		{"wechat enabled incomplete",
			validBase + "pay:\n  wechat:\n    enabled: true\n    mch_id: \"123\"\n",
			"pay.wechat"},
		{"wechat api_v3_key wrong length",
			validBase + "pay:\n  wechat:\n    enabled: true\n    mch_id: \"123\"\n    app_id: a\n    api_v3_key: tooshort\n    serial_no: s\n    private_key_path: /k.pem\n    notify_url: http://x\n",
			"api_v3_key must be exactly 32 bytes"},
		{"alipay enabled incomplete",
			validBase + "pay:\n  alipay:\n    enabled: true\n",
			"pay.alipay"},
		{"firewall backend typo", validBase + "firewall:\n  backend: nftablez\n", "firewall.backend"},
		{"firewall family typo", validBase + "firewall:\n  table: inet6\n", "firewall.table"},
		{"firewall table_name with space",
			validBase + "firewall:\n  table_name: \"billing extra\"\n",
			"firewall.table_name"},
		{"firewall set_name with brace",
			validBase + "firewall:\n  set_name: \"mac_paid}\"\n",
			"firewall.set_name"},
		{"firewall set_name with newline",
			validBase + "firewall:\n  set_name: \"mac\\npaid\"\n",
			"firewall.set_name"},
		{"ipset set_name too long for swap scratch",
			validBase + "firewall:\n  backend: ipset\n  set_name: \"a_very_long_ipset_name_28chr\"\n",
			"max 27 chars"},
		{"negative expire interval", validBase + "scheduler:\n  expire_check_interval: -1h\n", "expire_check_interval"},
		{"negative backup interval", validBase + "backup:\n  interval: -24h\n", "backup.interval"},
		{"negative backup retain", validBase + "backup:\n  retain_days: -1\n", "retain_days"},
		{"negative garden refresh", validBase + "walled_garden:\n  refresh_interval: -5m\n", "refresh_interval"},
		{"garden domain is a URL",
			validBase + "walled_garden:\n  domains: [\"https://weixin.qq.com/pay\"]\n",
			"bare domain"},
		{"garden domain empty", validBase + "walled_garden:\n  domains: [\"\"]\n", "empty entry"},
		{"password_strength typo",
			validBase + "security:\n  password_strength: strong\n",
			"password_strength"},
		{"negative hsts max age", validBase + "security:\n  hsts_max_age_seconds: -1\n", "hsts_max_age_seconds"},
		{"admin session hours over max", validBase + "security:\n  admin_session_hours: 300\n", "admin_session_hours"},
		{"user session days over max", validBase + "security:\n  user_session_days: 400\n", "user_session_days"},
		{"audit keep below min", validBase + "security:\n  audit_log_keep: 100\n", "audit_log_keep"},
		{"auto cancel over max", validBase + "security:\n  auto_cancel_stale_order_hours: 800\n", "auto_cancel_stale_order_hours"},
		{"sms provider typo", validBase + "sms:\n  provider: aliyum\n", "sms.provider"},
		{"sms aliyun incomplete",
			validBase + "sms:\n  provider: aliyun\n  aliyun:\n    access_key_id: k\n",
			"all required"},
		{"sms reminder days out of range", validBase + "sms:\n  expiry_reminder_days: 60\n", "expiry_reminder_days"},
		{"sms digest hour out of range", validBase + "sms:\n  admin_digest_hour: 25\n", "admin_digest_hour"},
		{"alert phone malformed",
			validBase + "sms:\n  provider: console\n  admin_login_alert_phone: \"12345\"\n",
			"admin_login_alert_phone"},
		{"digest hour without phone",
			validBase + "sms:\n  provider: console\n  admin_digest_hour: 9\n",
			"admin_login_alert_phone is empty"},
		{"digest hour with sms disabled",
			validBase + "sms:\n  admin_digest_hour: 9\n  admin_login_alert_phone: \"13800138000\"\n",
			"sms.provider is disabled"},
		{"tiny expire interval", validBase + "scheduler:\n  expire_check_interval: 1s\n", "at least 30s"},
		{"tiny backup interval", validBase + "backup:\n  interval: 5s\n", "at least 10m"},
		{"tiny garden refresh", validBase + "walled_garden:\n  refresh_interval: 1s\n", "at least 30s"},
		{"webhook bad scheme",
			validBase + "webhook:\n  url: \"ftp://hook.example\"\n  secret: s3cretlong\n",
			"webhook.url"},
		{"webhook without secret",
			validBase + "webhook:\n  url: \"https://hook.example/rb\"\n",
			"webhook.secret is empty"},
		{"trusted proxy garbage",
			validBase + "security:\n  trusted_proxies: [\"not-a-net\"]\n",
			"trusted_proxies"},
		{"trusted proxy bad cidr",
			validBase + "security:\n  trusted_proxies: [\"10.0.0.0/33\"]\n",
			"not a valid CIDR"},
		{"trusted proxy empty entry",
			validBase + "security:\n  trusted_proxies: [\"\"]\n",
			"empty entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadYAML(t, tc.yml)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLoadAcceptsHardenedConfig(t *testing.T) {
	bcryptHash, _ := bcrypt.GenerateFromPassword([]byte("p@ssw0rd!"), 4)
	yml := validBase +
		"admins:\n" +
		"  - username: alice\n" +
		"    password_hash: \"" + string(bcryptHash) + "\"\n" +
		"    totp_secret: JBSWY3DPEHPK3PXP\n" +
		"api_tokens:\n" +
		"  - token: 0123456789abcdef0123456789abcdef\n" +
		"    label: monitoring\n" +
		"    readonly: true\n" +
		"    rate_limit_per_min: 60\n" +
		"metrics_token: metrics-scraper-token\n" +
		"listen: \"0.0.0.0:8080\"\n" +
		"security:\n" +
		"  password_strength: strict\n" +
		"  admin_session_hours: 24\n" +
		"  user_session_days: 90\n" +
		"  audit_log_keep: 50000\n" +
		"  auto_cancel_stale_order_hours: 48\n" +
		"  trusted_proxies: [\"127.0.0.1\", \"10.0.0.0/8\", \"::1\", \"fd00::/8\"]\n" +
		"sms:\n" +
		"  provider: console\n" +
		"  admin_login_alert_phone: \"13800138000\"\n" +
		"  admin_digest_hour: 9\n" +
		"webhook:\n" +
		"  url: \"https://hook.example/rb\"\n" +
		"  secret: a-long-random-shared-secret\n"
	c, err := loadYAML(t, yml)
	if err != nil {
		t.Fatalf("hardened config rejected: %v", err)
	}
	if !c.Security.PasswordStrengthStrict() {
		t.Error("password_strength strict not picked up")
	}
	if tok := c.MatchAPITokenFull("0123456789abcdef0123456789abcdef"); tok == nil || !tok.ReadOnly {
		t.Error("api token not matched / readonly lost")
	}
}

// Case/whitespace variants of password_strength must be accepted — the
// runtime check is EqualFold+TrimSpace, so validation has to agree.
func TestLoadPasswordStrengthVariants(t *testing.T) {
	for _, v := range []string{"lax", "strict", "Strict", " STRICT ", ""} {
		if _, err := loadYAML(t, validBase+"security:\n  password_strength: \""+v+"\"\n"); err != nil {
			t.Errorf("password_strength %q should be accepted: %v", v, err)
		}
	}
}
