package config

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"router-billing/internal/models"
	"router-billing/internal/totp"
)

type Config struct {
	Listen       string          `yaml:"listen"`
	DBPath       string          `yaml:"db_path"`
	WebRoot      string          `yaml:"web_root"`
	PaidIface    string          `yaml:"paid_iface"`
	PortalHost   string          `yaml:"portal_host"`
	PortalPort   int             `yaml:"portal_port"`
	Admin        Admin           `yaml:"admin"`         // legacy single-admin
	Admins       []Admin         `yaml:"admins"`        // multi-admin list
	APITokens    []APIToken      `yaml:"api_tokens"`    // Bearer tokens for /api/admin/*
	MetricsToken string          `yaml:"metrics_token"` // optional bearer for /metrics
	SSIDs        SSIDInfo        `yaml:"ssids"`         // displayed on /admin/ssid-cards
	Plans        map[string]Plan `yaml:"plans"`
	Pay          Pay             `yaml:"pay"`
	Firewall     Firewall        `yaml:"firewall"`
	Scheduler    Scheduler       `yaml:"scheduler"`
	Backup       Backup          `yaml:"backup"`
	SMS          SMSConfig       `yaml:"sms"` // optional SMS provider
	Webhook      Webhook         `yaml:"webhook"`
	WalledGarden WalledGarden    `yaml:"walled_garden"`
	Security     Security        `yaml:"security"`
}

// Security holds opt-in hardening knobs that aren't safe-by-default
// (e.g. HSTS preload is a one-way trip — once a browser caches the
// preload directive it ignores any later removal for the max-age).
type Security struct {
	// HSTSMaxAgeSeconds overrides the default 31536000 (1 year) value.
	// Set to 63072000 (2 years) to be eligible for hstspreload.org.
	// Set to 0 to use the default.
	HSTSMaxAgeSeconds int `yaml:"hsts_max_age_seconds,omitempty"`
	// HSTSIncludeSubdomains adds "includeSubDomains" to the header.
	// Only enable when EVERY subdomain of your apex serves TLS; otherwise
	// a browser that gets this directive will refuse non-TLS subdomain
	// loads forever (within max-age).
	HSTSIncludeSubdomains bool `yaml:"hsts_include_subdomains,omitempty"`
	// HSTSPreload adds "preload". Submit your domain to hstspreload.org
	// AFTER you've verified your site survives the 2-year max-age +
	// includeSubdomains commitment. Cannot be undone for cached browsers.
	HSTSPreload bool `yaml:"hsts_preload,omitempty"`

	// AdminSessionHours overrides the default 12 (hours). Sets how long
	// an admin's rb_admin cookie stays valid after login. Range 1..168
	// (1 week max). 0/missing → use default.
	AdminSessionHours int `yaml:"admin_session_hours,omitempty"`
	// UserSessionDays overrides the default 30 (days). Sets how long a
	// user's rb_user cookie stays valid. Range 1..365. 0/missing → use
	// default.
	UserSessionDays int `yaml:"user_session_days,omitempty"`
	// AuditLogKeep is the max number of audit_log rows to retain. The
	// 2-hour janitor purges anything older when the table grows past
	// this count. Default 10000, range 1000..1000000. Set to 0 to use
	// the default. There's intentionally no "unlimited" — an audit
	// table that grows forever will eventually hurt query latency.
	AuditLogKeep int `yaml:"audit_log_keep,omitempty"`

	// PasswordStrength selects which validator runs at user register /
	// reset:
	//   "" / "lax"    → models.ValidPassword (length-only)
	//   "strict"      → models.ValidPasswordStrong (commons + letter+digit)
	// Default "" / lax preserves the original v0.0 behavior.
	PasswordStrength string `yaml:"password_strength,omitempty"`

	// AutoCancelStaleOrderHours: when > 0, the 2-hour purgeLoop also
	// flips every order with status='pending' AND created_at older than
	// this many hours to status='failed'. Same atomic semantics as v0.55's
	// /api/admin/orders/cancel-stale; this saves operators having to
	// wire up cron. 0 (default) = disabled. Clamped to [1, 720] (1h .. 30d).
	AutoCancelStaleOrderHours int `yaml:"auto_cancel_stale_order_hours,omitempty"`

	// TrustedProxies lists reverse-proxy addresses (single IPs or CIDRs,
	// e.g. "127.0.0.1" / "10.0.0.0/8") whose X-Forwarded-For header may be
	// believed for the client IP. Requests arriving from anywhere else
	// have the header ignored — otherwise any direct client could rotate
	// a fake X-Forwarded-For to sidestep every per-IP rate limit and to
	// forge the IPs recorded in the audit log. Empty (default) = never
	// trust the header; deployments behind nginx/Caddy should list the
	// proxy here to keep per-client rate-limit keying.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
}

// AutoCancelStaleOrders returns the clamped hours window or 0 (disabled).
func (s Security) AutoCancelStaleOrders() int {
	h := s.AutoCancelStaleOrderHours
	if h <= 0 {
		return 0
	}
	if h < 1 {
		return 1
	}
	if h > 720 {
		return 720
	}
	return h
}

// PasswordStrengthStrict returns true when the config opts into the
// strict (commons + letter+digit) validator.
func (s Security) PasswordStrengthStrict() bool {
	return strings.EqualFold(strings.TrimSpace(s.PasswordStrength), "strict")
}

// AuditLogKeep returns the clamped retention count.
func (s Security) AuditLogRetention() int {
	n := s.AuditLogKeep
	if n <= 0 {
		return 10000
	}
	if n < 1000 {
		return 1000
	}
	if n > 1000000 {
		return 1000000
	}
	return n
}

// AdminSessionTTL returns the configured admin session lifetime, falling
// back to the package default when unset / out of range.
func (s Security) AdminSessionTTL() time.Duration {
	h := s.AdminSessionHours
	if h <= 0 || h > 168 {
		h = 12
	}
	return time.Duration(h) * time.Hour
}

// UserSessionTTL returns the configured user session lifetime, falling
// back to the package default when unset / out of range.
func (s Security) UserSessionTTL() time.Duration {
	d := s.UserSessionDays
	if d <= 0 || d > 365 {
		d = 30
	}
	return time.Duration(d) * 24 * time.Hour
}

// Admin is either {username,password} or {username,password_hash}.
// password_hash is a bcrypt hash (`htpasswd -nB` or our --gen-password-hash CLI).
//
// totp_secret (optional) — base32-encoded RFC 6238 secret. When set, this
// admin's login asks for a 6-digit code in addition to the password.
// Generate with `--gen-totp-secret`.
type Admin struct {
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	PasswordHash string `yaml:"password_hash"`
	TOTPSecret   string `yaml:"totp_secret"`
}

// SSIDInfo holds the names + secure-SSID password so admins can render printable
// join-WiFi QR cards. Optional — purely informational.
// APIToken is a Bearer token that grants programmatic admin access. Set
// `Token` to a long random string (generate with `--gen-api-token`) and
// `Label` to whatever describes the consumer (e.g. "monitoring-script").
// The token compares constant-time; rotating = remove + add a new line.
type APIToken struct {
	Token string `yaml:"token"`
	Label string `yaml:"label"`
	// ReadOnly limits the token to GET endpoints (/api/admin/health,
	// /api/admin/macs). Default false = legacy full access, so adding
	// `readonly: true` to a token is a strict tightening — never a break.
	// Useful for monitoring scripts / dashboards that should never be
	// able to grant or revoke MAC subscriptions.
	ReadOnly bool `yaml:"readonly,omitempty"`
	// RateLimitPerMin caps how many requests this token can make per
	// minute (rolling 60s window). 0/missing = no limit. Helpful when a
	// bug in a monitoring script could otherwise hammer /api/admin/macs
	// every second.
	RateLimitPerMin int `yaml:"rate_limit_per_min,omitempty"`
}

// SSIDInfo names + PSK keys for the printable SSID-cards page.
//
// As of v0.9 the "Free" SSID is intended for trusted friends + the
// admin's own management traffic — it MUST have a WPA2 key
// (free_key). The cards page renders the key alongside the QR so the
// admin can show it on the printed card.
type SSIDInfo struct {
	Free       string `yaml:"free"`
	FreeKey    string `yaml:"free_key"` // WPA2-PSK for the friends/management SSID
	Paid       string `yaml:"paid"`
	PaidSecure string `yaml:"paid_secure"`
	PaidKey    string `yaml:"paid_secure_key"`
}

type Plan struct {
	Label      string `yaml:"label"`
	Days       int    `yaml:"days"`
	PriceCents int    `yaml:"price_cents"`
}

type Pay struct {
	WeChat WeChat `yaml:"wechat"`
	Alipay Alipay `yaml:"alipay"`
}

type WeChat struct {
	Enabled        bool   `yaml:"enabled"`
	MchID          string `yaml:"mch_id"`
	AppID          string `yaml:"app_id"`
	APIv3Key       string `yaml:"api_v3_key"`
	SerialNo       string `yaml:"serial_no"`
	PrivateKeyPath string `yaml:"private_key_path"`
	NotifyURL      string `yaml:"notify_url"`
}

type Alipay struct {
	Enabled             bool   `yaml:"enabled"`
	AppID               string `yaml:"app_id"`
	PrivateKeyPath      string `yaml:"private_key_path"`
	AlipayPublicKeyPath string `yaml:"alipay_public_key_path"`
	NotifyURL           string `yaml:"notify_url"`
	Gateway             string `yaml:"gateway"`
}

type Firewall struct {
	Backend   string `yaml:"backend"`
	Table     string `yaml:"table"`
	TableName string `yaml:"table_name"`
	SetName   string `yaml:"set_name"`
}

type Scheduler struct {
	ExpireCheckInterval time.Duration `yaml:"expire_check_interval"`
}

type Backup struct {
	Enabled    bool          `yaml:"enabled"`
	Dir        string        `yaml:"dir"`
	RetainDays int           `yaml:"retain_days"`
	Interval   time.Duration `yaml:"interval"`
}

// SMSConfig selects which SMS provider (if any) backs the password-reset
// and notification flows.
//
//	sms:
//	  provider: aliyun      # "" / console / aliyun
//	  aliyun:
//	    access_key_id: ...
//	    access_key_secret: ...
//	    sign_name: MyApp
//	    template_code: SMS_1234
//
// When provider == "" SMS features are disabled gracefully — handlers
// either degrade to the existing "show temp password once" path or hide
// the SMS button entirely.
type SMSConfig struct {
	Provider string       `yaml:"provider"`
	Aliyun   AliyunSMSCfg `yaml:"aliyun"`
	// ExpiryReminderDays sets how many days before a MAC expires to text
	// the owner. Default 3, range 1..30. 0/missing → 3.
	ExpiryReminderDays int `yaml:"expiry_reminder_days,omitempty"`
	// ExpiryReminderDisable turns off the background reminder loop entirely.
	// Useful if a deployer wants ONLY admin-triggered sends.
	ExpiryReminderDisable bool `yaml:"expiry_reminder_disable,omitempty"`
	// AdminLoginAlertPhone, if set to a valid mobile number, gets a text
	// every time an admin successfully logs in. Useful as a "did I just
	// log in at 3am?" alarm — surfaces credential compromises fast.
	// Disabled (no SMS sent) when empty / when no SMS provider is wired.
	AdminLoginAlertPhone string `yaml:"admin_login_alert_phone,omitempty"`

	// AdminDigestHour, if 1..24, enables a daily summary SMS to
	// AdminLoginAlertPhone at the given UTC hour. Body covers yesterday's
	// revenue, today's MACs expiring soon, and failed-orders count. 0 =
	// disabled.
	AdminDigestHour int `yaml:"admin_digest_hour,omitempty"`
}

// ExpiryReminderWindowDays returns the configured window, clamped to
// a safe range.
func (s SMSConfig) ExpiryReminderWindowDays() int {
	d := s.ExpiryReminderDays
	if d <= 0 || d > 30 {
		d = 3
	}
	return d
}

type AliyunSMSCfg struct {
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	SignName        string `yaml:"sign_name"`
	TemplateCode    string `yaml:"template_code"`
}

// Webhook config — outbound notifications to a user-supplied URL.
// The receiver should verify the X-Router-Billing-Signature header (sha256
// HMAC of the body, hex-encoded, prefixed with `sha256=`).
type Webhook struct {
	URL    string `yaml:"url"`
	Secret string `yaml:"secret"`
}

// WalledGarden lets unpaid devices on Paid_WiFi reach a short list of domains
// (typically WeChat / Alipay servers) so they can complete payment without
// being whitelisted first. Domains are re-resolved every RefreshInterval; an
// nftables ipv4 set is kept in sync. IPv6 is not supported yet.
type WalledGarden struct {
	Domains         []string      `yaml:"domains"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.DBPath == "" {
		c.DBPath = "/var/lib/router-billing/billing.db"
	}
	if c.WebRoot == "" {
		c.WebRoot = "/usr/share/router-billing/web"
	}
	if c.PaidIface == "" {
		c.PaidIface = "br-paid"
	}
	if c.PortalPort == 0 {
		c.PortalPort = 8080
	}
	if c.Firewall.Backend == "" {
		c.Firewall.Backend = "nftables"
	}
	if c.Firewall.Table == "" {
		c.Firewall.Table = "inet"
	}
	if c.Firewall.TableName == "" {
		c.Firewall.TableName = "billing"
	}
	if c.Firewall.SetName == "" {
		c.Firewall.SetName = "mac_paid"
	}
	if c.Scheduler.ExpireCheckInterval == 0 {
		c.Scheduler.ExpireCheckInterval = time.Hour
	}
	if c.Backup.Interval == 0 {
		c.Backup.Interval = 24 * time.Hour
	}
	if c.Backup.RetainDays == 0 {
		c.Backup.RetainDays = 7
	}
	if c.WalledGarden.RefreshInterval == 0 {
		c.WalledGarden.RefreshInterval = 5 * time.Minute
	}
	if len(c.WalledGarden.Domains) == 0 {
		// Sensible defaults so a fresh install with the right kernel can pay
		// without admin intervention.
		c.WalledGarden.Domains = []string{
			// Captive portal probes (so the OS pops the login)
			"captive.apple.com", "connectivitycheck.gstatic.com",
			"www.msftncsi.com", "www.msftconnecttest.com",
			// WeChat Pay
			"weixin.qq.com", "wx.qq.com", "wx.tenpay.com",
			"api.mch.weixin.qq.com", "wxpaylogo.tenpay.com",
			"long.weixin.qq.com", "short.weixin.qq.com",
			// Alipay
			"alipay.com", "mclient.alipay.com", "mapi.alipay.com",
			"openapi.alipay.com", "render.alipay.com",
			"alipayobjects.com",
			// NTP so clocks sync
			"pool.ntp.org", "time.windows.com", "time.apple.com",
		}
	}
	if len(c.Plans) == 0 {
		c.Plans = map[string]Plan{
			"month": {Label: "1 个月", Days: 30, PriceCents: 100},
			"year":  {Label: "1 年", Days: 365, PriceCents: 1000},
		}
	}
}

func (c *Config) validate() error {
	checks := []func() error{
		c.validateAdmins,
		c.validateTokens,
		c.validateNetwork,
		c.validatePlans,
		c.validatePay,
		c.validateFirewall,
		c.validateDurations,
		c.validateSecurity,
		c.validateSMS,
		c.validateWebhook,
		c.validateWalledGarden,
	}
	for _, f := range checks {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateAdmins() error {
	admins := c.AdminList()
	if len(admins) == 0 {
		return fmt.Errorf("at least one admin is required (set admin.* or admins[])")
	}
	seen := map[string]bool{}
	for _, a := range admins {
		if a.Username == "" {
			return fmt.Errorf("admin entry missing username")
		}
		if seen[a.Username] {
			return fmt.Errorf("duplicate admin username %q (check admin: vs admins[])", a.Username)
		}
		seen[a.Username] = true
		if a.Password == "" && a.PasswordHash == "" {
			return fmt.Errorf("admin %q has no password or password_hash", a.Username)
		}
		if a.Password != "" && a.PasswordHash != "" {
			return fmt.Errorf("admin %q sets both password and password_hash — keep only password_hash", a.Username)
		}
		if a.PasswordHash != "" {
			// Catch "pasted the plaintext / a sha256 hex into password_hash"
			// at load time instead of silently locking the admin out at login
			// (bcrypt.CompareHashAndPassword never matches a non-bcrypt hash).
			if _, err := bcrypt.Cost([]byte(a.PasswordHash)); err != nil {
				return fmt.Errorf("admin %q: password_hash is not a bcrypt hash (%v); generate one with --gen-password-hash", a.Username, err)
			}
		} else if len(a.Password) < 8 {
			return fmt.Errorf("admin %q: plaintext password must be at least 8 characters (prefer password_hash; see --gen-password-hash)", a.Username)
		}
		if a.TOTPSecret != "" {
			// A non-base32 secret means Verify() always returns false —
			// i.e. permanent 2FA lockout discovered only at the login prompt.
			if _, err := totp.Code(a.TOTPSecret, 0); err != nil {
				return fmt.Errorf("admin %q: totp_secret is not valid base32 (%v); generate one with --gen-totp-secret", a.Username, err)
			}
		}
	}
	return nil
}

func (c *Config) validateTokens() error {
	seen := map[string]int{}
	for i, t := range c.APITokens {
		name := t.Label
		if name == "" {
			name = fmt.Sprintf("entry #%d", i+1)
		}
		if strings.TrimSpace(t.Token) == "" {
			// MatchAPITokenFull skips empty tokens, so the operator would
			// believe a token is configured while every request 401s.
			return fmt.Errorf("api_tokens %s: token is empty (the entry would be silently ignored)", name)
		}
		if len(t.Token) < 16 {
			return fmt.Errorf("api_tokens %s: token must be at least 16 characters — use a long random string", name)
		}
		if j, dup := seen[t.Token]; dup {
			return fmt.Errorf("api_tokens %s: duplicate token value (same as entry #%d)", name, j+1)
		}
		seen[t.Token] = i
		if t.RateLimitPerMin < 0 {
			return fmt.Errorf("api_tokens %s: rate_limit_per_min must be >= 0", name)
		}
	}
	if c.MetricsToken != "" && len(c.MetricsToken) < 8 {
		return fmt.Errorf("metrics_token must be at least 8 characters when set (leave empty for a public /metrics)")
	}
	return nil
}

func (c *Config) validateNetwork() error {
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen %q: %v (want \"host:port\" or \":port\")", c.Listen, err)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("listen %q: port must be a number in 1..65535", c.Listen)
	}
	if c.PortalPort < 1 || c.PortalPort > 65535 {
		return fmt.Errorf("portal_port %d: must be in 1..65535", c.PortalPort)
	}
	if h := strings.TrimSpace(c.PortalHost); strings.Contains(h, "://") || strings.ContainsAny(h, "/ \t") {
		return fmt.Errorf("portal_host %q: must be a bare hostname or IP (no scheme, path or spaces)", c.PortalHost)
	}
	return nil
}

func (c *Config) validatePlans() error {
	for k, p := range c.Plans {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("plans: plan key must not be empty")
		}
		if p.Days <= 0 || p.PriceCents <= 0 {
			return fmt.Errorf("plan %q: days and price_cents must be positive", k)
		}
		if strings.TrimSpace(p.Label) == "" {
			return fmt.Errorf("plan %q: label must not be empty", k)
		}
	}
	return nil
}

func (c *Config) validatePay() error {
	if c.Pay.WeChat.Enabled {
		if c.Pay.WeChat.MchID == "" || c.Pay.WeChat.AppID == "" ||
			c.Pay.WeChat.APIv3Key == "" || c.Pay.WeChat.SerialNo == "" ||
			c.Pay.WeChat.PrivateKeyPath == "" || c.Pay.WeChat.NotifyURL == "" {
			return fmt.Errorf("pay.wechat enabled but credentials incomplete")
		}
		// AES-256-GCM requires exactly 32 bytes; otherwise every callback
		// fails at aes.NewCipher instead of at --check-config/startup.
		if len(c.Pay.WeChat.APIv3Key) != 32 {
			return fmt.Errorf("pay.wechat api_v3_key must be exactly 32 bytes (got %d)", len(c.Pay.WeChat.APIv3Key))
		}
	}
	if c.Pay.Alipay.Enabled {
		if c.Pay.Alipay.AppID == "" || c.Pay.Alipay.PrivateKeyPath == "" ||
			c.Pay.Alipay.AlipayPublicKeyPath == "" || c.Pay.Alipay.NotifyURL == "" {
			return fmt.Errorf("pay.alipay enabled but credentials incomplete")
		}
		if c.Pay.Alipay.Gateway == "" {
			c.Pay.Alipay.Gateway = "https://openapi.alipay.com/gateway.do"
		}
	}
	return nil
}

// validateFirewall mirrors firewall.NewBackend's accepted names so a typo
// fails --check-config instead of log.Fatal'ing at boot.
func (c *Config) validateFirewall() error {
	switch strings.ToLower(strings.TrimSpace(c.Firewall.Backend)) {
	case "", "nft", "nftables", "ipt", "iptables", "ipset":
		return nil
	default:
		return fmt.Errorf("firewall.backend %q: must be nftables or iptables", c.Firewall.Backend)
	}
}

// validateDurations rejects negative intervals. applyDefaults only fills
// zero values, so a negative typo used to pass --check-config and then be
// silently replaced by a hardcoded fallback deep in each goroutine.
//
// Sub-second typos are rejected too (e.g. `expire_check_interval: 1s`
// meant as `1h`, or a forgotten unit yaml parses as nanoseconds): each of
// these intervals drives a loop that hits the DB, forks nft, or
// re-resolves DNS — at a near-zero cadence they busy-loop a
// resource-constrained router into the ground while --check-config
// stayed green.
func (c *Config) validateDurations() error {
	if c.Scheduler.ExpireCheckInterval < 0 {
		return fmt.Errorf("scheduler.expire_check_interval must not be negative")
	}
	if c.Scheduler.ExpireCheckInterval != 0 && c.Scheduler.ExpireCheckInterval < 30*time.Second {
		return fmt.Errorf("scheduler.expire_check_interval %s: must be at least 30s (each pass queries the DB and reconciles the firewall)", c.Scheduler.ExpireCheckInterval)
	}
	if c.Backup.Interval < 0 {
		return fmt.Errorf("backup.interval must not be negative")
	}
	if c.Backup.Interval != 0 && c.Backup.Interval < 10*time.Minute {
		return fmt.Errorf("backup.interval %s: must be at least 10m (each pass copies the whole DB via VACUUM INTO)", c.Backup.Interval)
	}
	if c.Backup.RetainDays < 0 {
		return fmt.Errorf("backup.retain_days must not be negative")
	}
	if c.WalledGarden.RefreshInterval < 0 {
		return fmt.Errorf("walled_garden.refresh_interval must not be negative")
	}
	if c.WalledGarden.RefreshInterval != 0 && c.WalledGarden.RefreshInterval < 30*time.Second {
		return fmt.Errorf("walled_garden.refresh_interval %s: must be at least 30s (each pass re-resolves every garden domain)", c.WalledGarden.RefreshInterval)
	}
	return nil
}

func (c *Config) validateSecurity() error {
	s := c.Security
	switch strings.ToLower(strings.TrimSpace(s.PasswordStrength)) {
	case "", "lax", "strict":
	default:
		// Anything else used to silently mean "lax" — a security downgrade
		// hidden behind a typo like "strong" or "stricter".
		return fmt.Errorf("security.password_strength %q: must be \"\", \"lax\" or \"strict\"", s.PasswordStrength)
	}
	if s.HSTSMaxAgeSeconds < 0 {
		return fmt.Errorf("security.hsts_max_age_seconds must not be negative")
	}
	if s.AdminSessionHours < 0 || s.AdminSessionHours > 168 {
		return fmt.Errorf("security.admin_session_hours %d: must be 0 (default) or 1..168", s.AdminSessionHours)
	}
	if s.UserSessionDays < 0 || s.UserSessionDays > 365 {
		return fmt.Errorf("security.user_session_days %d: must be 0 (default) or 1..365", s.UserSessionDays)
	}
	if s.AuditLogKeep != 0 && (s.AuditLogKeep < 1000 || s.AuditLogKeep > 1000000) {
		return fmt.Errorf("security.audit_log_keep %d: must be 0 (default) or 1000..1000000", s.AuditLogKeep)
	}
	if s.AutoCancelStaleOrderHours < 0 || s.AutoCancelStaleOrderHours > 720 {
		return fmt.Errorf("security.auto_cancel_stale_order_hours %d: must be 0 (disabled) or 1..720", s.AutoCancelStaleOrderHours)
	}
	return nil
}

func (c *Config) validateSMS() error {
	switch strings.ToLower(strings.TrimSpace(c.SMS.Provider)) {
	case "", "none", "off", "console":
	case "aliyun":
		a := c.SMS.Aliyun
		if a.AccessKeyID == "" || a.AccessKeySecret == "" || a.SignName == "" || a.TemplateCode == "" {
			// buildSMSSender degrades this to "disabled" with only a log
			// line — password-reset SMS would just be missing in prod.
			return fmt.Errorf("sms.provider aliyun: access_key_id, access_key_secret, sign_name and template_code are all required")
		}
	default:
		return fmt.Errorf("sms.provider %q: must be \"\", \"none\", \"off\", \"console\" or \"aliyun\"", c.SMS.Provider)
	}
	if c.SMS.ExpiryReminderDays < 0 || c.SMS.ExpiryReminderDays > 30 {
		return fmt.Errorf("sms.expiry_reminder_days %d: must be 0 (default) or 1..30", c.SMS.ExpiryReminderDays)
	}
	if c.SMS.AdminDigestHour < 0 || c.SMS.AdminDigestHour > 24 {
		return fmt.Errorf("sms.admin_digest_hour %d: must be 0 (disabled) or 1..24", c.SMS.AdminDigestHour)
	}
	// A malformed alert phone used to pass --check-config and then
	// silently disable BOTH the login-alert SMS and the entire daily
	// digest loop at boot (one stderr line each) — the operator believed
	// the 3am-login alarm was armed when it wasn't.
	if p := strings.TrimSpace(c.SMS.AdminLoginAlertPhone); p != "" && !models.ValidPhone(p) {
		return fmt.Errorf("sms.admin_login_alert_phone %q: not a valid mobile number", c.SMS.AdminLoginAlertPhone)
	}
	if c.SMS.AdminDigestHour > 0 {
		// The digest can only ever fire with a target phone and a real
		// provider; setting the hour without them silently disabled the
		// loop at boot instead of failing --check-config.
		if strings.TrimSpace(c.SMS.AdminLoginAlertPhone) == "" {
			return fmt.Errorf("sms.admin_digest_hour is set but admin_login_alert_phone is empty — the digest has nowhere to go")
		}
		switch strings.ToLower(strings.TrimSpace(c.SMS.Provider)) {
		case "", "none", "off":
			return fmt.Errorf("sms.admin_digest_hour is set but sms.provider is disabled — the digest could never send")
		}
	}
	return nil
}

func (c *Config) validateWebhook() error {
	if c.Webhook.URL == "" {
		return nil
	}
	u, err := url.Parse(c.Webhook.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("webhook.url %q: must be an absolute http(s) URL", c.Webhook.URL)
	}
	if c.Webhook.Secret == "" {
		// Unsigned webhooks can't be verified by the receiver — anyone who
		// finds the endpoint can forge payment/grant events.
		return fmt.Errorf("webhook.url is set but webhook.secret is empty; set a long random secret so receivers can verify X-Router-Billing-Signature")
	}
	return nil
}

func (c *Config) validateWalledGarden() error {
	for _, d := range c.WalledGarden.Domains {
		h := strings.TrimSpace(d)
		if h == "" {
			return fmt.Errorf("walled_garden.domains: empty entry")
		}
		if strings.Contains(h, "://") || strings.ContainsAny(h, "/ \t") {
			// A pasted URL never resolves — the resolver would retry the
			// bogus lookup forever while payments stay unreachable.
			return fmt.Errorf("walled_garden.domains %q: must be a bare domain (no scheme or path)", d)
		}
	}
	return nil
}

// PlanKeys returns plan keys in a stable order (month before year).
func (c *Config) PlanKeys() []string {
	preferred := []string{"month", "year"}
	out := []string{}
	seen := map[string]bool{}
	for _, k := range preferred {
		if _, ok := c.Plans[k]; ok {
			out = append(out, k)
			seen[k] = true
		}
	}
	for k := range c.Plans {
		if !seen[k] {
			out = append(out, k)
		}
	}
	return out
}

// PortalBase returns "http://host:port" used as portal URL base.
func (c *Config) PortalBase() string {
	host := strings.TrimSpace(c.PortalHost)
	if host == "" {
		host = "192.168.5.1"
	}
	return fmt.Sprintf("http://%s:%d", host, c.PortalPort)
}

// AdminList returns the merged list of admin users (legacy single + new list).
func (c *Config) AdminList() []Admin {
	var out []Admin
	if c.Admin.Username != "" {
		out = append(out, c.Admin)
	}
	out = append(out, c.Admins...)
	return out
}

// AuthenticateAdmin returns true if username+password match any admin.
// Walks the full list to avoid timing leaks of which admin exists.
func (c *Config) AuthenticateAdmin(username, password string) bool {
	_, ok := c.AuthenticateAdminFull(username, password)
	return ok
}

// AuthenticateAdminFull returns the matched Admin (or nil) plus an ok flag.
// Lets the caller decide whether to demand a TOTP second factor.
// Walks the full list to avoid timing leaks of which admin exists.
func (c *Config) AuthenticateAdminFull(username, password string) (*Admin, bool) {
	var match *Admin
	for i, a := range c.AdminList() {
		userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.Username)) == 1
		var passOK bool
		if a.PasswordHash != "" {
			passOK = bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(password)) == nil
		} else {
			passOK = subtle.ConstantTimeCompare([]byte(password), []byte(a.Password)) == 1
		}
		if userOK && passOK {
			// Pin to the slice element so the returned pointer survives loop exit.
			list := c.AdminList()
			match = &list[i]
		}
	}
	return match, match != nil
}

// LookupAdmin returns the admin with the given username, or nil.
// Useful for checking TOTPSecret after the password stage.
func (c *Config) LookupAdmin(username string) *Admin {
	for i, a := range c.AdminList() {
		if subtle.ConstantTimeCompare([]byte(username), []byte(a.Username)) == 1 {
			list := c.AdminList()
			return &list[i]
		}
	}
	return nil
}

// MatchAPIToken returns the label of a matching API token, or "" if no match.
// Walks the whole list to defeat timing-side-channel deduction of which
// token is configured. Kept as a thin wrapper around MatchAPITokenFull for
// callers that don't care about the readonly bit.
func (c *Config) MatchAPIToken(presented string) string {
	t := c.MatchAPITokenFull(presented)
	if t == nil {
		return ""
	}
	if t.Label == "" {
		return "unnamed-token"
	}
	return t.Label
}

// MatchAPITokenFull returns the full APIToken on success so the caller can
// also inspect ReadOnly / future scopes. Returns nil on no match.
// Still walks the whole list for constant-time comparison.
func (c *Config) MatchAPITokenFull(presented string) *APIToken {
	if presented == "" {
		return nil
	}
	var match *APIToken
	for i, t := range c.APITokens {
		if t.Token == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(t.Token)) == 1 {
			match = &c.APITokens[i]
		}
	}
	return match
}
