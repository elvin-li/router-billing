package config

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen        string          `yaml:"listen"`
	DBPath        string          `yaml:"db_path"`
	WebRoot       string          `yaml:"web_root"`
	PaidIface     string          `yaml:"paid_iface"`
	PortalHost    string          `yaml:"portal_host"`
	PortalPort    int             `yaml:"portal_port"`
	Admin         Admin           `yaml:"admin"`                // legacy single-admin
	Admins        []Admin         `yaml:"admins"`               // multi-admin list
	MetricsToken  string          `yaml:"metrics_token"`        // optional bearer for /metrics
	SSIDs         SSIDInfo        `yaml:"ssids"`                // displayed on /admin/ssid-cards
	Plans         map[string]Plan `yaml:"plans"`
	Pay           Pay             `yaml:"pay"`
	Firewall      Firewall        `yaml:"firewall"`
	Scheduler     Scheduler       `yaml:"scheduler"`
	Backup        Backup          `yaml:"backup"`
	Webhook       Webhook         `yaml:"webhook"`
	WalledGarden  WalledGarden    `yaml:"walled_garden"`
}

// Admin is either {username,password} or {username,password_hash}.
// password_hash is a bcrypt hash (`htpasswd -nB` or our --gen-password-hash CLI).
type Admin struct {
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	PasswordHash string `yaml:"password_hash"`
}

// SSIDInfo holds the names + secure-SSID password so admins can render printable
// join-WiFi QR cards. Optional — purely informational.
type SSIDInfo struct {
	Free       string `yaml:"free"`
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
	if len(c.AdminList()) == 0 {
		return fmt.Errorf("at least one admin is required (set admin.* or admins[])")
	}
	for _, a := range c.AdminList() {
		if a.Username == "" {
			return fmt.Errorf("admin entry missing username")
		}
		if a.Password == "" && a.PasswordHash == "" {
			return fmt.Errorf("admin %q has no password or password_hash", a.Username)
		}
	}
	for k, p := range c.Plans {
		if p.Days <= 0 || p.PriceCents <= 0 {
			return fmt.Errorf("plan %q: days and price_cents must be positive", k)
		}
	}
	if c.Pay.WeChat.Enabled {
		if c.Pay.WeChat.MchID == "" || c.Pay.WeChat.AppID == "" ||
			c.Pay.WeChat.APIv3Key == "" || c.Pay.WeChat.SerialNo == "" ||
			c.Pay.WeChat.PrivateKeyPath == "" || c.Pay.WeChat.NotifyURL == "" {
			return fmt.Errorf("pay.wechat enabled but credentials incomplete")
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
	matched := false
	for _, a := range c.AdminList() {
		userOK := subtle.ConstantTimeCompare([]byte(username), []byte(a.Username)) == 1
		var passOK bool
		if a.PasswordHash != "" {
			passOK = bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(password)) == nil
		} else {
			passOK = subtle.ConstantTimeCompare([]byte(password), []byte(a.Password)) == 1
		}
		if userOK && passOK {
			matched = true
		}
	}
	return matched
}
