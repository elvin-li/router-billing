package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeCfg(t *testing.T, yaml string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMinimalDefaultsExhaustive(t *testing.T) {
	p := writeCfg(t, `
admin:
  username: root
  password: secret
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" {
		t.Errorf("Listen default: %q", c.Listen)
	}
	if c.DBPath != "/var/lib/router-billing/billing.db" {
		t.Errorf("DBPath default: %q", c.DBPath)
	}
	if c.PaidIface != "br-paid" {
		t.Errorf("PaidIface default: %q", c.PaidIface)
	}
	if c.Firewall.Backend != "nftables" || c.Firewall.Table != "inet" ||
		c.Firewall.TableName != "billing" || c.Firewall.SetName != "mac_paid" {
		t.Errorf("firewall defaults: %+v", c.Firewall)
	}
	if c.Scheduler.ExpireCheckInterval != time.Hour {
		t.Errorf("scheduler default: %s", c.Scheduler.ExpireCheckInterval)
	}
	if c.Backup.Interval != 24*time.Hour || c.Backup.RetainDays != 7 {
		t.Errorf("backup defaults: %+v", c.Backup)
	}
	if len(c.Plans) == 0 {
		t.Error("default plans missing")
	}
	if len(c.WalledGarden.Domains) == 0 || c.WalledGarden.RefreshInterval != 5*time.Minute {
		t.Errorf("walled garden defaults: %+v", c.WalledGarden)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("missing file should error")
	}
}

func TestLoadRejectsBadYAML(t *testing.T) {
	p := writeCfg(t, "admin: [not: valid\n")
	if _, err := Load(p); err == nil {
		t.Error("malformed yaml should error")
	}
}

func TestLoadRejectsNoAdmin(t *testing.T) {
	p := writeCfg(t, "listen: ':9090'\n")
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "admin") {
		t.Errorf("no-admin config must be rejected; got %v", err)
	}
}

func TestLoadRejectsAdminWithoutPassword(t *testing.T) {
	p := writeCfg(t, `
admins:
  - username: alice
`)
	if _, err := Load(p); err == nil {
		t.Error("admin without password/password_hash must be rejected")
	}
}

func TestLoadRejectsAdminWithoutUsername(t *testing.T) {
	p := writeCfg(t, `
admins:
  - password: pw
`)
	if _, err := Load(p); err == nil {
		t.Error("admin without username must be rejected")
	}
}

func TestLoadRejectsNonPositivePlan(t *testing.T) {
	p := writeCfg(t, `
admin: {username: root, password: pw}
plans:
  freebie: {label: free, days: 0, price_cents: 100}
`)
	if _, err := Load(p); err == nil {
		t.Error("plan with days=0 must be rejected")
	}
	p = writeCfg(t, `
admin: {username: root, password: pw}
plans:
  negative: {label: neg, days: 30, price_cents: -1}
`)
	if _, err := Load(p); err == nil {
		t.Error("plan with negative price must be rejected")
	}
}

func TestLoadRejectsIncompleteWeChat(t *testing.T) {
	p := writeCfg(t, `
admin: {username: root, password: pw}
pay:
  wechat:
    enabled: true
    mch_id: "123"
`)
	if _, err := Load(p); err == nil {
		t.Error("enabled wechat with missing credentials must be rejected")
	}
}

func TestLoadAlipayGatewayDefault(t *testing.T) {
	p := writeCfg(t, `
admin: {username: root, password: pw}
pay:
  alipay:
    enabled: true
    app_id: "2021"
    private_key_path: /k.pem
    alipay_public_key_path: /pub.pem
    notify_url: https://x/notify
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Pay.Alipay.Gateway != "https://openapi.alipay.com/gateway.do" {
		t.Errorf("gateway default: %q", c.Pay.Alipay.Gateway)
	}
}

func TestLoadRejectsIncompleteAlipay(t *testing.T) {
	p := writeCfg(t, `
admin: {username: root, password: pw}
pay:
  alipay:
    enabled: true
    app_id: "2021"
`)
	if _, err := Load(p); err == nil {
		t.Error("enabled alipay with missing credentials must be rejected")
	}
}

func TestLoadExampleConfigInRepo(t *testing.T) {
	// The shipped example must always pass -check-config.
	if _, err := Load("../../config.example.yaml"); err != nil {
		t.Errorf("config.example.yaml no longer loads: %v", err)
	}
}

func TestPlanKeysStableOrder(t *testing.T) {
	c := &Config{Plans: map[string]Plan{
		"week":  {Days: 7, PriceCents: 50},
		"year":  {Days: 365, PriceCents: 1000},
		"month": {Days: 30, PriceCents: 100},
	}}
	got := c.PlanKeys()
	if got[0] != "month" || got[1] != "year" {
		t.Errorf("month/year must lead: %+v", got)
	}
	if len(got) != 3 || got[2] != "week" {
		t.Errorf("custom plans must follow: %+v", got)
	}
}

func TestPortalBase(t *testing.T) {
	c := &Config{PortalPort: 8080}
	if got := c.PortalBase(); got != "http://192.168.5.1:8080" {
		t.Errorf("default host: %q", got)
	}
	c = &Config{PortalHost: " 10.0.0.1 ", PortalPort: 9000}
	if got := c.PortalBase(); got != "http://10.0.0.1:9000" {
		t.Errorf("custom host should be trimmed: %q", got)
	}
}

func TestLookupAdmin(t *testing.T) {
	c := &Config{Admins: []Admin{
		{Username: "alice", Password: "a", TOTPSecret: "SECRET"},
		{Username: "bob", Password: "b"},
	}}
	if a := c.LookupAdmin("alice"); a == nil || a.TOTPSecret != "SECRET" {
		t.Errorf("LookupAdmin(alice) = %+v", a)
	}
	if a := c.LookupAdmin("mallory"); a != nil {
		t.Errorf("unknown admin should be nil, got %+v", a)
	}
}

func TestMatchAPIToken(t *testing.T) {
	c := &Config{APITokens: []APIToken{
		{Token: "tok-full", Label: "ci"},
		{Token: "tok-ro", ReadOnly: true},
		{Token: ""}, // must never match anything
	}}
	if got := c.MatchAPIToken("tok-full"); got != "ci" {
		t.Errorf("label: %q", got)
	}
	if got := c.MatchAPIToken("tok-ro"); got != "unnamed-token" {
		t.Errorf("unnamed label: %q", got)
	}
	if got := c.MatchAPIToken("wrong"); got != "" {
		t.Errorf("bad token matched: %q", got)
	}
	if got := c.MatchAPIToken(""); got != "" {
		t.Errorf("empty presented token must never match (even the empty configured one): %q", got)
	}
	full := c.MatchAPITokenFull("tok-ro")
	if full == nil || !full.ReadOnly {
		t.Errorf("readonly bit lost: %+v", full)
	}
	if c.MatchAPITokenFull("tok-full").ReadOnly {
		t.Error("full token misreported as readonly")
	}
}

func TestSecurityClampHelpers(t *testing.T) {
	if got := (Security{}).AutoCancelStaleOrders(); got != 0 {
		t.Errorf("disabled by default: %d", got)
	}
	if got := (Security{AutoCancelStaleOrderHours: 48}).AutoCancelStaleOrders(); got != 48 {
		t.Errorf("in-range passthrough: %d", got)
	}
	if got := (Security{AutoCancelStaleOrderHours: 9999}).AutoCancelStaleOrders(); got != 720 {
		t.Errorf("clamp to 720: %d", got)
	}

	if (Security{}).PasswordStrengthStrict() {
		t.Error("default must be lax")
	}
	if !(Security{PasswordStrength: " STRICT "}).PasswordStrengthStrict() {
		t.Error("strict should match case/space-insensitively")
	}
	if (Security{PasswordStrength: "lax"}).PasswordStrengthStrict() {
		t.Error("lax is not strict")
	}
}

func TestExpiryReminderWindowDays(t *testing.T) {
	for in, want := range map[int]int{0: 3, -1: 3, 31: 3, 1: 1, 30: 30, 7: 7} {
		if got := (SMSConfig{ExpiryReminderDays: in}).ExpiryReminderWindowDays(); got != want {
			t.Errorf("days=%d: got %d want %d", in, got, want)
		}
	}
}

func TestLoadRoundTripsPlans(t *testing.T) {
	p := writeCfg(t, `
admin: {username: root, password: pw}
plans:
  day: {label: 1 天, days: 1, price_cents: 10}
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Plan{"day": {Label: "1 天", Days: 1, PriceCents: 10}}
	if !reflect.DeepEqual(c.Plans, want) {
		t.Errorf("plans: %+v", c.Plans)
	}
}
