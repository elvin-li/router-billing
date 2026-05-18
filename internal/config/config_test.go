package config

import (
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
