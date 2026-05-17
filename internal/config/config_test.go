package config

import (
	"testing"

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
