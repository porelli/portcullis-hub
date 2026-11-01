package lldap

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

// LLDAP lowercases user ids and accepts almost anything; the Hub is
// stricter because a username ends up in LDAP DNs (uid=<u>,ou=people,…),
// URLs, Keycloak and app accounts: lowercase letters, digits, '.', '_',
// '-', starting with a letter or digit, at most 64 characters.
var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// groupRe matches the Hub's template group names (templates.groupRe).
var groupRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidUsername reports whether u is an acceptable username.
func ValidUsername(u string) bool { return usernameRe.MatchString(u) }

// ValidGroupName reports whether g is an acceptable group name.
func ValidGroupName(g string) bool { return groupRe.MatchString(g) }

// ValidEmail accepts a single bare address (no display name), ≤ 254 chars.
func ValidEmail(e string) bool {
	if e == "" || len(e) > 254 || strings.ContainsAny(e, " <>\"") {
		return false
	}
	a, err := mail.ParseAddress(e)
	return err == nil && a.Address == e && strings.Contains(e[strings.LastIndex(e, "@")+1:], ".")
}

// ValidDisplayName: ≤ 128 printable characters (may be empty).
func ValidDisplayName(d string) bool {
	if len(d) > 128 {
		return false
	}
	for _, r := range d {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Password bounds for admin-provided passwords.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// ValidPassword: MinPasswordLen..MaxPasswordLen bytes, no control characters.
func ValidPassword(p string) bool {
	if len(p) < MinPasswordLen || len(p) > MaxPasswordLen {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
