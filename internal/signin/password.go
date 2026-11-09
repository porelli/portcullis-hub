package signin

import (
	_ "embed"
	"errors"
	"strings"
	"unicode/utf8"
)

// commonPasswords is SecLists' Passwords/Common-Credentials/Pwdb_top-10000.txt
// (github.com/danielmiessler/SecLists at a1a06ab, byte for byte),
// Copyright (c) 2018 Daniel Miessler, under the MIT License whose full text
// is in common-passwords.LICENSE next to it.
//
//go:embed common-passwords.txt
var commonPasswords string

// Password length limits, in characters (D13).
const (
	MinPasswordLen = 12
	MaxPasswordLen = 128
)

// isCommon scans the list (passwords are set rarely; no cache, no state).
func isCommon(pw string) bool {
	for line := range strings.Lines(commonPasswords) {
		if p := strings.TrimRight(line, "\r\n"); p != "" && strings.EqualFold(p, pw) {
			return true
		}
	}
	return false
}

// CheckPassword applies the Hub's rules for a password it sets (D13): 12–128
// characters, not the username, not in the common-password list (both
// compared case-insensitively). The error never quotes the password.
func CheckPassword(user, pw string) error {
	if !utf8.ValidString(pw) {
		return errors.New("the password isn't valid text")
	}
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLen {
		return errors.New("the password needs at least 12 characters")
	}
	if n > MaxPasswordLen {
		return errors.New("the password can have at most 128 characters")
	}
	if user != "" && strings.EqualFold(pw, user) {
		return errors.New("the password can't be the username")
	}
	if isCommon(pw) {
		return errors.New("the password is one of the most common passwords")
	}
	return nil
}
