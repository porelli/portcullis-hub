// Package credentials provides password generation, NT hash computation,
// and username validation for file-sharing credentials (§13.16).
package credentials

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"

	"github.com/portcullis/hub/internal/templates"
)

// Alphabet is the 54-character alphabet for generated passwords (global
// constraints; spec call 2): digits minus 0 and 1, upper case minus I, O
// and Z, lower case minus i, l and o.
const Alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYabcdefghjkmnpqrstuvwxyz"

// Generate produces length random characters from Alphabet, grouped by 4
// with '-' (29 characters for length 24). Length must be a multiple of 4
// and at least 24 (global constraints).
func Generate(length int) ([]byte, error) {
	if length < 24 || length%4 != 0 {
		return nil, fmt.Errorf("length %d: must be at least 24 and a multiple of 4", length)
	}

	// Use crypto/rand.Int to avoid modulo bias
	max := big.NewInt(int64(len(Alphabet)))
	chars := make([]byte, length)
	for i := range chars {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("random generation: %w", err)
		}
		chars[i] = Alphabet[n.Int64()]
	}

	// Group by 4 with dashes
	groups := length / 4
	result := make([]byte, length+groups-1)
	outIdx := 0
	for i := 0; i < length; i++ {
		if i > 0 && i%4 == 0 {
			result[outIdx] = '-'
			outIdx++
		}
		result[outIdx] = chars[i]
		outIdx++
	}

	return result, nil
}

// NTHash computes the NT hash (uppercase hex of MD4(UTF-16LE(password))).
// The password is the 29-character dashed form.
func NTHash(password []byte) string {
	// Convert to UTF-16LE
	runes := []rune(string(password))
	utf16Bytes := utf16.Encode(runes)
	le := make([]byte, 0, len(utf16Bytes)*2)
	for _, u := range utf16Bytes {
		le = append(le, byte(u), byte(u>>8))
	}

	// MD4 hash
	h := md4.New()
	h.Write(le)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// Zero overwrites b with zeros.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// CheckUsername validates user against the rule. It returns ok=true when
// the username passes, or ok=false with the rule's reason.
func CheckUsername(r *templates.UsernameRule, user string) (ok bool, reason string) {
	if r == nil {
		return true, ""
	}

	// Check pattern
	if r.Pattern != "" {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			// This should never happen since patterns are validated at manifest time
			return false, r.Reason
		}
		if !re.MatchString(user) {
			return false, r.Reason
		}
	}

	// Check reserved names (case-insensitive)
	lower := strings.ToLower(user)
	for _, reserved := range r.Reserved {
		if lower == strings.ToLower(reserved) {
			return false, r.Reason
		}
	}

	return true, ""
}

// patternRE matches the 29-character dashed password shape.
var patternRE = regexp.MustCompile(`^([A-Za-z2-9]{4}-){5}[A-Za-z2-9]{4}$`)
