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
	"unicode/utf8"

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
// The password is the 29-character dashed form. No string copy of the
// password is made, and the UTF-16 and little-endian buffers are zeroed
// once hashed (invalid UTF-8 reads as U+FFFD, as a string conversion
// would).
func NTHash(password []byte) string {
	u16 := make([]uint16, 0, len(password))
	for i := 0; i < len(password); {
		r, n := utf8.DecodeRune(password[i:])
		u16 = utf16.AppendRune(u16, r)
		i += n
	}
	le := make([]byte, 2*len(u16))
	for i, u := range u16 {
		le[2*i], le[2*i+1] = byte(u), byte(u>>8)
	}
	h := md4.New()
	h.Write(le)
	sum := h.Sum(nil)
	for i := range u16 {
		u16[i] = 0
	}
	Zero(le)
	return strings.ToUpper(hex.EncodeToString(sum))
}

// Zero overwrites b with zeros.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// hardRefusedRe: the file server script's own refusals (templates
// portcullis-sync), whatever a template's pattern admits: "..", a
// leading "." or "-", "/", and the per-folder group names pfg<digits>.
var hardRefusedRe = regexp.MustCompile(`\.\.|^[.-]|/|^pfg[0-9]+$`)

// hardRefusedReason is the reason of a hard refusal without a rule.
const hardRefusedReason = "isn't a name file sharing can use"

// CheckUsername validates user against the rule (a person_secret
// option's username rule) and the hard rules every file-sharing
// username follows (B-M2: the script refuses them, so the Hub does too:
// the card says unavailable). It returns ok=true when the username
// passes, or ok=false with the rule's reason.
func CheckUsername(r *templates.UsernameRule, user string) (ok bool, reason string) {
	if hardRefusedRe.MatchString(user) {
		if r != nil && r.Reason != "" {
			return false, r.Reason
		}
		return false, hardRefusedReason
	}
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
