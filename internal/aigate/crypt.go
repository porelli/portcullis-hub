package aigate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// The Hub encrypts to the gate's recipient and holds no identity
// (contract §15): it can replace or drop a credential entry, never read
// one back. There is deliberately no decryption code in the Hub (a test
// greps for it).

// maxRecipientFile bounds what ParseRecipientFile reads.
const maxRecipientFile = 4096

// ParseRecipientFile reads core's secrets/mcp-gate/age.pub: exactly one
// X25519 recipient (one line, surrounding whitespace ignored). Anything
// else is an error: no gate (the Hub then writes enabled: false).
func ParseRecipientFile(path string) (*age.X25519Recipient, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > maxRecipientFile {
		return nil, fmt.Errorf("%s: not a recipient file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("%s: want exactly one age recipient", path)
	}
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("%s: not an age X25519 recipient", path)
	}
	return r, nil
}

// Encrypt returns plaintext as ASCII-armored age ciphertext to r. The
// caller zeroes plaintext afterwards; the plaintext never appears in an
// error.
func Encrypt(r age.Recipient, plaintext []byte) (string, error) {
	if r == nil {
		return "", errors.New("no recipient")
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		return "", fmt.Errorf("age: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", errors.New("age: encrypt failed")
	}
	if err := w.Close(); err != nil {
		return "", errors.New("age: encrypt failed")
	}
	if err := aw.Close(); err != nil {
		return "", errors.New("age: armor failed")
	}
	return buf.String(), nil
}
