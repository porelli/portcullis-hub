package servers

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// NewWGKeyPair is a fresh WireGuard key pair (standard base64): the
// bootstrap key of a join code. The private key goes into the code only.
func NewWGKeyPair() (priv, pub string, err error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

// ValidWGKey: s is a WireGuard key (standard base64 of 32 bytes, never
// all zeros).
func ValidWGKey(s string) error {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return errors.New("not a WireGuard key")
	}
	for _, c := range b {
		if c != 0 {
			return nil
		}
	}
	return errors.New("the all-zero WireGuard key")
}
