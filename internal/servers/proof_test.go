package servers

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestProofBindsSPKI(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	nonce := []byte(strings.Repeat("n", NonceLen))
	spki, other := []byte("spki-of-the-agent"), []byte("spki-of-another")
	p := Proof(secret, nonce, "nas", spki)
	if len(p) != sha256.Size {
		t.Fatalf("len %d", len(p))
	}
	if !VerifyProof(secret, nonce, "nas", spki, p) {
		t.Fatal("own proof refused")
	}
	if VerifyProof(secret, nonce, "nas", other, p) {
		t.Error("another SPKI accepted")
	}
	if VerifyProof(secret, nonce, "nas2", spki, p) {
		t.Error("another server id accepted")
	}
	if VerifyProof([]byte(strings.Repeat("t", 32)), nonce, "nas", spki, p) {
		t.Error("another secret accepted")
	}
	n2 := []byte(strings.Repeat("m", NonceLen))
	if VerifyProof(secret, n2, "nas", spki, p) {
		t.Error("another nonce accepted")
	}
	if VerifyProof(secret, nonce[:NonceLen-1], "nas", spki, Proof(secret, nonce[:NonceLen-1], "nas", spki)) {
		t.Error("a short nonce accepted")
	}
	if VerifyProof(secret, nonce, "nas", spki, p[:31]) || VerifyProof(secret, nonce, "nas", spki, nil) {
		t.Error("a truncated proof accepted")
	}
	if VerifyProof(nil, nonce, "nas", spki, Proof(nil, nonce, "nas", spki)) {
		t.Error("an empty secret accepted")
	}
	// The input is the contract's: "portcullis-enrol-v1" || nonce || id || sha256(spki).
	h := sha256.Sum256(spki)
	want := hmacSHA256(secret, append(append(append([]byte("portcullis-enrol-v1"), nonce...), "nas"...), h[:]...))
	if string(want) != string(p) {
		t.Error("proof input differs from the contract")
	}
}
