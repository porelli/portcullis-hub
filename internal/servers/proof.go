package servers

import (
	"crypto/hmac"
	"crypto/sha256"
)

// NonceLen is the agent's enrolment nonce length (bytes). Fixed, so the
// proof's concatenated input is unambiguous.
const NonceLen = 32

// SecretLen is the join code secret's length (256 bits).
const SecretLen = 32

// proofLabel starts every enrolment proof's input (contract §17).
const proofLabel = "portcullis-enrol-v1"

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Proof is the enrolment proof, bound to the TLS channel:
// HMAC-SHA256(secret, "portcullis-enrol-v1" || nonce || server_id ||
// sha256(agentSPKI)), agentSPKI the DER SubjectPublicKeyInfo of the
// agent's enrolling certificate.
func Proof(secret []byte, nonce []byte, serverID string, agentSPKI []byte) []byte {
	h := sha256.Sum256(agentSPKI)
	msg := make([]byte, 0, len(proofLabel)+len(nonce)+len(serverID)+len(h))
	msg = append(msg, proofLabel...)
	msg = append(msg, nonce...)
	msg = append(msg, serverID...)
	msg = append(msg, h[:]...)
	return hmacSHA256(secret, msg)
}

// VerifyProof checks got in constant time (hmac.Equal). A secret of
// another length than SecretLen, a nonce of another length than NonceLen
// or an invalid server id never verify.
func VerifyProof(secret, nonce []byte, serverID string, agentSPKI, got []byte) bool {
	if len(secret) != SecretLen || len(nonce) != NonceLen || ValidID(serverID) != nil {
		return false
	}
	return hmac.Equal(Proof(secret, nonce, serverID, agentSPKI), got)
}
