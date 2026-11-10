// Package fidomds derives the passkey trust list the Keycloak extension
// classifies new passkeys against (plan D15, contract §8.1 "FIDO
// metadata"): AAGUID → kind, status and attestation roots.
package fidomds

// Authenticator kinds and statuses (contract §8.1 signin-keycloak.json
// authenticators).
const (
	KindSecurityKey   = "security_key"
	KindPasskeyDevice = "passkey_device"
	StatusCertified   = "certified"
	StatusRevoked     = "revoked"
)

// AuthenticatorTrust is one AAGUID's entry: Kind security_key or
// passkey_device, Status certified or revoked, Roots the attestation root
// certificates (DER; standard base64 in JSON).
type AuthenticatorTrust struct {
	Kind   string   `json:"kind"`
	Status string   `json:"status"`
	Roots  [][]byte `json:"roots"`
}
