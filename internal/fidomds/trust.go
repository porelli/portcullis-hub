// Package fidomds derives the passkey trust list the Keycloak extension
// classifies new passkeys against (plan D15, contract §8.1 "FIDO
// metadata"): AAGUID → kind, status and attestation roots.
package fidomds

import (
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/google/uuid"
)

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

// revokedStatuses are the MDS statuses that publish an entry as revoked
// (contract §8.1): anywhere in its status reports.
var revokedStatuses = map[metadata.AuthenticatorStatus]bool{
	metadata.Revoked:                   true,
	metadata.UserVerificationBypass:    true,
	metadata.AttestationKeyCompromise:  true,
	metadata.UserKeyRemoteCompromise:   true,
	metadata.UserKeyPhysicalCompromise: true,
}

// Trust is the authenticator trust list of BLOB m at now (D15, contract
// §8.1): AAGUID (lowercase, hyphenated) → kind, status, roots.
//   - kind security_key: attachmentHint has external and keyProtection
//     secure_element; passkey_device: attachmentHint has internal and
//     keyProtection hardware, tee or secure_element; anything else is left
//     out (it registers as synced);
//   - status revoked: any status report REVOKED, USER_VERIFICATION_BYPASS,
//     ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE or
//     USER_KEY_PHYSICAL_COMPROMISE (kind and roots still listed);
//     certified: else, the latest report (by effective date, then order)
//     is FIDO_CERTIFIED*; anything else is left out;
//   - entries without an AAGUID or without attestation roots are left out.
//
// A nil m, or one more than StaleAfter past its nextUpdate (stale true),
// is an empty list: never a stale or missing list's entries.
func Trust(m *metadata.Metadata, now time.Time) (trust map[string]AuthenticatorTrust, stale bool) {
	trust = map[string]AuthenticatorTrust{}
	if m == nil {
		return trust, false
	}
	if IsStale(m.Parsed.NextUpdate, now) {
		return trust, true
	}
	for _, e := range m.Parsed.Entries {
		if e.AaGUID == uuid.Nil {
			continue
		}
		kind := kindOf(e.MetadataStatement)
		status := statusOf(e.StatusReports)
		if kind == "" || status == "" || len(e.MetadataStatement.AttestationRootCertificates) == 0 {
			continue
		}
		roots := make([][]byte, 0, len(e.MetadataStatement.AttestationRootCertificates))
		for _, c := range e.MetadataStatement.AttestationRootCertificates {
			roots = append(roots, slices.Clone(c.Raw))
		}
		trust[e.AaGUID.String()] = AuthenticatorTrust{Kind: kind, Status: status, Roots: roots}
	}
	return trust, false
}

func kindOf(s metadata.Statement) string {
	switch {
	case slices.Contains(s.AttachmentHint, "external") && slices.Contains(s.KeyProtection, "secure_element"):
		return KindSecurityKey
	case slices.Contains(s.AttachmentHint, "internal") && slices.ContainsFunc(s.KeyProtection, func(p string) bool {
		return p == "hardware" || p == "tee" || p == "secure_element"
	}):
		return KindPasskeyDevice
	}
	return ""
}

func statusOf(reports []metadata.StatusReport) string {
	var latest *metadata.StatusReport
	var latestAt time.Time
	for i := range reports {
		r := &reports[i]
		if revokedStatuses[r.Status] {
			return StatusRevoked
		}
		var at time.Time
		if r.EffectiveDate != nil {
			at = *r.EffectiveDate
		}
		if latest == nil || !at.Before(latestAt) {
			latest, latestAt = r, at
		}
	}
	if latest != nil && (latest.Status == metadata.FidoCertified || strings.HasPrefix(string(latest.Status), "FIDO_CERTIFIED_")) {
		return StatusCertified
	}
	return ""
}
