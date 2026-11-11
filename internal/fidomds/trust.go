// Package fidomds derives the passkey trust list the Keycloak extension
// classifies new passkeys against (plan D15, contract §8.1 "FIDO
// metadata"): AAGUID → kind, status and attestation roots, from the FIDO
// MDS BLOB (fidomds.go: fetched, verified and cached). The BLOB's chain
// revocation is checked by go-webauthn; a CRL or OCSP responder that
// can't be reached counts as not revoked (accepted, contract §8.1).
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
// (contract §8.1): any in-effect status report.
var revokedStatuses = map[metadata.AuthenticatorStatus]bool{
	metadata.Revoked:                   true,
	metadata.UserVerificationBypass:    true,
	metadata.AttestationKeyCompromise:  true,
	metadata.UserKeyRemoteCompromise:   true,
	metadata.UserKeyPhysicalCompromise: true,
}

// isCertified: FIDO_CERTIFIED or FIDO_CERTIFIED_L*.
func isCertified(s metadata.AuthenticatorStatus) bool {
	return s == metadata.FidoCertified || strings.HasPrefix(string(s), "FIDO_CERTIFIED_L")
}

// isCertification: the statuses that say whether the model is FIDO
// certified (ruling R1); UPDATE_AVAILABLE, FIPS140_CERTIFIED_*, RETIRED
// (sticky: statusOf) and the revocation statuses aren't.
func isCertification(s metadata.AuthenticatorStatus) bool {
	return isCertified(s) || s == metadata.NotFidoCertified || s == metadata.SelfAssertionSubmitted
}

// Trust is the authenticator trust list of BLOB m at now (D15, contract
// §8.1): AAGUID (lowercase, hyphenated) → kind, status, roots. Only the
// status reports in effect at now count (metadata.EffectiveStatusReports).
//   - kind security_key: attachmentHint has external and not internal,
//     keyProtection secure_element and not software; passkey_device:
//     attachmentHint has internal, keyProtection hardware, tee or
//     secure_element and not software; anything else is left out (it
//     registers as synced);
//   - status revoked: any report REVOKED, USER_VERIFICATION_BYPASS,
//     ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE or
//     USER_KEY_PHYSICAL_COMPROMISE (kind and roots still listed);
//     left out: else, any report RETIRED (sticky, whatever comes after);
//     certified: else, the latest certification status (isCertification;
//     dates when both reports have one, else document order, ties to the
//     later — the library's current-report rule) is FIDO_CERTIFIED*;
//     anything else is left out;
//   - entries without an AAGUID are left out, and so are certified ones
//     without attestation roots; a revoked entry is kept without them
//     (Roots empty, never nil: a revocation needs no roots, and it still
//     downgrades that model's passkeys).
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
		status := statusOf(metadata.EffectiveStatusReports(e.StatusReports, now))
		if kind == "" || status == "" || (status != StatusRevoked && len(e.MetadataStatement.AttestationRootCertificates) == 0) {
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
	has := func(l []string, v string) bool { return slices.Contains(l, v) }
	if has(s.KeyProtection, "software") {
		return ""
	}
	switch {
	case has(s.AttachmentHint, "external") && !has(s.AttachmentHint, "internal") && has(s.KeyProtection, "secure_element"):
		return KindSecurityKey
	case has(s.AttachmentHint, "internal") && (has(s.KeyProtection, "hardware") || has(s.KeyProtection, "tee") || has(s.KeyProtection, "secure_element")):
		return KindPasskeyDevice
	}
	return ""
}

// statusOf judges the reports in effect: revoked, certified or "".
func statusOf(effective []metadata.StatusReport) string {
	var current *metadata.StatusReport
	retired := false
	for i := range effective {
		r := &effective[i]
		if revokedStatuses[r.Status] {
			return StatusRevoked
		}
		if r.Status == metadata.Retired {
			retired = true
			continue
		}
		if !isCertification(r.Status) {
			continue
		}
		// metadata's currentStatusReport rule, over certification reports.
		if current == nil || current.EffectiveDate == nil || r.EffectiveDate == nil || !r.EffectiveDate.Before(*current.EffectiveDate) {
			current = r
		}
	}
	if !retired && current != nil && isCertified(current.Status) {
		return StatusCertified
	}
	return ""
}
