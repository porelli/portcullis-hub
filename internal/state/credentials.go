package state

import "time"

// Credential is the metadata of one per-person credential (contract
// §13.16): a person_secret option's password for one person on one
// instance. Never the password or its hash: those live only on the
// Hub's secrets volume (HUB_SECRETS_DIR), never in state.yaml.
type Credential struct {
	// ID is new on every create and regenerate; Version is 1 on create
	// and +1 on every regenerate.
	ID      string `json:"id" yaml:"id"`
	Version int    `json:"version" yaml:"version"`
	// UUID is the person's LLDAP user uuid at creation.
	UUID      string    `json:"uuid" yaml:"uuid"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	CreatedBy string    `json:"created_by" yaml:"created_by"`
	// RevokedAt is set once the credential is no longer active (nil =
	// active); Reason says why (CredentialReason*).
	RevokedAt *time.Time `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty" yaml:"revoked_by,omitempty"`
	Reason    string     `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// Active reports whether the credential is in use (not revoked or
// voided).
func (c Credential) Active() bool { return c.RevokedAt == nil }

// Revocation reasons (Credential.Reason, contract §13.16).
const (
	CredentialReasonSelf    = "self"
	CredentialReasonAdmin   = "admin"
	CredentialReasonLeave   = "leave"
	CredentialReasonDeleted = "deleted"
	CredentialReasonRestore = "restore"
)
