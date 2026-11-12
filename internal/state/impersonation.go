package state

import (
	"slices"
	"time"
)

// Impersonation is one administrator's impersonation of a person
// (contract §8.1 "Impersonation", D36–D38, D41, D44). Times are UTC.
type Impersonation struct {
	// ID: 32 lowercase hex characters (16 bytes from crypto/rand).
	ID string `json:"id" yaml:"id"`
	// Admin and Target are LLDAP usernames (lowercase).
	Admin  string `json:"admin" yaml:"admin"`
	Target string `json:"target" yaml:"target"`
	// AdminSID is the administrator's Keycloak session id at the start
	// (the resource binds the start to that browser, D38).
	AdminSID string `json:"admin_sid" yaml:"admin_sid"`
	// Reason is the administrator's typed reason (never a secret, never
	// in a token, a URL or a log line).
	Reason string `json:"reason" yaml:"reason"`
	// Fresh is the fresh touch's method (security_key or yubikey_cert),
	// FreshAt its auth_time.
	Fresh   string    `json:"fresh" yaml:"fresh"`
	FreshAt time.Time `json:"fresh_at" yaml:"fresh_at"`
	// Started is the start (= the pending record's created); Until the
	// end at the latest.
	Started time.Time `json:"started" yaml:"started"`
	Until   time.Time `json:"until" yaml:"until"`
	// Ended is zero while running.
	Ended time.Time `json:"ended,omitempty" yaml:"ended,omitempty"`
	// How it ended: stopped | expired | switched_off | not_used.
	How string `json:"how,omitempty" yaml:"how,omitempty"`
	// EndedBy is who stopped it (the audit actor; "portcullis" for
	// expiry and the switch).
	EndedBy string `json:"ended_by,omitempty" yaml:"ended_by,omitempty"`
	// Used: an IMPERSONATE event with its id exists (D44), set at the end.
	Used bool `json:"used,omitempty" yaml:"used,omitempty"`
	// Apps are the apps opened, filled at the end (F1).
	Apps []ImpersonationApp `json:"apps,omitempty" yaml:"apps,omitempty"`
	// Finished: the end's second half is done (apps and used stored,
	// impersonation.end audited); NoticeOwed: a used end whose notice
	// action Keycloak hasn't accepted yet. The Hub's loop retries both.
	Finished   bool `json:"finished,omitempty" yaml:"finished,omitempty"`
	NoticeOwed bool `json:"notice_owed,omitempty" yaml:"notice_owed,omitempty"`
}

// ImpersonationApp is an app opened during an impersonation: its name
// and whether it keeps its own session (a native-OIDC app).
type ImpersonationApp struct {
	Name       string `yaml:"name" json:"name"`
	OwnSession bool   `yaml:"own_session" json:"own_session"`
}

// Running reports whether the record hasn't ended.
func (r Impersonation) Running() bool { return r.Ended.IsZero() }

// Clone is a deep copy.
func (r Impersonation) Clone() Impersonation {
	r.Apps = slices.Clone(r.Apps)
	return r
}
