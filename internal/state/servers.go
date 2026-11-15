package state

import "time"

// Server is one worker server (contract §17.3). The primary is never
// listed here (it is the local engine).
type Server struct {
	Name     string `json:"name" yaml:"name"`
	TunnelIP string `json:"tunnel_ip" yaml:"tunnel_ip"`
	// WGPublicKey is the peer key link.json carries: the bootstrap key's
	// while enrolling, the agent's own once enrolled.
	WGPublicKey string `json:"wg_public_key" yaml:"wg_public_key"`
	// CertSerial / SPKI pin the worker's node certificate (serial as
	// Vault writes it; SPKI the sha256 hex of its SubjectPublicKeyInfo).
	CertSerial string `json:"cert_serial,omitempty" yaml:"cert_serial,omitempty"`
	SPKI       string `json:"spki,omitempty" yaml:"spki,omitempty"`
	// State is enrolling, ready, offline or revoked.
	State          string         `json:"state" yaml:"state"`
	LocalNetworks  *[]string      `json:"local_networks,omitempty" yaml:"local_networks,omitempty"`
	BackupSchedule BackupSchedule `json:"backup_schedule" yaml:"backup_schedule"`
	CertNotAfter   time.Time      `json:"cert_not_after,omitempty" yaml:"cert_not_after,omitempty"`
	LastContact    time.Time      `json:"last_contact,omitempty" yaml:"last_contact,omitempty"`
	AgentVersion   string         `json:"agent_version,omitempty" yaml:"agent_version,omitempty"`
	// Enrol exists only while enrolling (no secret: its sha256).
	Enrol *Enrol `json:"enrol,omitempty" yaml:"enrol,omitempty"`
	// QuarantinedUntil: a revoked server's tunnel address is free again
	// after it.
	QuarantinedUntil time.Time `json:"quarantined_until,omitempty" yaml:"quarantined_until,omitempty"`
	// Revoke is the revocation's progress (each step retried until done).
	Revoke *RevokeSteps `json:"revoke,omitempty" yaml:"revoke,omitempty"`
}

// Enrol is an enrolment in progress: the join code secret's sha256, the
// bootstrap public key, when the code expires, whether it was used, and
// how far it got (join, handshake, verify).
type Enrol struct {
	SecretSHA256 string    `json:"secret_sha256" yaml:"secret_sha256"`
	BootstrapPub string    `json:"bootstrap_pub" yaml:"bootstrap_pub"`
	IssuedAt     time.Time `json:"issued_at" yaml:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at" yaml:"expires_at"`
	Used         bool      `json:"used,omitempty" yaml:"used,omitempty"`
	Step         string    `json:"step,omitempty" yaml:"step,omitempty"`
}

// RevokeSteps records which revocation steps are done (spec §6).
// Serials are the certificate serials still to revoke: the pinned one at
// the revocation's start, and any signed while it is pending (an
// enrolment or renewal that raced it); step 2 is done when it is empty.
type RevokeSteps struct {
	At         time.Time `json:"at" yaml:"at"`
	Serials    []string  `json:"serials,omitempty" yaml:"serials,omitempty"`
	RelaysDone bool      `json:"relays_done,omitempty" yaml:"relays_done,omitempty"`
	Rotated    bool      `json:"rotated,omitempty" yaml:"rotated,omitempty"`
	// Remove: a removal (the entry goes once every step is done).
	Remove bool `json:"remove,omitempty" yaml:"remove,omitempty"`
}

// BackupSchedule is a server's scheduled backups (contract §11.5):
// off, daily or weekly at Hour (0–23), Weekday 0–6 (weekly; 0 = Sunday).
type BackupSchedule struct {
	Mode    string `json:"mode" yaml:"mode"`
	Hour    int    `json:"hour" yaml:"hour"`
	Weekday int    `json:"weekday" yaml:"weekday"`
}
