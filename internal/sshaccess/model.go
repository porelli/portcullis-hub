// Package sshaccess is the SSH access mapping's pure model (contract
// §18.12): validation, privilege, the merge rules and the compilation of
// Hub state into Vault roles, host bundles, people's certificate plans,
// client config and access previews. No I/O; deterministic output
// (sorted), pinned by golden files in testdata/golden.
package sshaccess

import (
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/state"
)

// Input is everything Compile reads. Members, Pending and Expired are a
// fresh directory.Membership's Users, Pending and Expired.
type Input struct {
	State state.SSHState
	// Members: user → group name → LLDAP group id.
	Members map[string]map[string]int
	// Pending: user → group → the end of a temporary membership.
	Pending map[string]map[string]time.Time
	// Expired: user → group: memberships past their end (never count).
	Expired map[string]map[string]bool
	Now     time.Time
	// VPNRanges returns the source ranges of "Only through the Portcullis
	// VPN" (the built-in subnet plus the via providers' ranges); nil = none.
	VPNRanges func(via []string) []string
	// UserCAs and RevokedKeys go into every bundle as given.
	UserCAs     []string
	RevokedKeys []string
}

// Compiled is the compilation of an Input.
type Compiled struct {
	// Roles: host group → its Vault role (only groups with principals).
	Roles map[string]cliapi.RoleSpec
	// Bundles: managed host id → its bundle (Serial and Generated left
	// zero: the Hub sets them, BundleHash ignores them).
	Bundles map[string]*cliapi.Bundle
	// People: user → what they may get.
	People map[string]PersonAccess
	// NeedUIDs: users who need a per-person account on a managed host but
	// have no uid yet (the Hub allocates, then compiles again).
	NeedUIDs []string
	// Hosts: host group → the names clients use (managed hosts' names and
	// addresses, then the group's patterns).
	Hosts map[string][]string
	// Hints: host group → the `--account` lines for `host trust`.
	Hints map[string][]string
	// Collisions: personal grants skipped because the username is an
	// account that isn't the person's (ssh_username_collision).
	Collisions []Collision

	in    Input
	sudo  map[string]map[string][]string // host → account → grant ids giving sudo
	where map[string]map[string][]grantUse
}

// PersonAccess is one person's certificate plans.
type PersonAccess struct {
	HostGroups map[string]CertPlan
}

// CertPlan is one certificate: the merge of the person's grants on one
// host group (contract §18.12 "Merge").
type CertPlan struct {
	Principals []string
	Extensions []string
	// Until is now + the earliest of the grants' TTLs, the setting's
	// maximum and a temporary membership's end.
	Until time.Time
	// Grants are the grant ids it comes from.
	Grants []string
}

// grantUse is one grant giving one account to one person.
type grantUse struct {
	grant   string
	group   string
	hg      string
	person  string
	account string
	until   *time.Time
	// end is the membership's end when temporary.
	end      *time.Time
	sudo     bool
	priv     bool
	root     bool
	personal bool
	kind     string
}

// principal is the use's `<kind>:<account>@<hg>`.
func (u grantUse) principal() string { return cliapi.Principal(u.kind, u.account, u.hg) }

// validPrincipal: the principal passes the grammar (a username that can't
// be a local account doesn't).
func (u grantUse) validPrincipal() bool {
	_, _, _, ok := cliapi.ParsePrincipal(u.principal())
	return ok
}

// PreviewRow is one line of an access preview (spec §9.8).
type PreviewRow struct {
	Person  string     `json:"person"`
	Account string     `json:"account"`
	Host    string     `json:"host,omitempty"`
	Root    bool       `json:"root"`
	Sudo    bool       `json:"sudo"`
	Via     []string   `json:"via"`
	Until   *time.Time `json:"until,omitempty"`
	Status  string     `json:"status"`
}

// Preview statuses.
const (
	StatusOK          = "ok"
	StatusUnmanaged   = "accounts and sudo unknown (unmanaged)"
	StatusInvalidName = "the username can't be a local account"
	// StatusCollision prefixes a skipped personal grant's reason.
	StatusCollision = "skipped: "
)

type stateGrant = state.SSHGrant
