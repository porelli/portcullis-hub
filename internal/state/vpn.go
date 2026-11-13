package state

import (
	"time"

	"github.com/portcullis/hub/internal/templates"
)

// Reach modes (contract §11, spec §8.1): no entry = internet.
const (
	ReachInternet = "internet"
	ReachVPN      = "vpn"
	// ReachAny is via: ["*"]: every wired, fresh provider.
	ReachAny = "*"
)

// Reach is one instance's Reachable from / Through choice.
type Reach struct {
	Mode        string   `json:"mode" yaml:"mode"`
	Via         []string `json:"via" yaml:"via"`
	PublicLinks bool     `json:"public_links,omitempty" yaml:"public_links,omitempty"`
}

// VPNState is the Hub's VPN configuration (contract §11; public data and
// metadata only: never a private key).
type VPNState struct {
	// UsersGroup gates every provider's device map ("" = every person).
	UsersGroup string `json:"users_group,omitempty" yaml:"users_group,omitempty"`
	// DevicesPerPerson bounds built-in devices (0 = the default 10).
	DevicesPerPerson int `json:"devices_per_person,omitempty" yaml:"devices_per_person,omitempty"`
	// Expiry is a new built-in device's lifetime ("" = 1y; 30d, 90d, 1y,
	// never, or a duration of at least 30 days).
	Expiry string `json:"expiry,omitempty" yaml:"expiry,omitempty"`
	// BuiltinOff leaves the built-in provider out of vpn.json.
	BuiltinOff bool `json:"builtin_off,omitempty" yaml:"builtin_off,omitempty"`
	// Providers are the wired marketplace instances by id.
	Providers map[string]VPNProvider `json:"providers,omitempty" yaml:"providers,omitempty"`
	// Devices are the built-in devices.
	Devices []VPNDevice `json:"devices,omitempty" yaml:"devices,omitempty"`
	// Quarantine: a removed built-in address → when it was removed (not
	// handed out again for 7 days).
	Quarantine map[string]time.Time `json:"quarantine,omitempty" yaml:"quarantine,omitempty"`
	// Static: a source: static provider's instance id → its assignments.
	Static map[string][]VPNStatic `json:"static,omitempty" yaml:"static,omitempty"`
}

// VPNProvider is one wired provider: its edge slot (port 9001+slot,
// gateway .16+slot), its identity refresh and DNS acknowledgement.
type VPNProvider struct {
	Slot     int                `json:"slot" yaml:"slot"`
	Refresh  templates.Duration `json:"refresh,omitempty" yaml:"refresh,omitempty"`
	WiredAt  time.Time          `json:"wired_at" yaml:"wired_at"`
	DNSAcked bool               `json:"dns_acked,omitempty" yaml:"dns_acked,omitempty"`
}

// VPNDevice is one built-in device: owner (lowercase username and the
// LLDAP uuid it was created under), address and public key (never the
// private key).
type VPNDevice struct {
	ID        string     `json:"id" yaml:"id"`
	User      string     `json:"user" yaml:"user"`
	UUID      string     `json:"uuid" yaml:"uuid"`
	Name      string     `json:"name" yaml:"name"`
	IP        string     `json:"ip" yaml:"ip"`
	PublicKey string     `json:"public_key" yaml:"public_key"`
	Created   time.Time  `json:"created" yaml:"created"`
	Expires   *time.Time `json:"expires,omitempty" yaml:"expires,omitempty"`
}

// VPNStatic is one admin assignment of a static provider's address.
type VPNStatic struct {
	IP   string `json:"ip" yaml:"ip"`
	User string `json:"user" yaml:"user"`
	Name string `json:"name" yaml:"name"`
}
