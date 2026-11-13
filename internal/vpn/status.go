package vpn

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// ErrStatusStale: wg's status.json is too old (or from the future):
// wg counts as down.
var ErrStatusStale = errors.New("the VPN service's status is out of date")

// Status is wg_data/status.json v1 (contract §16), written by wg.
type Status struct {
	Version int          `json:"version"`
	Written time.Time    `json:"written"`
	Mode    string       `json:"mode"`
	Edge    RoleStatus   `json:"edge"`
	People  *PeopleState `json:"people"`
}

// RoleStatus is a role's health.
type RoleStatus struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// PeopleState is the built-in people role's state (nil: the role is off).
type PeopleState struct {
	OK        bool         `json:"ok"`
	Error     string       `json:"error"`
	PublicKey string       `json:"public_key"`
	Port      int          `json:"port"`
	Subnet    string       `json:"subnet"`
	MTU       int          `json:"mtu"`
	Peers     []PeerStatus `json:"peers"`
}

// PeerStatus is one peer's last handshake.
type PeerStatus struct {
	PublicKey     string     `json:"public_key"`
	LastHandshake *time.Time `json:"last_handshake"`
}

// ReadStatus reads and checks status.json at now: strict, version 1,
// written within StatusMaxAge (either way); else wg is down.
func ReadStatus(path string, now time.Time) (*Status, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseStatus(b, now)
}

// ParseStatus is ReadStatus on bytes.
func ParseStatus(b []byte, now time.Time) (*Status, error) {
	var s Status
	if err := strictJSON(b, &s); err != nil {
		return nil, fmt.Errorf("status.json: %s", jsonErrKind(err))
	}
	if s.Version != StatusVersion {
		return nil, fmt.Errorf("status.json version %d: only %d is understood", s.Version, StatusVersion)
	}
	if d := now.Sub(s.Written); d > StatusMaxAge || d < -StatusMaxAge {
		return nil, ErrStatusStale
	}
	return &s, nil
}

// Handshakes maps each peer's public key to its last handshake.
func (s *Status) Handshakes() map[string]time.Time {
	out := map[string]time.Time{}
	if s == nil || s.People == nil {
		return out
	}
	for _, p := range s.People.Peers {
		if p.LastHandshake != nil {
			out[p.PublicKey] = *p.LastHandshake
		}
	}
	return out
}
