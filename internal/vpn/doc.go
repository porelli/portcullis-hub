// Package vpn is the Hub's pure VPN model (contract §4 vpn.json v2,
// §13.8 the vpn hook documents, §16 the wg service's status.json):
// the vpn.json writer and its reference reader (shared vectors with
// core's readers), client ranges, address allocation with quarantine and
// the hook and status documents. No hub, engine or network imports.
package vpn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
)

// Versions and limits (contract §4, §13.8, §16; spec §4–§10).
const (
	DocVersion     = 2
	HookDocVersion = 1
	StatusVersion  = 1

	MaxHookOutput = 4 << 20
	MaxDevices    = 10000

	RefreshMin     = 15 * time.Second
	RefreshMax     = 10 * time.Minute
	RefreshDefault = time.Minute
	StaleFloor     = 3 * time.Minute

	Quarantine              = 7 * 24 * time.Hour
	DefaultDevicesPerPerson = 10
	DefaultExpiry           = 365 * 24 * time.Hour
	MinExpiry               = 30 * 24 * time.Hour

	EdgePortBase = 9001
	GatewayFirst = 16
	GatewayLast  = 62
	BuiltinMTU   = 1280
	StatusMaxAge = 30 * time.Second

	// Provider sources (vpn.json providers[].source).
	SourceBuiltin = "builtin"
	SourceHook    = "hook"
	SourceStatic  = "static"
	// MaxStaleWindow bounds stale_after − refreshed_at of a hook map.
	MaxStaleWindow = 30 * time.Minute

	// BuiltinID is the built-in people provider's id.
	BuiltinID = "builtin"
	// FileName is vpn.json's name in the Hub's data directory (policy
	// devices_file must be exactly this).
	FileName = "vpn.json"
)

// FileGID is Write's group (the Hub passes its configured group to
// WriteGroup; a variable for tests).
var FileGID = 10001

// Doc is vpn.json v2.
type Doc struct {
	Version   int        `json:"version"`
	Builtin   *Builtin   `json:"builtin,omitempty"`
	Providers []Provider `json:"providers"`
	Devices   []Device   `json:"devices"`
}

// Builtin is the built-in people role's configuration (wg reads it).
type Builtin struct {
	Subnet          string   `json:"subnet"`
	ServerPublicKey string   `json:"server_public_key"`
	Domains         []string `json:"domains"`
	Peers           []Peer   `json:"peers"`
}

// Peer is one built-in WireGuard peer (public data only).
type Peer struct {
	IP        string     `json:"ip"`
	PublicKey string     `json:"public_key"`
	DeviceID  string     `json:"device_id"`
	Expires   *time.Time `json:"expires"`
}

// Provider is one provider: the built-in one or a wired instance.
type Provider struct {
	ID        string   `json:"id"`
	Label     string   `json:"label,omitempty"`
	Ranges    []string `json:"ranges"`
	EdgePort  int      `json:"edge_port"`
	GatewayIP string   `json:"gateway_ip"`
	// Source is builtin, hook or static (required): a hook map needs
	// refreshed_at and stale_after (at most 30 min apart), builtin and
	// static ones have neither.
	Source      string     `json:"source"`
	RefreshedAt *time.Time `json:"refreshed_at,omitempty"`
	StaleAfter  *time.Time `json:"stale_after,omitempty"`
	Stale       bool       `json:"stale"`
}

// Device is one device of a provider's map, bound to a Portcullis person.
type Device struct {
	IP       string     `json:"ip"`
	Provider string     `json:"provider"`
	User     string     `json:"user"`
	DeviceID string     `json:"device_id"`
	Name     string     `json:"name"`
	Expires  *time.Time `json:"expires"`
}

// Write writes d to path atomically, mode 0640, group FileGID.
func Write(path string, d Doc) error { return WriteGroup(path, d, FileGID) }

// WriteGroup is Write with the file's group: the one group shared only
// with vpn.json's readers (wg and group-gate).
func WriteGroup(path string, d Doc, gid int) error {
	if d.Providers == nil {
		d.Providers = []Provider{}
	}
	if d.Devices == nil {
		d.Devices = []Device{}
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if _, err := Parse(b); err != nil {
		return fmt.Errorf("vpn.json: refusing to write an invalid document: %w", err)
	}
	if err := fsutil.WriteFileAtomic(path, append(b, '\n'), 0o640); err != nil {
		return err
	}
	return os.Chown(path, -1, gid)
}

// strictJSON decodes b into v, refusing unknown keys and trailing data.
func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing data after the document")
	}
	return nil
}

// ValidPublicKey: a WireGuard public key (32 bytes, standard base64).
func ValidPublicKey(k string) bool {
	b, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == k
}

// Parse is the reference reader: strict (unknown keys refused), version
// 2 only, provider ids unique, ranges valid and pairwise disjoint,
// device and peer addresses valid, unique and inside their provider's
// ranges. Any error means every VPN request is denied.
func Parse(b []byte) (*Doc, error) {
	var d Doc
	if err := strictJSON(b, &d); err != nil {
		return nil, err
	}
	if d.Version != DocVersion {
		return nil, fmt.Errorf("version %d: only version %d is understood", d.Version, DocVersion)
	}
	ranges := map[string][]netip.Prefix{}
	ports := map[int]string{}
	var all []netip.Prefix
	var allOwner []string
	for _, p := range d.Providers {
		if p.ID == "" {
			return nil, fmt.Errorf("a provider has no id")
		}
		if _, dup := ranges[p.ID]; dup {
			return nil, fmt.Errorf("provider %s listed twice", p.ID)
		}
		ps, err := ParseRanges(p.Ranges)
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", p.ID, err)
		}
		if len(ps) == 0 {
			return nil, fmt.Errorf("provider %s has no ranges", p.ID)
		}
		for i, a := range all {
			for _, q := range ps {
				if a.Overlaps(q) {
					return nil, fmt.Errorf("overlapping provider ranges: %s (%s) overlaps %s (%s)", a, allOwner[i], q, p.ID)
				}
			}
		}
		for _, q := range ps {
			all, allOwner = append(all, q), append(allOwner, p.ID)
		}
		ranges[p.ID] = ps
		if p.ID == BuiltinID {
			if d.Builtin == nil {
				return nil, fmt.Errorf("missing builtin with a builtin provider")
			}
			if p.Source != SourceBuiltin {
				return nil, fmt.Errorf("provider builtin: source %q must be builtin", p.Source)
			}
			if p.EdgePort != 0 || p.GatewayIP != "" || p.RefreshedAt != nil || p.StaleAfter != nil {
				return nil, fmt.Errorf("provider builtin has an edge port, a gateway, refreshed_at or stale_after")
			}
		} else {
			if p.EdgePort < EdgePortBase || p.EdgePort > EdgePortBase+GatewayLast-GatewayFirst {
				return nil, fmt.Errorf("provider %s: edge_port %d outside %d–%d", p.ID, p.EdgePort, EdgePortBase, EdgePortBase+GatewayLast-GatewayFirst)
			}
			if a, err := netip.ParseAddr(p.GatewayIP); err != nil || !a.Is4() {
				return nil, fmt.Errorf("provider %s: gateway_ip %q is not an IPv4 address", p.ID, p.GatewayIP)
			}
			if ports[p.EdgePort] != "" {
				return nil, fmt.Errorf("providers %s and %s share edge_port %d", ports[p.EdgePort], p.ID, p.EdgePort)
			}
			ports[p.EdgePort] = p.ID
			switch p.Source {
			case SourceHook:
				// A hook map carries its own expiry: a file without one
				// could never go stale (a stopped Hub must end in deny).
				if p.RefreshedAt == nil || p.StaleAfter == nil {
					return nil, fmt.Errorf("provider %s (hook) has no refreshed_at or no stale_after", p.ID)
				}
				if !p.StaleAfter.After(*p.RefreshedAt) {
					return nil, fmt.Errorf("provider %s: stale_after is not after refreshed_at", p.ID)
				}
				if p.StaleAfter.Sub(*p.RefreshedAt) > MaxStaleWindow {
					return nil, fmt.Errorf("provider %s: stale_after is more than 30 min after refreshed_at", p.ID)
				}
			case SourceStatic:
				// An admin's assignments never go stale.
				if p.RefreshedAt != nil || p.StaleAfter != nil {
					return nil, fmt.Errorf("provider %s (static) has refreshed_at or stale_after", p.ID)
				}
			default:
				return nil, fmt.Errorf("provider %s: source %q must be hook or static", p.ID, p.Source)
			}
		}
	}
	if d.Builtin != nil {
		sub, err := netip.ParsePrefix(d.Builtin.Subnet)
		if err != nil || !sub.Addr().Is4() || sub.Masked() != sub {
			return nil, fmt.Errorf("builtin.subnet %q is not an IPv4 prefix", d.Builtin.Subnet)
		}
		br, ok := ranges[BuiltinID]
		if !ok {
			return nil, fmt.Errorf("builtin without a builtin provider")
		}
		if len(br) != 1 || br[0] != sub {
			return nil, fmt.Errorf("provider builtin's ranges must be exactly builtin.subnet")
		}
		if !ValidPublicKey(d.Builtin.ServerPublicKey) {
			return nil, fmt.Errorf("builtin.server_public_key is not a WireGuard public key")
		}
		seenIP, seenKey := map[netip.Addr]bool{}, map[string]bool{}
		for _, pr := range d.Builtin.Peers {
			a, err := netip.ParseAddr(pr.IP)
			if err != nil || !a.Is4() || !sub.Contains(a) {
				return nil, fmt.Errorf("builtin peer %q is not an address of builtin.subnet", pr.IP)
			}
			if seenIP[a] {
				return nil, fmt.Errorf("duplicate peer ip %s", a)
			}
			if !ValidPublicKey(pr.PublicKey) || seenKey[pr.PublicKey] {
				return nil, fmt.Errorf("builtin peer %s: invalid or duplicate public key", a)
			}
			if pr.DeviceID == "" {
				return nil, fmt.Errorf("builtin peer %s has no device_id", a)
			}
			seenIP[a], seenKey[pr.PublicKey] = true, true
		}
	}
	seen := map[netip.Addr]bool{}
	for _, dv := range d.Devices {
		a, err := netip.ParseAddr(dv.IP)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("device ip %q is not an IPv4 address", dv.IP)
		}
		if seen[a] {
			return nil, fmt.Errorf("duplicate device ip %s", a)
		}
		seen[a] = true
		ps, ok := ranges[dv.Provider]
		if !ok {
			return nil, fmt.Errorf("device %s: unknown provider %q", a, dv.Provider)
		}
		if !containsAddr(ps, a) {
			return nil, fmt.Errorf("device %s is outside provider %s's ranges", a, dv.Provider)
		}
		if dv.User == "" || dv.DeviceID == "" {
			return nil, fmt.Errorf("device %s has no user or device_id", a)
		}
	}
	return &d, nil
}

// Lookup is the reader's decision for a client address that arrived
// through provider's ingress, at now: the device it belongs to, or false
// (deny). The provider is never taken from anything the client or a
// gateway sends: it is the ingress the connection came in on (the edge's
// per-provider port 9001+slot, accepted only from that provider's
// gateway_ip; the people stack for builtin). The address must lie in
// THAT provider's ranges, the provider must not be stale (its flag, or
// stale_after passed by the reader's own clock), and a device of THAT
// provider must hold the address, unexpired (a built-in device also
// needs its unexpired peer).
func (d *Doc) Lookup(provider string, ip netip.Addr, now time.Time) (Device, bool) {
	var prov *Provider
	for i := range d.Providers {
		if d.Providers[i].ID == provider {
			prov = &d.Providers[i]
			break
		}
	}
	if prov == nil {
		return Device{}, false
	}
	ps, err := ParseRanges(prov.Ranges)
	if err != nil || !containsAddr(ps, ip) {
		return Device{}, false
	}
	if prov.Stale || prov.StaleAfter != nil && !now.Before(*prov.StaleAfter) {
		return Device{}, false
	}
	for _, dv := range d.Devices {
		if dv.Provider != prov.ID || dv.IP != ip.String() {
			continue
		}
		if expired(dv.Expires, now) {
			return Device{}, false
		}
		if prov.ID == BuiltinID {
			if d.Builtin == nil {
				return Device{}, false
			}
			ok := false
			for _, pr := range d.Builtin.Peers {
				if pr.IP == dv.IP && pr.DeviceID == dv.DeviceID && !expired(pr.Expires, now) {
					ok = true
				}
			}
			if !ok {
				return Device{}, false
			}
		}
		return dv, true
	}
	return Device{}, false
}

// ProviderOf is the one provider whose ranges hold ip ("" = none). Parse
// guarantees ranges are pairwise disjoint across providers, and the edge
// re-originates only addresses inside the ranges of the provider whose
// ingress they came through, so behind the edge (Traefik vpnsecure,
// group-gate) the address names that provider.
func (d *Doc) ProviderOf(ip netip.Addr) string {
	for _, p := range d.Providers {
		if ps, err := ParseRanges(p.Ranges); err == nil && containsAddr(ps, ip) {
			return p.ID
		}
	}
	return ""
}

func expired(t *time.Time, now time.Time) bool { return t != nil && !now.Before(*t) }

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
