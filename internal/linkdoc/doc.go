// Package linkdoc is link.json v1 (contract §17): the document the Hub
// writes into the link_doc volume for the link role of core's wg service
// (peers: the workers' public keys, tunnel addresses and states; relays:
// the per-instance bearer hashes). Parse is the reference reader; core's
// wg reader (wg/internal/linkdoc) is held to the same vectors
// (testdata/link_json_vectors.json, a byte copy in core's tests/). No
// hub, engine or network imports.
package linkdoc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/vpn"
)

const (
	// Version is the only version a reader understands.
	Version = 1
	// FileName is the document's name in the link_doc volume.
	FileName = "link.json"
	// MaxPeers / MaxRelays bound the lists (checked before any entry);
	// MaxSize the file.
	MaxPeers  = 250
	MaxRelays = 4096
	MaxSize   = 1 << 20
)

// Peer states (pre-flight P23: every non-revoked server is a peer; the
// Hub's offline is Hub-only and stays ready here, so it can reconnect).
const (
	StateEnrolling = "enrolling"
	StateReady     = "ready"
)

// Subnet is the link subnet (fixed in v1, pre-flight P3).
var Subnet = servers.LinkSubnet

// Peer is one worker: its server id, WireGuard public key (standard
// base64, 32 bytes), tunnel address and state.
type Peer struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	IP        netip.Addr `json:"ip"`
	State     string     `json:"state"`
}

// Relay is one placed instance's data-path bearer: the sha256 (hex) of
// its token, the instance and the server it runs on.
type Relay struct {
	TokenSHA256 string `json:"token_sha256"`
	Instance    string `json:"instance"`
	Server      string `json:"server"`
}

// Doc is link.json v1.
type Doc struct {
	Version   int          `json:"version"`
	WrittenAt time.Time    `json:"written_at"`
	Subnet    netip.Prefix `json:"subnet"`
	Peers     []Peer       `json:"peers"`
	Relays    []Relay      `json:"relays"`
}

// zeroKey is the all-zero key: never a peer's.
const zeroKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// instanceRe is an instance id as the contract allows it (§11.1: segments
// of [a-z0-9] joined by single "-", at most 64 characters).
var instanceRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Parse is the reference reader (contract §17). Any error means link has
// no peers and refuses every CONNECT:
//   - strict JSON: no unknown, duplicate, missing or null key, no
//     trailing data, at most MaxSize bytes;
//   - version 1, written_at set (RFC 3339 UTC), subnet exactly 10.214.0.0/24;
//   - at most 250 peers and 4096 relays;
//   - each peer: a valid server id (never primary), a WireGuard public
//     key (never all zeros), an ip inside the subnet in .10–.250, state enrolling|ready; ids,
//     keys and ips unique;
//   - each relay: token_sha256 64 lower-case hex digits (unique), a valid
//     instance id, and server a ready peer.
func Parse(b []byte) (*Doc, error) {
	if len(b) > MaxSize {
		return nil, fmt.Errorf("link.json: larger than %d bytes", MaxSize)
	}
	var d Doc
	if err := jsonstrict.Decode(b, &d); err != nil {
		return nil, fmt.Errorf("link.json: %v", err)
	}
	if err := d.check(); err != nil {
		return nil, fmt.Errorf("link.json: %v", err)
	}
	return &d, nil
}

func utcOffset(t time.Time) bool {
	_, off := t.Zone()
	return off == 0
}

func (d *Doc) check() error {
	switch {
	case d.Version != Version:
		return fmt.Errorf("version %d: only version %d is understood", d.Version, Version)
	case d.WrittenAt.IsZero():
		return errors.New("written_at: not set")
	case !utcOffset(d.WrittenAt):
		return errors.New("written_at: must be UTC (Z)")
	case d.Subnet != Subnet:
		return fmt.Errorf("subnet: must be %s", Subnet)
	case len(d.Peers) > MaxPeers:
		return fmt.Errorf("more than %d peers", MaxPeers)
	case len(d.Relays) > MaxRelays:
		return fmt.Errorf("more than %d relays", MaxRelays)
	}
	ids, keys, ips := map[string]bool{}, map[string]bool{}, map[netip.Addr]bool{}
	ready := map[string]bool{}
	for i, p := range d.Peers {
		switch {
		case servers.ValidID(p.ID) != nil:
			return fmt.Errorf("peers[%d]: id is not a server id", i)
		case !vpn.ValidPublicKey(p.PublicKey) || p.PublicKey == zeroKey:
			return fmt.Errorf("peers[%d]: public_key is not a WireGuard key", i)
		case !servers.TunnelIPOK(p.IP):
			return fmt.Errorf("peers[%d]: ip is not a worker address of %s (.%d–.%d)", i, Subnet, servers.FirstHost, servers.LastHost)
		case p.State != StateEnrolling && p.State != StateReady:
			return fmt.Errorf("peers[%d]: state must be %s or %s", i, StateEnrolling, StateReady)
		case ids[p.ID]:
			return fmt.Errorf("peers[%d]: duplicate peer id", i)
		case keys[p.PublicKey]:
			return fmt.Errorf("peers[%d]: duplicate public key", i)
		case ips[p.IP]:
			return fmt.Errorf("peers[%d]: duplicate peer ip", i)
		}
		ids[p.ID], keys[p.PublicKey], ips[p.IP] = true, true, true
		if p.State == StateReady {
			ready[p.ID] = true
		}
	}
	tokens := map[string]bool{}
	for i, r := range d.Relays {
		switch {
		case !servers.ValidSHA256Hex(r.TokenSHA256):
			return fmt.Errorf("relays[%d]: token_sha256 must be 64 lower-case hex digits", i)
		case tokens[r.TokenSHA256]:
			return fmt.Errorf("relays[%d]: duplicate relay token", i)
		case len(r.Instance) > 64 || !instanceRe.MatchString(r.Instance):
			return fmt.Errorf("relays[%d]: instance is not an instance id", i)
		case !ready[r.Server]:
			return fmt.Errorf("relays[%d]: server is not a ready peer", i)
		}
		tokens[r.TokenSHA256] = true
	}
	return nil
}

// Write writes d as dir/link.json: checked as Parse reads it (an invalid
// document is never written; the last good file stays), nil lists as [],
// atomically, mode 0640, group gid (set before the rename, so link never
// sees a file it can't read).
func Write(dir string, gid int, d *Doc) error {
	out := *d
	out.WrittenAt = out.WrittenAt.UTC()
	if out.Peers == nil {
		out.Peers = []Peer{}
	}
	if out.Relays == nil {
		out.Relays = []Relay{}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if _, err := Parse(b); err != nil {
		return fmt.Errorf("refusing to write an invalid document: %w", err)
	}
	return fsutil.WriteFileAtomicGroup(filepath.Join(dir, FileName), append(b, '\n'), 0o640, gid)
}
