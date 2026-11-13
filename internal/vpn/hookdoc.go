package vpn

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// Hook operations (contract §13.8).
const (
	OpDevices = "devices"
	OpDNS     = "dns"
	Trigger   = "vpn"
)

// HookInput is a vpn hook's stdin.
type HookInput struct {
	Version  int      `json:"version"`
	Trigger  string   `json:"trigger"`
	Instance string   `json:"instance"`
	Op       string   `json:"op"`
	Ranges   []string `json:"ranges,omitempty"`
	Records  []Record `json:"records,omitempty"`
}

// Record is one DNS record a dns hook applies.
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// HookDevices is a validated devices document.
type HookDevices struct {
	Gateway netip.Addr
	Devices []HookDevice
	Dropped []Dropped
}

// HookDevice is one accepted device (Owner as the hook wrote it).
type HookDevice struct {
	ID, Name, Owner string
	Address         netip.Addr
	Online          bool
	LastSeen        *time.Time
	Expires         *time.Time
}

// Dropped is a device left out of the map, and why.
type Dropped struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Drop reasons.
const (
	DropIPv6       = "ipv6"
	DropOutside    = "outside_ranges"
	DropDuplicate  = "duplicate"
	DropExpired    = "expired"
	DropGateway    = "gateway"
	DropInvalid    = "invalid"
	DropUnresolved = "not a Portcullis person"
)

// clock is the hook parser's clock (tests).
var clock = time.Now

type rawHookDoc struct {
	Version int    `json:"version"`
	Gateway string `json:"gateway"`
	Devices []struct {
		ID       string     `json:"id"`
		Name     string     `json:"name"`
		Address  string     `json:"address"`
		Owner    string     `json:"owner"`
		Online   bool       `json:"online"`
		LastSeen *time.Time `json:"last_seen"`
		Expires  *time.Time `json:"expires"`
	} `json:"devices"`
}

// ParseHookDevices validates a devices hook's stdout (spec §6.1): at most
// MaxHookOutput bytes and MaxDevices devices, version 1, no unknown keys,
// a gateway inside ranges. Devices are dropped (with a reason) when their
// address is IPv6, outside ranges, the gateway's, shared with another
// device (every holder is dropped) or expired, or when the entry is
// unusable. Errors never quote the document.
func ParseHookDevices(out []byte, ranges []netip.Prefix) (*HookDevices, error) {
	if len(out) > MaxHookOutput {
		return nil, fmt.Errorf("the hook printed more than %d bytes", MaxHookOutput)
	}
	var raw rawHookDoc
	if err := strictJSON(bytes.TrimSpace(out), &raw); err != nil {
		return nil, fmt.Errorf("the hook's output is not a valid devices document (%s)", jsonErrKind(err))
	}
	if raw.Version != HookDocVersion {
		return nil, fmt.Errorf("devices document version %d: only %d is understood", raw.Version, HookDocVersion)
	}
	if len(raw.Devices) > MaxDevices {
		return nil, fmt.Errorf("the hook listed %d devices: at most %d", len(raw.Devices), MaxDevices)
	}
	gw, err := netip.ParseAddr(raw.Gateway)
	if err != nil || !gw.Is4() {
		return nil, fmt.Errorf("the devices document has no IPv4 gateway")
	}
	if !containsAddr(ranges, gw) {
		return nil, fmt.Errorf("the gateway %s is outside the provider's ranges", gw)
	}
	now := clock()
	res := &HookDevices{Gateway: gw}
	count := map[netip.Addr]int{}
	type cand struct {
		d   HookDevice
		bad string
	}
	cands := make([]cand, 0, len(raw.Devices))
	for _, rd := range raw.Devices {
		c := cand{d: HookDevice{ID: rd.ID, Name: rd.Name, Owner: rd.Owner, Online: rd.Online, LastSeen: rd.LastSeen, Expires: rd.Expires}}
		a, err := netip.ParseAddr(rd.Address)
		switch {
		case rd.ID == "" || !cleanField(rd.ID, 128) || !cleanField(rd.Owner, 256) || rd.Name != "" && !cleanField(rd.Name, 128):
			c.bad = DropInvalid
		case err != nil:
			c.bad = DropInvalid
		case a.Is6() && !a.Is4In6():
			c.bad = DropIPv6
		case !a.Is4():
			c.bad = DropInvalid
		case a == gw:
			c.bad = DropGateway
		case !containsAddr(ranges, a):
			c.bad = DropOutside
		case rd.Expires != nil && !now.Before(*rd.Expires):
			c.bad = DropExpired
		}
		if c.bad == "" {
			c.d.Address = a
			count[a]++
		}
		cands = append(cands, c)
	}
	for _, c := range cands {
		switch {
		case c.bad != "":
			res.Dropped = append(res.Dropped, Dropped{ID: clip(c.d.ID), Reason: c.bad})
		case count[c.d.Address] > 1:
			res.Dropped = append(res.Dropped, Dropped{ID: clip(c.d.ID), Reason: DropDuplicate})
		default:
			res.Devices = append(res.Devices, c.d)
		}
	}
	return res, nil
}

// cleanField: non-empty, at most max bytes, valid UTF-8, no control
// characters.
func cleanField(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 })
}

func clip(s string) string {
	if len(s) > 64 || !utf8.ValidString(s) || !cleanField(s, 64) {
		return "?"
	}
	return s
}

// jsonErrKind names a decode error without quoting the input.
func jsonErrKind(err error) string {
	switch msg := err.Error(); {
	case strings.Contains(msg, "unknown field"):
		return "unknown key"
	case strings.Contains(msg, "trailing data"):
		return "trailing data"
	default:
		return "malformed JSON"
	}
}
