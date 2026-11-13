// Package idmap reads a user namespace's id maps (/proc/<pid>/uid_map and
// gid_map, user_namespaces(7)) and names the two shapes Portcullis runs
// under (contract §6, §14.2): the identity map (rootful Docker) and the
// rootless Podman default namespace, where container id 0 is the operator
// and container ids 1–65535 are one subordinate range.
package idmap

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Overflow is the id the kernel shows for a host id the namespace doesn't
// map (/proc/sys/kernel/overflowuid and overflowgid, 65534 by default).
const Overflow = 65534

// MaxLines is the kernel's limit on the lines of an id map (Linux ≥ 4.15).
const MaxLines = 340

// MinSubordinate is the smallest subordinate range of the consistent
// shape: container ids 1–65535 must all be mapped.
const MinSubordinate = 65536

// Range is one line of an id map: Size ids from Container (inside the
// namespace) map to Size ids from Host (outside it).
type Range struct {
	Container uint32 `json:"container"`
	Host      uint32 `json:"host"`
	Size      uint32 `json:"size"`
}

// Map is a whole id map, in the file's order.
type Map []Range

// Parse reads an id map strictly: 1–MaxLines lines of three unsigned
// decimal numbers separated by spaces, a non-zero size each, and ranges
// that fit in 32 bits. Empty lines are ignored; anything else is an error.
func Parse(s string) (Map, error) {
	var m Map
	for i, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("id map line %d: want 3 numbers, got %d fields", i+1, len(f))
		}
		var n [3]uint32
		for j, v := range f {
			if v == "" || v[0] < '0' || v[0] > '9' {
				return nil, fmt.Errorf("id map line %d: %q is not a number", i+1, v)
			}
			u, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("id map line %d: %q is not a 32-bit number", i+1, v)
			}
			n[j] = uint32(u)
		}
		r := Range{Container: n[0], Host: n[1], Size: n[2]}
		if r.Size == 0 {
			return nil, fmt.Errorf("id map line %d: size 0", i+1)
		}
		if uint64(r.Container)+uint64(r.Size) > 1<<32 || uint64(r.Host)+uint64(r.Size) > 1<<32 {
			return nil, fmt.Errorf("id map line %d: range overflows 32 bits", i+1)
		}
		m = append(m, r)
		if len(m) > MaxLines {
			return nil, fmt.Errorf("id map: more than %d lines", MaxLines)
		}
	}
	if len(m) == 0 {
		return nil, errors.New("id map: empty")
	}
	return m, nil
}

// Identity reports the identity map of the initial namespace
// ("0 0 4294967295"): ids are not translated.
func (m Map) Identity() bool {
	return len(m) == 1 && m[0] == Range{Container: 0, Host: 0, Size: 4294967295}
}

// Consistent reports the rootless Podman default namespace: exactly
// container 0 → the operator (a non-root host id), then container ids
// from 1 → one subordinate range of at least MinSubordinate ids that
// doesn't start at host root (container uid 1 would be host uid 0).
func (m Map) Consistent() bool {
	return len(m) == 2 &&
		m[0].Container == 0 && m[0].Size == 1 && m[0].Host != 0 &&
		m[1].Container == 1 && m[1].Size >= MinSubordinate && m[1].Host != 0
}

// ToHost translates container id c to its host id; false when the map
// doesn't map it.
func (m Map) ToHost(c uint32) (uint32, bool) {
	for _, r := range m {
		if c >= r.Container && uint64(c) < uint64(r.Container)+uint64(r.Size) {
			return r.Host + (c - r.Container), true
		}
	}
	return 0, false
}
