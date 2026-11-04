// Package folderfix is the shared-folder fixer (contract §14.2): the POSIX
// ACL xattr codec, access evaluation, and (later) the walk that scans and
// applies consistent ownership.
package folderfix

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// Perm is an ACL entry's permission set: r 4, w 2, x 1
// (include/uapi/linux/posix_acl.h ACL_READ / ACL_WRITE / ACL_EXECUTE).
type Perm uint8

// The permission bits.
const (
	X Perm = 1
	W Perm = 2
	R Perm = 4

	permAll = R | W | X
)

// String is the getfacl form, e.g. "rw-".
func (p Perm) String() string {
	b := []byte("---")
	if p&R != 0 {
		b[0] = 'r'
	}
	if p&W != 0 {
		b[1] = 'w'
	}
	if p&X != 0 {
		b[2] = 'x'
	}
	return string(b)
}

// Entry tags (include/uapi/linux/posix_acl.h). Their numeric order is the
// canonical entry order.
const (
	TagUserObj  uint16 = 0x01
	TagUser     uint16 = 0x02
	TagGroupObj uint16 = 0x04
	TagGroup    uint16 = 0x08
	TagMask     uint16 = 0x10
	TagOther    uint16 = 0x20
)

// The xattr names Linux exposes ACLs under.
const XattrAccess, XattrDefault = "system.posix_acl_access", "system.posix_acl_default"

const (
	xattrVersion = 2          // POSIX_ACL_XATTR_VERSION
	undefinedID  = 0xFFFFFFFF // ACL_UNDEFINED_ID, the id of non-named entries
	headerSize   = 4          // struct posix_acl_xattr_header { __le32 a_version; }
	entrySize    = 8          // struct posix_acl_xattr_entry { __le16 e_tag; __le16 e_perm; __le32 e_id; }
)

// Entry is one ACL entry. ID is the uid (TagUser) or gid (TagGroup) and 0
// for every other tag.
type Entry struct {
	Tag  uint16
	ID   uint32
	Perm Perm
}

// ACL is a list of entries; the canonical order is by tag, then id.
type ACL []Entry

func named(tag uint16) bool { return tag == TagUser || tag == TagGroup }

func knownTag(tag uint16) bool {
	switch tag {
	case TagUserObj, TagUser, TagGroupObj, TagGroup, TagMask, TagOther:
		return true
	}
	return false
}

func less(a, b Entry) int {
	if a.Tag != b.Tag {
		return int(a.Tag) - int(b.Tag)
	}
	switch {
	case a.ID < b.ID:
		return -1
	case a.ID > b.ID:
		return 1
	}
	return 0
}

// DecodeACL parses a system.posix_acl_* xattr value (the layout of
// include/uapi/linux/posix_acl_xattr.h, read as fs/posix_acl.c
// posix_acl_from_xattr does): a little-endian u32 version 2, then 8-byte
// entries {u16 tag, u16 perm, u32 id}. Another version, a size that isn't
// header + n entries, an unknown tag or a perm beyond rwx is refused. The id
// of a non-named entry is ignored (stored as 0). A header alone is the empty
// ACL. Decoding doesn't check Valid: entries are kept in buffer order.
func DecodeACL(b []byte) (ACL, error) {
	if len(b) < headerSize {
		return nil, fmt.Errorf("acl: %d bytes, shorter than the header", len(b))
	}
	if v := binary.LittleEndian.Uint32(b); v != xattrVersion {
		return nil, fmt.Errorf("acl: version %d, want %d", v, xattrVersion)
	}
	body := b[headerSize:]
	if len(body)%entrySize != 0 {
		return nil, fmt.Errorf("acl: truncated (%d bytes after the header)", len(body))
	}
	a := make(ACL, 0, len(body)/entrySize)
	for off := 0; off < len(body); off += entrySize {
		tag := binary.LittleEndian.Uint16(body[off:])
		perm := binary.LittleEndian.Uint16(body[off+2:])
		id := binary.LittleEndian.Uint32(body[off+4:])
		if !knownTag(tag) {
			return nil, fmt.Errorf("acl: entry %d: unknown tag %#x", off/entrySize, tag)
		}
		if perm&^uint16(permAll) != 0 {
			return nil, fmt.Errorf("acl: entry %d: perm %#x beyond rwx", off/entrySize, perm)
		}
		if !named(tag) {
			id = 0
		}
		a = append(a, Entry{Tag: tag, ID: id, Perm: Perm(perm)})
	}
	return a, nil
}

// Valid checks what the kernel's posix_acl_valid (fs/posix_acl.c) checks
// before it stores an ACL, plus libacl's acl_check rule against duplicate
// ids: exactly one USER_OBJ, GROUP_OBJ and OTHER, at most one MASK and one
// whenever there are named entries, entries sorted by tag then id with no
// duplicate, known tags, perms within rwx, and no named entry with
// ACL_UNDEFINED_ID (the kernel can't map it). The empty ACL is invalid.
func (a ACL) Valid() error {
	var count [0x21]int
	namedEntries := false
	for i, e := range a {
		if !knownTag(e.Tag) {
			return fmt.Errorf("acl: entry %d: unknown tag %#x", i, e.Tag)
		}
		if e.Perm&^permAll != 0 {
			return fmt.Errorf("acl: entry %d: perm %#x beyond rwx", i, e.Perm)
		}
		if named(e.Tag) {
			namedEntries = true
			if e.ID == undefinedID {
				return fmt.Errorf("acl: entry %d: named entry with the undefined id", i)
			}
		}
		if i > 0 {
			c := less(a[i-1], e)
			if c == 0 {
				return fmt.Errorf("acl: entry %d: duplicate", i)
			}
			if c > 0 {
				return fmt.Errorf("acl: entry %d: out of order", i)
			}
		}
		count[e.Tag]++
	}
	for _, tag := range []uint16{TagUserObj, TagGroupObj, TagOther} {
		if count[tag] != 1 {
			return fmt.Errorf("acl: %d entries with tag %#x, want 1", count[tag], tag)
		}
	}
	if count[TagMask] > 1 {
		return errors.New("acl: more than one mask")
	}
	if namedEntries && count[TagMask] == 0 {
		return errors.New("acl: named entries without a mask")
	}
	return nil
}

// Encode returns the xattr value for a sorted copy of the ACL
// (fs/posix_acl.c posix_acl_to_xattr's layout: perm as u16, non-named ids
// ACL_UNDEFINED_ID). An ACL that isn't Valid once sorted is refused, so
// nothing invalid is ever handed to setxattr.
func (a ACL) Encode() ([]byte, error) {
	s := slices.Clone(a)
	slices.SortStableFunc(s, less)
	if err := s.Valid(); err != nil {
		return nil, err
	}
	b := make([]byte, headerSize+entrySize*len(s))
	binary.LittleEndian.PutUint32(b, xattrVersion)
	for i, e := range s {
		off := headerSize + entrySize*i
		id := e.ID
		if !named(e.Tag) {
			id = undefinedID
		}
		binary.LittleEndian.PutUint16(b[off:], e.Tag)
		binary.LittleEndian.PutUint16(b[off+2:], uint16(e.Perm))
		binary.LittleEndian.PutUint32(b[off+4:], id)
	}
	return b, nil
}

// FromMode is the minimal ACL a mode's permission bits imply (acl(5): the
// three base entries, no mask; file type and setuid/setgid/sticky ignored).
func FromMode(mode uint32) ACL {
	return ACL{
		{Tag: TagUserObj, Perm: Perm(mode>>6) & permAll},
		{Tag: TagGroupObj, Perm: Perm(mode>>3) & permAll},
		{Tag: TagOther, Perm: Perm(mode) & permAll},
	}
}

// Mask returns the MASK entry's perms, and whether there is one.
func (a ACL) Mask() (Perm, bool) {
	for _, e := range a {
		if e.Tag == TagMask {
			return e.Perm, true
		}
	}
	return 0, false
}

// Clamp narrows every named (USER / GROUP) entry to entry ∧ mask: what it
// grants today. Raising the mask afterwards changes nobody's effective
// rights through a named entry. Without a mask the ACL is returned as a copy.
// The receiver is never modified.
func (a ACL) Clamp() ACL {
	out := slices.Clone(a)
	m, ok := a.Mask()
	if !ok {
		return out
	}
	for i := range out {
		if named(out[i].Tag) {
			out[i].Perm &= m
		}
	}
	return out
}

// Set returns a copy with the entry for (tag, id) set to p: replaced if
// present, else inserted in canonical position. The id is ignored (0) for
// non-named tags. The receiver is never modified.
func (a ACL) Set(tag uint16, id uint32, p Perm) ACL {
	if !named(tag) {
		id = 0
	}
	out := slices.Clone(a)
	for i := range out {
		if out[i].Tag == tag && out[i].ID == id {
			out[i].Perm = p
			return out
		}
	}
	e := Entry{Tag: tag, ID: id, Perm: p}
	i, _ := slices.BinarySearchFunc(out, e, less)
	return slices.Insert(out, i, e)
}

// RecalcMask returns a copy whose MASK is the union of the group class
// (GROUP_OBJ, every USER and GROUP entry), as libacl's acl_calc_mask and
// `setfacl` without -n do.
func (a ACL) RecalcMask() ACL {
	var m Perm
	for _, e := range a {
		switch e.Tag {
		case TagGroupObj, TagUser, TagGroup:
			m |= e.Perm
		}
	}
	return a.Set(TagMask, 0, m)
}
