package folderfix

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"
)

// setfaclSample is the system.posix_acl_access value Linux stores after
// `setfacl -m u:1000:rw,g:60001:rwx,m::rwx` on a 0644 file: the layout of
// include/uapi/linux/posix_acl_xattr.h (le32 a_version = 2, then
// {le16 e_tag, le16 e_perm, le32 e_id}), entries in posix_acl_valid order,
// ACL_UNDEFINED_ID (0xFFFFFFFF) on the non-named entries
// (fs/posix_acl.c posix_acl_to_xattr).
var setfaclSample = []byte{
	0x02, 0x00, 0x00, 0x00, // a_version 2
	0x01, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff, // USER_OBJ rw-
	0x02, 0x00, 0x06, 0x00, 0xe8, 0x03, 0x00, 0x00, // USER 1000 rw-
	0x04, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // GROUP_OBJ r--
	0x08, 0x00, 0x07, 0x00, 0x61, 0xea, 0x00, 0x00, // GROUP 60001 rwx
	0x10, 0x00, 0x07, 0x00, 0xff, 0xff, 0xff, 0xff, // MASK rwx
	0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff, // OTHER r--
}

var setfaclSampleACL = ACL{
	{Tag: TagUserObj, Perm: R | W},
	{Tag: TagUser, ID: 1000, Perm: R | W},
	{Tag: TagGroupObj, Perm: R},
	{Tag: TagGroup, ID: 60001, Perm: R | W | X},
	{Tag: TagMask, Perm: R | W | X},
	{Tag: TagOther, Perm: R},
}

func TestACLRoundTrip(t *testing.T) {
	a, err := DecodeACL(setfaclSample)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(a, setfaclSampleACL) {
		t.Fatalf("decode = %+v, want %+v", a, setfaclSampleACL)
	}
	if err := a.Valid(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	b, err := a.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(b, setfaclSample) {
		t.Fatalf("encode = % x\nwant     % x", b, setfaclSample)
	}

	// Encode sorts: the same entries in another order give the same bytes.
	shuffled := ACL{setfaclSampleACL[5], setfaclSampleACL[3], setfaclSampleACL[0],
		setfaclSampleACL[4], setfaclSampleACL[1], setfaclSampleACL[2]}
	b2, err := shuffled.Encode()
	if err != nil || !bytes.Equal(b2, setfaclSample) {
		t.Fatalf("shuffled encode = % x, %v", b2, err)
	}
	if !reflect.DeepEqual(shuffled, ACL{setfaclSampleACL[5], setfaclSampleACL[3], setfaclSampleACL[0],
		setfaclSampleACL[4], setfaclSampleACL[1], setfaclSampleACL[2]}) {
		t.Fatal("Encode reordered its receiver")
	}

	// Decoding accepts any id on the non-named entries and normalises it.
	odd := bytes.Clone(setfaclSample)
	binary.LittleEndian.PutUint32(odd[4+4:], 0) // USER_OBJ id 0
	a2, err := DecodeACL(odd)
	if err != nil || !reflect.DeepEqual(a2, setfaclSampleACL) {
		t.Fatalf("decode with id 0 on USER_OBJ = %+v, %v", a2, err)
	}

	// A header alone is an empty ACL (the kernel's "no ACL").
	if a, err := DecodeACL([]byte{2, 0, 0, 0}); err != nil || len(a) != 0 {
		t.Fatalf("header only = %+v, %v", a, err)
	}
}

func TestDecodeACLRefuses(t *testing.T) {
	v1 := bytes.Clone(setfaclSample)
	v1[0] = 1
	unknownTag := bytes.Clone(setfaclSample)
	unknownTag[4] = 0x40
	zeroTag := bytes.Clone(setfaclSample)
	zeroTag[4] = 0
	highPerm := bytes.Clone(setfaclSample)
	highPerm[6] = 0x08
	highPermHi := bytes.Clone(setfaclSample)
	highPermHi[7] = 0x01
	cases := map[string][]byte{
		"nil":             nil,
		"empty":           {},
		"short header":    {2, 0, 0},
		"truncated entry": setfaclSample[:len(setfaclSample)-1],
		"partial entry":   setfaclSample[:4+8+3],
		"version 1":       v1,
		"version 3":       append([]byte{3, 0, 0, 0}, setfaclSample[4:]...),
		"unknown tag":     unknownTag,
		"tag 0":           zeroTag,
		"perm bit 8":      highPerm,
		"perm high byte":  highPermHi,
	}
	for name, b := range cases {
		if a, err := DecodeACL(b); err == nil {
			t.Errorf("%s: decoded %+v, want an error", name, a)
		}
	}
}

func TestACLValid(t *testing.T) {
	base := func() ACL { return append(ACL(nil), setfaclSampleACL...) }
	bad := map[string]ACL{
		"empty":               {},
		"no user_obj":         base()[1:],
		"no group_obj":        append(base()[:2:2], base()[3:]...),
		"no other":            base()[:5],
		"named without mask":  append(base()[:4:4], base()[5]),
		"two user_obj":        append(ACL{{Tag: TagUserObj, Perm: R}}, base()...),
		"two masks":           append(base()[:5:5], ACL{{Tag: TagMask, Perm: R}, base()[5]}...),
		"duplicate named":     append(base()[:2:2], append(ACL{{Tag: TagUser, ID: 1000, Perm: R}}, base()[2:]...)...),
		"unsorted":            {base()[5], base()[0], base()[2]},
		"unsorted named ids":  append(ACL{base()[0], {Tag: TagUser, ID: 2000, Perm: R}, {Tag: TagUser, ID: 1000, Perm: R}}, base()[2:]...),
		"unknown tag":         append(base()[:5:5], Entry{Tag: 0x40}, base()[5]),
		"perm beyond rwx":     append(ACL{{Tag: TagUserObj, Perm: 8}}, base()[1:]...),
		"named undefined uid": append(ACL{base()[0], {Tag: TagUser, ID: 0xFFFFFFFF, Perm: R}}, base()[2:]...),
	}
	for name, a := range bad {
		if err := a.Valid(); err == nil {
			t.Errorf("%s: Valid() = nil for %+v", name, a)
		}
		if name == "unsorted" || name == "unsorted named ids" {
			continue // Encode sorts first
		}
		if b, err := a.Encode(); err == nil {
			t.Errorf("%s: Encode() = % x, want a refusal", name, b)
		}
	}
	good := map[string]ACL{
		"sample":            base(),
		"minimal":           FromMode(0o750),
		"mask without name": {{Tag: TagUserObj, Perm: 7}, {Tag: TagGroupObj, Perm: 5}, {Tag: TagMask, Perm: 5}, {Tag: TagOther}},
	}
	for name, a := range good {
		if err := a.Valid(); err != nil {
			t.Errorf("%s: Valid() = %v", name, err)
		}
	}
}

func TestFromModeAndMask(t *testing.T) {
	a := FromMode(0o640)
	want := ACL{{Tag: TagUserObj, Perm: R | W}, {Tag: TagGroupObj, Perm: R}, {Tag: TagOther, Perm: 0}}
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("FromMode(0640) = %+v", a)
	}
	if _, ok := a.Mask(); ok {
		t.Fatal("FromMode has a mask")
	}
	// File type and setgid bits are ignored.
	if got := FromMode(0o2040755); !reflect.DeepEqual(got, FromMode(0o755)) {
		t.Fatalf("FromMode ignores type bits: %+v", got)
	}

	m := ACL{{Tag: TagGroupObj, Perm: R}, {Tag: TagGroup, ID: 1000, Perm: R | W}}.RecalcMask()
	if p, ok := m.Mask(); !ok || p != R|W {
		t.Fatalf("RecalcMask mask = %v %v (%+v)", p, ok, m)
	}

	// The group class is GROUP_OBJ, USER and GROUP; USER_OBJ and OTHER don't count.
	full := FromMode(0o701).Set(TagUser, 7, X).Set(TagGroup, 9, W).RecalcMask()
	if p, _ := full.Mask(); p != W|X {
		t.Fatalf("mask = %v, want -wx (%+v)", p, full)
	}
	if err := full.Valid(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	// Recalculating replaces the existing mask.
	if p, _ := full.Set(TagMask, 0, R).RecalcMask().Mask(); p != W|X {
		t.Fatalf("recalc over an existing mask = %v", p)
	}
}

func TestSet(t *testing.T) {
	a := FromMode(0o750)
	b := a.Set(TagGroup, 60001, R|W|X).Set(TagUser, 1000, R).Set(TagGroup, 100, R)
	if !reflect.DeepEqual(a, FromMode(0o750)) {
		t.Fatal("Set modified its receiver")
	}
	want := ACL{
		{Tag: TagUserObj, Perm: 7},
		{Tag: TagUser, ID: 1000, Perm: R},
		{Tag: TagGroupObj, Perm: 5},
		{Tag: TagGroup, ID: 100, Perm: R},
		{Tag: TagGroup, ID: 60001, Perm: 7},
		{Tag: TagOther, Perm: 0},
	}
	if !reflect.DeepEqual(b, want) {
		t.Fatalf("Set = %+v", b)
	}
	// Replacing keeps one entry; a non-named entry ignores the id.
	c := b.Set(TagGroup, 100, R|X).Set(TagGroupObj, 1234, 7)
	if len(c) != len(b) || c[3].Perm != R|X || c[2].Perm != 7 || c[2].ID != 0 {
		t.Fatalf("replace = %+v", c)
	}
}

func TestSetUnsortedReceiver(t *testing.T) {
	// DecodeACL keeps buffer order; Set still yields a canonical ACL.
	unsorted := ACL{
		{Tag: TagOther, Perm: R},
		{Tag: TagGroupObj, Perm: R},
		{Tag: TagMask, Perm: 7},
		{Tag: TagUserObj, Perm: 6},
	}
	got := unsorted.Set(TagGroup, 60001, 7)
	want := ACL{
		{Tag: TagUserObj, Perm: 6},
		{Tag: TagGroupObj, Perm: R},
		{Tag: TagGroup, ID: 60001, Perm: 7},
		{Tag: TagMask, Perm: 7},
		{Tag: TagOther, Perm: R},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Set on an unsorted ACL = %+v", got)
	}
	if err := got.Valid(); err != nil {
		t.Fatalf("Valid: %v", err)
	}
	if unsorted[0].Tag != TagOther {
		t.Fatal("Set reordered its receiver")
	}
}

func TestClampKeepsEffective(t *testing.T) {
	a := ACL{
		{Tag: TagUserObj, Perm: R | W | X},
		{Tag: TagUser, ID: 1000, Perm: R | W | X},
		{Tag: TagGroupObj, Perm: R | X},
		{Tag: TagGroup, ID: 2000, Perm: R | W},
		{Tag: TagMask, Perm: R},
		{Tag: TagOther, Perm: 0},
	}
	c := a.Clamp()
	if c[1].Perm != R || c[3].Perm != R {
		t.Fatalf("Clamp = %+v", c)
	}
	if c[0].Perm != R|W|X || c[2].Perm != R|X || c[4].Perm != R {
		t.Fatalf("Clamp touched a non-named entry: %+v", c)
	}
	if a[1].Perm != R|W|X {
		t.Fatal("Clamp modified its receiver")
	}
	for _, p := range []Principal{{UID: 1000}, {UID: 3000, GIDs: []int{2000}}} {
		for _, want := range []Perm{R, W, X, R | W, R | X} {
			before := Allowed(Stat{UID: 1, GID: 1, Access: a}, p, want)
			after := Allowed(Stat{UID: 1, GID: 1, Access: c}, p, want)
			if before != after {
				t.Errorf("%+v want %v: before %v after %v", p, want, before, after)
			}
		}
	}
	// After the clamp the mask can be raised without anyone gaining.
	raised := c.Set(TagMask, 0, R|W|X)
	if Allowed(Stat{UID: 1, GID: 1, Access: raised}, Principal{UID: 1000}, W) {
		t.Fatal("raising the mask after Clamp granted w to user 1000")
	}
	// Without a mask nothing changes.
	if m := FromMode(0o750).Set(TagUser, 5, 7); !reflect.DeepEqual(m.Clamp(), m) {
		t.Fatal("Clamp without a mask changed the ACL")
	}
}

// FuzzDecodeACL: DecodeACL never panics; whatever it accepts re-encodes to
// bytes that decode to the same ACL, and a valid ACL whose non-named ids
// are ACL_UNDEFINED_ID re-encodes byte-identical.
func FuzzDecodeACL(f *testing.F) {
	f.Add(setfaclSample)
	f.Add([]byte{2, 0, 0, 0})
	f.Add([]byte{})
	f.Add(setfaclSample[:len(setfaclSample)-3])
	min, _ := FromMode(0o644).Encode()
	f.Add(min)
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := DecodeACL(b)
		if err != nil {
			return
		}
		if len(b) != 4+8*len(a) {
			t.Fatalf("accepted %d bytes for %d entries", len(b), len(a))
		}
		for _, e := range a {
			if !named(e.Tag) && e.ID != 0 {
				t.Fatalf("non-named entry kept id %d", e.ID)
			}
		}
		// Encode sorts, then refuses exactly what Valid refuses.
		sorted := slices.Clone(a)
		slices.SortStableFunc(sorted, less)
		out, err := a.Encode()
		if (err == nil) != (sorted.Valid() == nil) {
			t.Fatalf("Encode error %v, Valid of the sorted ACL %v: %+v", err, sorted.Valid(), a)
		}
		if err != nil {
			return
		}
		if a.Valid() != nil {
			// Unsorted input: the canonical bytes decode to the sorted ACL.
			again, err := DecodeACL(out)
			if err != nil || !reflect.DeepEqual(again, sorted) {
				t.Fatalf("re-decode = %+v, %v; want %+v", again, err, sorted)
			}
			return
		}
		again, err := DecodeACL(out)
		if err != nil || !reflect.DeepEqual(again, a) {
			t.Fatalf("re-decode = %+v, %v; want %+v", again, err, a)
		}
		canonical := true
		for i := range a {
			id := binary.LittleEndian.Uint32(b[4+8*i+4:])
			if !named(a[i].Tag) && id != undefinedID {
				canonical = false
			}
		}
		if canonical && !bytes.Equal(out, b) {
			t.Fatalf("re-encode = % x, want % x", out, b)
		}
	})
}
