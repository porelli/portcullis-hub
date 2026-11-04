package folderfix

import (
	"errors"
	"fmt"
	"time"
)

// Target is the consistent-ownership state an apply produces (contract
// §14.2). GID 0 means "scan without an expected state".
type Target struct {
	GID      int      // folder gid (0 = scan without an expected state)
	Files    string   // "rw" | "r"
	OwnerUID *int     // must_own
	Mkdir    []string // relative subpaths to create (apply)
}

// Options select the folder and what a run looks for.
type Options struct {
	Root string // "/folder"
	// ExpectDev / ExpectIno: 0 = unchecked; else the root's st_dev and
	// st_ino must match (contract §6: every run on a defined folder).
	ExpectDev uint64
	ExpectIno uint64
	// ExpectMountRoot: "" = unchecked; else the root field of Root's line in
	// /proc/self/mountinfo must be exactly this (R41).
	ExpectMountRoot string
	// ExpectDigest (apply): "" = unchecked; else the plan's Digest must be
	// exactly this (the snapshot's entries, M5).
	ExpectDigest string
	// SnapshotRootDev / SnapshotRootIno (restore, undo snapshot): 0 = the
	// apply snapshot's header must name the walk root itself; else it
	// must name exactly these — the root as it was when the snapshot was
	// taken, before a device-only identity re-check — and the inode must
	// be the walk root's (follow-up (a)).
	SnapshotRootDev uint64
	SnapshotRootIno uint64
	Target          Target
	Principals      []Principal
	Children        bool // per first-level child owner counts
	// TopOnly (scan with Children): read the first level only, never
	// entering a child (a per-person tree: its top-level directories'
	// owner, group and mode are all the doctor judges).
	TopOnly    bool
	MaxEntries int64
	MaxTime    time.Duration
}

// maxSample is the number of relative paths a Count keeps.
const maxSample = 20

// Count is a number of entries and up to 20 of their relative paths.
type Count struct {
	N      int64    `json:"n"`
	Sample []string `json:"sample,omitempty"`
}

func (c *Count) add(rel string) {
	c.N++
	if len(c.Sample) < maxSample {
		c.Sample = append(c.Sample, clip(rel, maxPathRunes))
	}
}

// OwnerCount is how many entries one uid:gid pair owns.
type OwnerCount struct {
	UID int   `json:"uid"`
	GID int   `json:"gid"`
	N   int64 `json:"n"`
}

// PrincipalAccess is what one principal can't reach.
type PrincipalAccess struct {
	Name      string `json:"name"`
	UID       int    `json:"uid"`
	CantRead  Count  `json:"cant_read"`
	CantWrite Count  `json:"cant_write"`
}

// Conformance counts the entries (among those the fix handles) that differ
// from the Target, per attribute. A verify scan after an apply finds all 0.
type Conformance struct {
	Group      Count `json:"group"`
	Setgid     Count `json:"setgid"`
	DefaultACL Count `json:"default_acl"`
	Mode       Count `json:"mode"` // permission bits or the access ACL
	Owner      Count `json:"owner"`
}

// PlanCounts is what an apply to the Target would do.
type PlanCounts struct {
	Changes       int64  `json:"changes"` // entries an apply changes (its --expect)
	Digest        string `json:"digest"`  // sha256 of those entries' paths and current state (its --expect-digest)
	ChangeGroup   Count  `json:"change_group"`
	AddSetgid     Count  `json:"add_setgid"`
	AddDefaultACL Count  `json:"add_default_acl"`
	ChangeOwner   Count  `json:"change_owner"`
	Narrowed      Count  `json:"narrowed"`
	// KeepGroup: previous gid → entries given a named group entry for it.
	KeepGroup map[int]int64 `json:"keep_group"`
	// KeepUser: previous owner uid (must_own) → entries given a named user entry.
	KeepUser map[int]int64 `json:"keep_user"`
	// LoseAccess: only without ACL support: entries whose previous group or
	// owner would lose (or, falling back to "others", gain) bits.
	LoseAccess Count `json:"lose_access"`
}

// ChildOwner is one first-level child: its owner, group, permission bits
// and type, and how many entries below it (itself included) are not owned
// by that uid.
type ChildOwner struct {
	Name    string `json:"name"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	Mode    uint32 `json:"mode"` // permission bits (07777)
	Dir     bool   `json:"dir"`
	Entries int64  `json:"entries"`
	Foreign int64  `json:"foreign"`
}

// Skipped counts entries the fix leaves alone because a snapshot couldn't
// record them (R49).
type Skipped struct {
	PathTooLong Count `json:"path_too_long"` // path > 4096 bytes
	ACLTooLarge Count `json:"acl_too_large"` // its snapshot line would exceed the line cap
	// FileCaps: regular files with file capabilities (security.capability),
	// which a chown would make the kernel drop (R54).
	FileCaps Count `json:"filecaps"`
}

// Report is the one JSON line every mode prints.
type Report struct {
	Version       int    `json:"version"`
	Mode          string `json:"mode"`
	Root          string `json:"root"`
	Dev           uint64 `json:"dev"`
	Ino           uint64 `json:"ino"`
	MountRoot     string `json:"mount_root"`
	FSType        string `json:"fs_type"`
	ACL           bool   `json:"acl"`
	Xattr         bool   `json:"xattr"`
	Entries       int64  `json:"entries"`
	Dirs          int64  `json:"dirs"`
	Files         int64  `json:"files"`
	Partial       bool   `json:"partial"`
	PartialReason string `json:"partial_reason,omitempty"` // "entries" | "time" | "depth"

	Owners       []OwnerCount      `json:"owners"` // top 10 by N
	HardLinks    Count             `json:"hard_links"`
	MountPoints  Count             `json:"mount_points"`
	Specials     Count             `json:"specials"`
	Symlinks     Count             `json:"symlinks"`
	SetID        Count             `json:"setid"`         // setgid files under a group change, setuid files under must_own: skipped
	Races        Count             `json:"races"`         // changed between fstatat and open: skipped
	BadACL       Count             `json:"bad_acl"`       // an ACL the fix can't carry exactly: skipped
	Failed       Count             `json:"failed"`        // couldn't be read or changed
	ChangedSince Count             `json:"changed_since"` // restore: changed since the fix (or gone): skipped
	Skipped      Skipped           `json:"skipped"`
	Principals   []PrincipalAccess `json:"principals,omitempty"`
	Expected     *Conformance      `json:"expected,omitempty"` // when Target.GID != 0
	Plan         *PlanCounts       `json:"plan,omitempty"`     // when Target.GID != 0
	Children     []ChildOwner      `json:"children,omitempty"`
	FreeBytes    uint64            `json:"free_bytes"`
	TotalBytes   uint64            `json:"total_bytes"`
	Errors       []string          `json:"errors,omitempty"` // ≤ 20, clipped to 200 runes each
	Changed      int64             `json:"changed"`          // apply / restore
	ToRestore    int64             `json:"to_restore"`       // restore --dry-run: entries a restore would rewrite
	Created      int64             `json:"created"`          // apply --mkdir
	Elapsed      time.Duration     `json:"elapsed"`
}

const (
	maxErrors    = 20
	maxErrRunes  = 200
	maxPathRunes = 200
	maxOwners    = 10
	maxChildren  = 200
)

func (r *Report) errorf(format string, args ...any) {
	if len(r.Errors) < maxErrors {
		r.Errors = append(r.Errors, clip(fmt.Sprintf(format, args...), maxErrRunes))
	}
}

// clip shortens s to n runes.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// Refused is an error that ended a run before anything changed (exit 2).
type Refused struct{ Msg string }

func (e *Refused) Error() string { return e.Msg }

func refuse(format string, args ...any) error { return &Refused{Msg: fmt.Sprintf(format, args...)} }

// IsRefused reports whether err is a refusal: nothing was changed.
func IsRefused(err error) bool {
	var r *Refused
	return errors.As(err, &r)
}

// Unsupported filesystems: the Hub refuses folders on them, and apply and
// restore refuse to run there.
var Unsupported = map[string]bool{"nfs": true, "cifs": true, "fuse": true, "overlay": true, "tmpfs": true,
	"9p": true, "ceph": true, "ramfs": true, "ecryptfs": true,
	// virtiofs reports FUSE's magic (statfs says "fuse"); named for the
	// Hub's refusal list all the same.
	"virtiofs": true}

// FSName maps a statfs f_type magic to a name.
func FSName(magic int64) string {
	switch uint32(magic) {
	case 0xEF53:
		return "ext4"
	case 0x58465342:
		return "xfs"
	case 0x9123683E:
		return "btrfs"
	case 0x2FC12FC1:
		return "zfs"
	case 0x6969:
		return "nfs"
	case 0xFF534D42, 0xFE534D42, 0x517B: // CIFS, SMB2, SMB
		return "cifs"
	case 0x65735546:
		return "fuse"
	case 0x794C7630:
		return "overlay"
	case 0x01021994:
		return "tmpfs"
	case 0x01021997:
		return "9p"
	case 0x00C36400:
		return "ceph"
	case 0x858458F6:
		return "ramfs"
	case 0xF15F:
		return "ecryptfs"
	}
	return "other"
}

// Scan walks the folder and reports what it found; with a Target, also how
// far it is from it and what an apply would do. It changes nothing.
func Scan(o Options) (*Report, error) {
	w, err := openWalker(o, "scan")
	if err != nil {
		return w.report(), err
	}
	defer w.close()
	w.run(w.tally)
	r := w.finish()
	// R55: entries that couldn't be read make the scan a failure (exit 1;
	// the report still says which): its counts and conformance are
	// incomplete.
	if r.Failed.N > 0 {
		return r, fmt.Errorf("%d entries couldn't be read", r.Failed.N)
	}
	return r, nil
}

// writableFS: the only filesystems apply and restore write to (M6): an
// allowlist, so vfat, exfat, ntfs3 and the rest ("other") are refused too.
var writableFS = map[string]bool{"ext4": true, "xfs": true, "btrfs": true, "zfs": true}
