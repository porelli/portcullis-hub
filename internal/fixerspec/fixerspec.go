// Package fixerspec is the shared-folder fixer helper's spec builder
// (contract §6, §14.2–14.4), shared by the Hub and the worker agent: the
// agent rebuilds every folder_fix spec it is sent with this builder and
// runs it only when the two are byte for byte the same (contract §17.4).
package fixerspec

import (
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/settings"
)

const (
	// Folder / BindRoot: where the folder (or, for a probe, its
	// bind root) is bound in the helper.
	Folder   = "/folder"
	BindRoot = "/broot"
	In       = "/in"
	Out      = "/out"
	Pids     = 16
	Memory   = 256 << 20
	// UsageRoot: where a usage run mounts its volume or bind (never an
	// image path: the Podman domains_data lesson).
	UsageRoot = "/vol"
)

// Env keeps the Go runtime inside the helper's limits: pids 16 counts
// threads, and GC workers on idle Ps could otherwise start one per CPU on a
// large host; the soft memory limit makes the GC work before the 256 MiB
// cgroup limit kills the run.
var Env = []string{"GOMAXPROCS=2", "GOMEMLIMIT=200MiB"}

// The capabilities by mode (contract §6), each the measured minimum
// (fixer_docker_test.go TestDockerFixerCapsMinimal):
//   - DAC_READ_SEARCH (every mode): read and search entries the fixer, uid 0
//     without DAC_OVERRIDE, doesn't own (a 0750 directory of uid 1000);
//   - CHOWN (apply, restore): fchown to the folder gid / must_own uid;
//   - FOWNER (apply, restore): fchmod and the posix_acl xattrs of entries
//     uid 0 doesn't own (inode_owner_or_capable);
//   - FSETID (apply, restore): uid 0 isn't in the folder gid, so without it
//     the kernel drops setgid when it sets a directory's mode or access ACL;
//   - DAC_OVERRIDE (apply --mkdir only): mkdirat in a directory uid 0 has no
//     write bit on. Every other change goes through an fd, so no write
//     permission is checked.
//
// SETFCAP is never needed: it guards security.capability only, which the
// fixer never writes.
var (
	ReadCaps  = []string{"DAC_READ_SEARCH"}
	WriteCaps = []string{"CHOWN", "FOWNER", "FSETID", "DAC_READ_SEARCH"}
	MkdirCaps = []string{"CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE", "DAC_READ_SEARCH"}
	// childfix (F33): fchown and fchmod of one directory through its fd.
	ChildCaps = []string{"CHOWN", "FOWNER"}
)

var DigestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Run is one helper run.
type Run struct {
	Mode string // probe | scan | snapshot | apply | restore | childfix | usage
	// Folder is the folder id (label "folder:<id>"); "" = a path check or
	// a scan of a hand-typed path (label "path-check").
	Folder string
	// Source is the host path bound at /folder; for a probe, the bind
	// root, bound at /broot. The caller has validated it (folder path
	// rules); runFixer only refuses what is malformed.
	Source string
	// Volume: usage only, a named volume mounted read-only at /vol in
	// place of Source (exactly one of the two). A worker's agent never
	// runs a usage helper (its label is refused).
	Volume runtime.VolumeMount
	// Opts and Extra are the fixer's flags, rendered by folderfix.Args
	// (ruling 38). Root and the /in, /out paths are set here.
	Opts  folderfix.Options
	Extra folderfix.ArgsExtra
	// In / InSize: the apply snapshot (restore, undo snapshot), streamed
	// into /in/snapshot.ndjson.gz.
	In     io.Reader
	InSize int64
	// Out receives the snapshot file (snapshot mode) once the run exits 0,
	// after the tar from /out passed the transfer rules. An error from the
	// run after Out returned means the caller must discard what it read.
	Out func(io.Reader) error
	// Timeout: 0 = the mode's default (Timeout).
	Timeout time.Duration
	// Unchecked: a folder scan that learns the folder's identity (create,
	// path change, check path, re-check): the probe's dev/ino just before
	// are still required, the mount root isn't known yet (H5). Every other
	// folder scan and every snapshot checks dev, ino and mount root.
	Unchecked bool
	// Server is the server whose engine runs it ("" = the primary; a
	// worker's agent rebuilds the spec on its own image). The Hub's only.
	Server string
}

func Timeout(r Run) time.Duration {
	switch {
	case r.Timeout > 0:
		return r.Timeout
	case r.Mode == "probe", r.Mode == "childfix":
		return 2 * time.Minute
	case r.Mode == "usage":
		return r.Opts.MaxTime + 30*time.Second
	case r.Mode == "scan" && r.Opts.MaxTime > 0:
		return r.Opts.MaxTime + 2*time.Minute
	case r.Mode == "scan":
		return 30 * time.Minute
	}
	// snapshot / apply / restore take no cap (a plan once accepted is
	// applied whole); this only ends a hung run.
	return 12 * time.Hour
}

// Validate refuses runs the fixer must never get (T4 carries): a missing
// root check on a write, caps on a non-scan, a mode without its transfer.
func (r Run) Validate() error {
	o := r.Opts
	if r.Mode == "usage" {
		return r.validateUsage()
	}
	if r.Volume != (runtime.VolumeMount{}) {
		return errors.New("a named volume is for the usage mode only")
	}
	if r.Folder != "" && !settings.FolderIDRe.MatchString(r.Folder) {
		return fmt.Errorf("folder id %q", r.Folder)
	}
	if !strings.HasPrefix(r.Source, "/") || path.Clean(r.Source) != r.Source || r.Source == "/" ||
		strings.ContainsFunc(r.Source, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return fmt.Errorf("source %q: want an absolute, clean path below /", r.Source)
	}
	if r.Mode != "scan" && (o.MaxEntries != 0 || o.MaxTime != 0) {
		return errors.New("--max-entries / --max-time are for scan only")
	}
	wantIn := r.Mode == "restore" || (r.Mode == "snapshot" && r.Extra.Kind == "undo")
	if (r.In != nil) != wantIn {
		return fmt.Errorf("%s: the snapshot input is required exactly for restore and the undo snapshot", r.Mode)
	}
	if (r.Out != nil) != (r.Mode == "snapshot") {
		return fmt.Errorf("%s: an output is required exactly for snapshot", r.Mode)
	}
	if r.Unchecked && (r.Mode != "scan" || r.Folder == "") {
		return errors.New("only a folder scan learns an identity (unchecked)")
	}
	identity := o.ExpectDev != 0 && o.ExpectIno != 0 && o.ExpectMountRoot != ""
	if (o.SnapshotRootDev != 0 || o.SnapshotRootIno != 0) &&
		(!(r.Mode == "restore" || (r.Mode == "snapshot" && r.Extra.Kind == "undo")) || o.SnapshotRootDev == 0 || o.SnapshotRootIno != o.ExpectIno) {
		return errors.New("an expected snapshot root goes with a restore or an undo snapshot of the same root inode")
	}
	switch r.Mode {
	case "childfix":
		// F33: one per-person tree's child, below the bind root (r.Source,
		// bound at /broot), with the preview probe's identity.
		x := r.Extra
		switch {
		case r.Folder != "":
			return errors.New("childfix is for a per-person tree, never a shared folder")
		case !ValidSub(x.Rel):
			return fmt.Errorf("childfix: tree %q", x.Rel)
		case !ValidSub(x.Child.Name) || strings.Contains(x.Child.Name, "/"):
			return fmt.Errorf("childfix: child %q", x.Child.Name)
		case x.Child.UID <= 0 || x.Child.UID >= 0xFFFFFFFF:
			return fmt.Errorf("childfix: uid %d", x.Child.UID)
		case x.Child.Owner != x.Child.UID:
			return fmt.Errorf("childfix: the child must already be owned by uid %d (owner %d)", x.Child.UID, x.Child.Owner)
		case !identity:
			return errors.New("childfix needs the child's device, inode and mount root")
		case o.Target.GID != 0 || o.Target.OwnerUID != nil || len(o.Target.Mkdir) > 0 || len(o.Principals) > 0 || o.Children || o.ExpectDigest != "" ||
			x.Create || len(x.Subs) > 0 || x.Expect != 0 || x.In != "" || x.Out != "" || x.DryRun:
			return errors.New("childfix takes the tree, the child and its identity only")
		}
	case "probe":
		if r.Extra.Rel == "" {
			return errors.New("probe needs a relative path")
		}
		if len(r.Extra.Subs) > 0 && r.Extra.Create {
			return errors.New("probe: subpaths don't go with create")
		}
		for _, sub := range r.Extra.Subs {
			if !ValidSub(sub) {
				return fmt.Errorf("probe: subpath %q", sub)
			}
		}
	case "scan":
		switch {
		case r.Folder == "":
		case r.Unchecked && (o.ExpectDev == 0 || o.ExpectIno == 0):
			return errors.New("a folder scan learning its identity needs the probe's device and inode")
		case !r.Unchecked && !identity:
			return errors.New("a folder scan needs the folder's device, inode and mount root")
		}
	case "snapshot":
		if o.Target.GID == 0 || r.Folder == "" || !identity {
			return errors.New("snapshot needs a folder, its gid, device, inode and mount root")
		}
	case "apply":
		if r.Folder == "" || o.Target.GID == 0 || o.ExpectDev == 0 || o.ExpectIno == 0 || o.ExpectMountRoot == "" || !DigestRe.MatchString(o.ExpectDigest) {
			return errors.New("apply needs a folder, its gid, device, inode, mount root and the plan digest")
		}
	case "restore":
		if r.Folder == "" || o.Target.GID == 0 || o.ExpectDev == 0 || o.ExpectIno == 0 || o.ExpectMountRoot == "" {
			return errors.New("restore needs a folder, its gid, device, inode and mount root")
		}
	default:
		return fmt.Errorf("unknown fixer mode %q", r.Mode)
	}
	return nil
}

// validateUsage: a usage run measures exactly one volume or one bind,
// read-only, with its caps and nothing else (contract §6).
func (r Run) validateUsage() error {
	o, x := r.Opts, r.Extra
	hasVol := r.Volume != (runtime.VolumeMount{})
	switch {
	case hasVol == (r.Source != ""):
		return errors.New("usage measures exactly one volume or one bind")
	case hasVol && (r.Volume.Name == "" || strings.ContainsAny(r.Volume.Name, "/\x00") || strings.ContainsFunc(r.Volume.Name, func(c rune) bool { return c < 0x20 || c == 0x7f })):
		return fmt.Errorf("usage: volume %q", r.Volume.Name)
	case !hasVol && (!strings.HasPrefix(r.Source, "/") || path.Clean(r.Source) != r.Source || r.Source == "/" ||
		strings.ContainsFunc(r.Source, func(c rune) bool { return c < 0x20 || c == 0x7f })):
		return fmt.Errorf("source %q: want an absolute, clean path below /", r.Source)
	case r.Folder != "" || r.Unchecked || r.In != nil || r.Out != nil || r.Server != "":
		return errors.New("usage takes no folder, transfer, identity check or server")
	case o.MaxEntries <= 0 || o.MaxTime <= 0:
		return errors.New("usage needs --max-entries and --max-time")
	case o.Target.GID != 0 || o.Target.OwnerUID != nil || len(o.Target.Mkdir) > 0 || len(o.Principals) > 0 || o.Children || o.TopOnly ||
		o.ExpectDev != 0 || o.ExpectIno != 0 || o.ExpectMountRoot != "" || o.ExpectDigest != "" || o.SnapshotRootDev != 0 || o.SnapshotRootIno != 0:
		return errors.New("usage takes the caps only")
	case x.Rel != "" || x.Create || len(x.Subs) > 0 || x.Expect != 0 || x.In != "" || x.Out != "" || x.Kind != "" || x.DryRun || x.Child != (folderfix.ChildFix{}):
		return errors.New("usage takes the caps only")
	}
	return nil
}

// usageTargetLabel is a usage run's label target, clipped to 200 runes.
func usageTargetLabel(r Run) string {
	t := r.Source
	if r.Volume.Name != "" {
		t = r.Volume.Name
	}
	if rs := []rune(t); len(rs) > 200 {
		t = string(rs[:200])
	}
	return t
}

// ValidSub: a clean relative path below the bind root or folder.
func ValidSub(sub string) bool {
	return sub != "" && !strings.HasPrefix(sub, "/") && path.Clean(sub) == sub && sub != "." && sub != ".." && !strings.HasPrefix(sub, "../") &&
		!strings.ContainsFunc(sub, func(c rune) bool { return c < 0x20 || c == 0x7f })
}

// Spec builds the helper for r (binary: the fixer binary inside the image, the Hub's or the agent's): image, argv, mounts and caps by mode.
func (r Run) Spec(image, binary string) runtime.FixerSpec {
	o, x := r.Opts, r.Extra
	s := runtime.FixerSpec{
		Image:   image,
		User:    "0:0",
		Env:     slices.Clone(Env),
		CapAdd:  slices.Clone(ReadCaps),
		Label:   "path-check",
		Pids:    Pids,
		Memory:  Memory,
		Timeout: Timeout(r),
	}
	if r.Folder != "" {
		s.Label = "folder:" + r.Folder
	}
	if r.Mode == "usage" {
		// One read-only mount at /vol: a volume (NoCopy) or a bind.
		s.Label = "usage:" + usageTargetLabel(r)
		o.Root = UsageRoot
		if r.Volume.Name != "" {
			s.Volumes = []runtime.VolumeMount{{Name: r.Volume.Name, Target: UsageRoot, Instance: r.Volume.Instance}}
		} else {
			s.Binds = []runtime.BindMount{{Source: r.Source, Target: UsageRoot, ReadOnly: true}}
		}
		s.Cmd = append([]string{binary, "folderfix"}, folderfix.Args(r.Mode, o, x)...)
		return s
	}
	bind := runtime.BindMount{Source: r.Source, Target: Folder, ReadOnly: true}
	o.Root = Folder
	switch r.Mode {
	case "probe":
		bind.Target, o.Root = BindRoot, BindRoot
		// Read-write only to create the missing components (mkdirat as
		// the bind root's owner: no capability beyond DAC_READ_SEARCH).
		bind.ReadOnly = !x.Create
	case "childfix":
		// Read-write: the one directory's owner and mode, through its fd.
		bind.Target, o.Root = BindRoot, BindRoot
		bind.ReadOnly, s.CapAdd = false, slices.Clone(ChildCaps)
	case "snapshot":
		x.Out = Out
		s.Scratch, s.OutPath = []string{Out}, Out
		if x.Kind == "undo" {
			x.In = In + "/" + folderfix.SnapshotName
			s.Scratch = []string{In, Out}
		}
	case "apply":
		bind.ReadOnly, s.CapAdd = false, slices.Clone(WriteCaps)
		if len(o.Target.Mkdir) > 0 {
			s.CapAdd = slices.Clone(MkdirCaps)
		}
	case "restore":
		// --dry-run (R56) only reads: the folder read-only, read caps.
		if !x.DryRun {
			bind.ReadOnly, s.CapAdd = false, slices.Clone(WriteCaps)
		}
		x.In = In + "/" + folderfix.SnapshotName
		s.Scratch = []string{In}
	}
	if r.In != nil {
		s.InPath = In
	}
	s.Binds = []runtime.BindMount{bind}
	s.Cmd = append([]string{binary, "folderfix"}, folderfix.Args(r.Mode, o, x)...)
	return s
}
