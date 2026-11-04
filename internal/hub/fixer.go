package hub

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/settings"
)

// The shared-folder fixer helper (contract §6, §14.2–14.4): the Hub's own
// image, started as root with the capabilities its mode needs and nothing
// else, running `hub folderfix <mode> <flags>…`. The Hub's state lock is
// never held here: every function in this file makes Docker calls.

const (
	// fixerBinary is the Hub binary inside its image (Dockerfile).
	fixerBinary = "/usr/local/bin/hub"
	// fixerFolder / fixerBindRoot: where the folder (or, for a probe, its
	// bind root) is bound in the helper.
	fixerFolder   = "/folder"
	fixerBindRoot = "/broot"
	fixerIn       = "/in"
	fixerOut      = "/out"
	fixerPids     = 16
	fixerMemory   = 256 << 20
)

// fixerEnv keeps the Go runtime inside the helper's limits: pids 16 counts
// threads, and GC workers on idle Ps could otherwise start one per CPU on a
// large host; the soft memory limit makes the GC work before the 256 MiB
// cgroup limit kills the run.
var fixerEnv = []string{"GOMAXPROCS=2", "GOMEMLIMIT=200MiB"}

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
	fixerReadCaps  = []string{"DAC_READ_SEARCH"}
	fixerWriteCaps = []string{"CHOWN", "FOWNER", "FSETID", "DAC_READ_SEARCH"}
	fixerMkdirCaps = []string{"CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE", "DAC_READ_SEARCH"}
	// childfix (F33): fchown and fchmod of one directory through its fd.
	fixerChildCaps = []string{"CHOWN", "FOWNER"}
)

// maxSnapshotBytes caps the snapshot a run copies out (ruling 31; a var for
// tests). The caller checks free space before the run.
var maxSnapshotBytes int64 = 2 << 30

var digestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// fixerRun is one helper run.
type fixerRun struct {
	Mode string // probe | scan | snapshot | apply | restore | childfix
	// Folder is the folder id (label "folder:<id>"); "" = a path check or
	// a scan of a hand-typed path (label "path-check").
	Folder string
	// Source is the host path bound at /folder; for a probe, the bind
	// root, bound at /broot. The caller has validated it (folder path
	// rules); runFixer only refuses what is malformed.
	Source string
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
	// Timeout: 0 = the mode's default (fixerTimeout).
	Timeout time.Duration
	// Unchecked: a folder scan that learns the folder's identity (create,
	// path change, check path, re-check): the probe's dev/ino just before
	// are still required, the mount root isn't known yet (H5). Every other
	// folder scan and every snapshot checks dev, ino and mount root.
	Unchecked bool
}

func fixerTimeout(r fixerRun) time.Duration {
	switch {
	case r.Timeout > 0:
		return r.Timeout
	case r.Mode == "probe", r.Mode == "childfix":
		return 2 * time.Minute
	case r.Mode == "scan" && r.Opts.MaxTime > 0:
		return r.Opts.MaxTime + 2*time.Minute
	case r.Mode == "scan":
		return 30 * time.Minute
	}
	// snapshot / apply / restore take no cap (a plan once accepted is
	// applied whole); this only ends a hung run.
	return 12 * time.Hour
}

// validate refuses runs the fixer must never get (T4 carries): a missing
// root check on a write, caps on a non-scan, a mode without its transfer.
func (r fixerRun) validate() error {
	o := r.Opts
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
		case !validSub(x.Rel):
			return fmt.Errorf("childfix: tree %q", x.Rel)
		case !validSub(x.Child.Name) || strings.Contains(x.Child.Name, "/"):
			return fmt.Errorf("childfix: child %q", x.Child.Name)
		case x.Child.UID <= 0 || x.Child.UID >= 0xFFFFFFFF:
			return fmt.Errorf("childfix: uid %d", x.Child.UID)
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
			if !validSub(sub) {
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
		if r.Folder == "" || o.Target.GID == 0 || o.ExpectDev == 0 || o.ExpectIno == 0 || o.ExpectMountRoot == "" || !digestRe.MatchString(o.ExpectDigest) {
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

// validSub: a clean relative path below the bind root or folder.
func validSub(sub string) bool {
	return sub != "" && !strings.HasPrefix(sub, "/") && path.Clean(sub) == sub && sub != "." && sub != ".." && !strings.HasPrefix(sub, "../") &&
		!strings.ContainsFunc(sub, func(c rune) bool { return c < 0x20 || c == 0x7f })
}

// spec builds the helper for r: image, argv, mounts and caps by mode.
func (r fixerRun) spec(image string) docker.RunSpec {
	o, x := r.Opts, r.Extra
	s := docker.RunSpec{
		Image:   image,
		User:    "0:0",
		Env:     slices.Clone(fixerEnv),
		CapAdd:  slices.Clone(fixerReadCaps),
		Label:   "path-check",
		Pids:    fixerPids,
		Memory:  fixerMemory,
		Timeout: fixerTimeout(r),
	}
	if r.Folder != "" {
		s.Label = "folder:" + r.Folder
	}
	bind := docker.BindMount{Source: r.Source, Target: fixerFolder, ReadOnly: true}
	o.Root = fixerFolder
	switch r.Mode {
	case "probe":
		bind.Target, o.Root = fixerBindRoot, fixerBindRoot
		// Read-write only to create the missing components (mkdirat as
		// the bind root's owner: no capability beyond DAC_READ_SEARCH).
		bind.ReadOnly = !x.Create
	case "childfix":
		// Read-write: the one directory's owner and mode, through its fd.
		bind.Target, o.Root = fixerBindRoot, fixerBindRoot
		bind.ReadOnly, s.CapAdd = false, slices.Clone(fixerChildCaps)
	case "snapshot":
		x.Out = fixerOut
		s.Scratch, s.OutPath = []string{fixerOut}, fixerOut
		if x.Kind == "undo" {
			x.In = fixerIn + "/" + folderfix.SnapshotName
			s.Scratch = []string{fixerIn, fixerOut}
		}
	case "apply":
		bind.ReadOnly, s.CapAdd = false, slices.Clone(fixerWriteCaps)
		if len(o.Target.Mkdir) > 0 {
			s.CapAdd = slices.Clone(fixerMkdirCaps)
		}
	case "restore":
		// --dry-run (R56) only reads: the folder read-only, read caps.
		if !x.DryRun {
			bind.ReadOnly, s.CapAdd = false, slices.Clone(fixerWriteCaps)
		}
		x.In = fixerIn + "/" + folderfix.SnapshotName
		s.Scratch = []string{fixerIn}
	}
	if r.In != nil {
		s.InPath = fixerIn
	}
	s.Binds = []docker.BindMount{bind}
	s.Cmd = append([]string{fixerBinary, "folderfix"}, folderfix.Args(r.Mode, o, x)...)
	return s
}

// runFixer runs one scan, snapshot, apply or restore and returns its
// report. Refusals before any run: no engine or own image (503), a daemon
// that translates ids (userns-remap, rootless: 503, ruling 28). Exit 2
// with a report = 409 carrying the report's first error (the report is
// returned too); exit 2 without one (a Go runtime crash), exit 1 or any
// other code = 500. The report's Races, SetID, … are the caller's to show
// (fixerWarnings).
func (h *Hub) runFixer(ctx context.Context, r fixerRun) (*folderfix.Report, error) {
	if r.Mode == "probe" {
		return nil, statusErr(http.StatusInternalServerError, "shared folder fixer: probes go through runProbe")
	}
	var rep folderfix.Report
	if err := h.execFixer(ctx, r, &rep, func() []string { return rep.Errors }, func() (int, string) { return rep.Version, rep.Mode }); err != nil {
		if rep.Mode == "" {
			return nil, err
		}
		return &rep, err
	}
	return &rep, nil
}

// runProbe runs a probe of r.Extra.Rel below the bind root r.Source.
func (h *Hub) runProbe(ctx context.Context, r fixerRun) (*folderfix.ProbeReport, error) {
	if r.Mode != "probe" {
		return nil, statusErr(http.StatusInternalServerError, "shared folder fixer: runProbe runs probes only")
	}
	var rep folderfix.ProbeReport
	if err := h.execFixer(ctx, r, &rep, func() []string { return rep.Errors }, func() (int, string) { return rep.Version, rep.Mode }); err != nil {
		if rep.Mode == "" {
			return nil, err
		}
		return &rep, err
	}
	return &rep, nil
}

// execFixer runs r and decodes its report into rep. On an error, rep is
// left zero unless a valid report came back.
func (h *Hub) execFixer(ctx context.Context, r fixerRun, rep any, errs func() []string, id func() (int, string)) error {
	if err := r.validate(); err != nil {
		return statusErr(http.StatusInternalServerError, "shared folder fixer: %v", err)
	}
	if h.engine == nil {
		return statusErr(http.StatusServiceUnavailable, "shared folders need the Docker Engine API")
	}
	image, err := h.selfImage(ctx)
	if err != nil {
		return err
	}
	opts, err := h.engine.SecurityOptions(ctx)
	if err != nil {
		return statusErr(http.StatusServiceUnavailable, "shared folders: can't read the Docker daemon's security options: %v", err)
	}
	if m := docker.RemappedIDs(opts); m != "" {
		return statusErr(http.StatusServiceUnavailable, "shared folders can't be fixed: Docker runs with %s, so user and group ids inside the fixer are translated and owners and ACLs would be written for the wrong ids; nothing was changed", m)
	}
	s := r.spec(image)
	if r.In != nil {
		pr, pw := io.Pipe()
		// Closing the reader ends the writer if the run never reads it.
		defer pr.Close()
		go func() { pw.CloseWithError(writeInTar(pw, r.In, r.InSize)) }()
		s.In = pr
	}
	var out func(io.Reader) error
	if r.Out != nil {
		out = func(t io.Reader) error { return readSnapshotTar(t, r.Out) }
	}
	res, err := h.engine.RunHelper(ctx, s, out)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			return err
		}
		return statusErr(http.StatusInternalServerError, "shared folder fixer (%s): %v", r.Mode, err)
	}
	line := lastLine(res.Stdout)
	decErr := decodeStrict(line, rep)
	if decErr == nil {
		if v, m := id(); v != 1 || m != r.Mode {
			decErr = fmt.Errorf("version %d mode %q, want 1 %q", v, m, r.Mode)
		}
	}
	if decErr != nil {
		// Leave rep zero: the caller sees no report.
		zero(rep)
	}
	first := func() string {
		if e := errs(); len(e) > 0 {
			return e[0]
		}
		return ""
	}
	switch {
	case res.ExitCode == 0 && decErr == nil:
		return nil
	case res.ExitCode == 0:
		return statusErr(http.StatusInternalServerError, "shared folder fixer (%s): unreadable report: %v", r.Mode, decErr)
	case res.ExitCode == 2 && decErr == nil:
		msg := first()
		if msg == "" {
			msg = "refused, nothing changed"
		}
		return statusErr(http.StatusConflict, "%s", msg)
	case (res.ExitCode == 1 || res.ExitCode == 2) && decErr == nil && first() != "":
		return statusErr(http.StatusInternalServerError, "shared folder fixer (%s) failed: %s", r.Mode, first())
	}
	why := firstLine(res.Stderr)
	switch {
	case res.ExitCode == 2:
		// A Go runtime fatal error exits 2 without a report: a crash,
		// never a refusal (T4 carry).
		return statusErr(http.StatusInternalServerError, "shared folder fixer (%s) crashed without a report: %s", r.Mode, why)
	case res.ExitCode == 1:
		return statusErr(http.StatusInternalServerError, "shared folder fixer (%s) failed: %s", r.Mode, why)
	case res.ExitCode == 137:
		return statusErr(http.StatusInternalServerError, "shared folder fixer (%s) was killed (exit 137: out of memory?) %s", r.Mode, why)
	}
	return statusErr(http.StatusInternalServerError, "shared folder fixer (%s) exited %d: %s", r.Mode, res.ExitCode, why)
}

func zero(v any) {
	switch p := v.(type) {
	case *folderfix.Report:
		*p = folderfix.Report{}
	case *folderfix.ProbeReport:
		*p = folderfix.ProbeReport{}
	}
}

// lastLine is the last non-empty line of b.
func lastLine(b []byte) []byte {
	b = bytes.TrimRight(b, "\r\n\t ")
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	return bytes.TrimSpace(b)
}

// firstLine is stderr's first non-empty line, clipped, printable only.
func firstLine(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f || r == utf8.RuneError {
				return -1
			}
			return r
		}, l))
		if l != "" {
			if r := []rune(l); len(r) > 200 {
				l = string(r[:199]) + "…"
			}
			return l
		}
	}
	return "no output"
}

// decodeStrict decodes exactly one JSON document with no unknown fields.
func decodeStrict(line []byte, v any) error {
	if len(line) == 0 {
		return errors.New("no report line")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the report")
	}
	return nil
}

// writeInTar writes the tar the helper's /in receives: exactly one
// root-owned 0600 file, the snapshot.
func writeInTar(w io.Writer, in io.Reader, size int64) error {
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: folderfix.SnapshotName, Typeflag: tar.TypeReg, Mode: 0o600, Size: size,
		ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
		return err
	}
	if n, err := io.Copy(tw, io.LimitReader(in, size)); err != nil {
		return err
	} else if n != size {
		return fmt.Errorf("snapshot input: %d of %d bytes", n, size)
	}
	return tw.Close()
}

// readSnapshotTar checks the archive endpoint's tar of /out: the directory
// entry "out/" and exactly one regular file "out/snapshot.ndjson.gz" of at
// most maxSnapshotBytes, which goes to out; anything else fails the run
// (ruling 31).
func readSnapshotTar(t io.Reader, out func(io.Reader) error) error {
	tr := tar.NewReader(t)
	want := strings.TrimPrefix(fixerOut, "/") + "/" + folderfix.SnapshotName
	seen := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("snapshot transfer: %w", err)
		}
		name := hdr.Name
		switch {
		case hdr.Typeflag == tar.TypeDir && strings.TrimSuffix(name, "/") == strings.TrimPrefix(fixerOut, "/"):
			continue
		case hdr.Typeflag == tar.TypeReg && name == want && !seen:
			if hdr.Size > maxSnapshotBytes {
				return fmt.Errorf("snapshot transfer: the snapshot is too large (%d bytes, at most %d)", hdr.Size, maxSnapshotBytes)
			}
			seen = true
			if err := out(io.LimitReader(tr, hdr.Size)); err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return fmt.Errorf("snapshot transfer: %w", err)
			}
		default:
			return fmt.Errorf("snapshot transfer: unexpected entry %q (type %c)", clipRunes(name, 80), hdr.Typeflag)
		}
	}
	if !seen {
		return errors.New("snapshot transfer: the fixer wrote no snapshot")
	}
	return nil
}

// fixerWarnings are what the admin must see from a successful run: the
// entries the fixer left alone because they changed while it ran (races,
// T4 carry: an apply exits 0 with them).
func fixerWarnings(rep *folderfix.Report) []string {
	if rep == nil || rep.Races.N == 0 {
		return nil
	}
	w := fmt.Sprintf("%d entries changed while the fixer ran and were left alone", rep.Races.N)
	if len(rep.Races.Sample) > 0 {
		w += ": " + strings.Join(rep.Races.Sample, ", ")
	}
	return []string{w + " (run the doctor's disk check again)"}
}

// coreProject / hubService: the compose labels the Hub's own container
// carries (core's docker-compose.yml: `name: portcullis`, service `hub`).
const (
	coreProject = "portcullis"
	hubService  = "hub"
)

// selfMountRe matches the root field of the hostname / hosts / resolv.conf
// bind mounts Docker gives every container:
// …/docker/containers/<64 hex>/<file>.
var selfMountRe = regexp.MustCompile(`(?:^|/)docker/containers/([0-9a-f]{64})/(hostname|hosts|resolv\.conf)$`)

// selfContainerID is the Hub's own container ID from /proc/self/mountinfo
// (R53): the root of the /etc/hostname, /etc/hosts or /etc/resolv.conf mount.
// Every such mount must name the same 64-hex ID; none, or two IDs, is an
// error. Never a name or prefix lookup another container could shadow.
func selfContainerID(mountinfo []byte) (string, error) {
	id := ""
	for _, line := range strings.Split(string(mountinfo), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		root, point := f[3], f[4]
		if point != "/etc/hostname" && point != "/etc/hosts" && point != "/etc/resolv.conf" {
			continue
		}
		m := selfMountRe.FindStringSubmatch(root)
		if m == nil || "/etc/"+m[2] != point {
			continue
		}
		if id != "" && id != m[1] {
			return "", errors.New("mountinfo names two containers")
		}
		id = m[1]
	}
	if id == "" {
		return "", errors.New("no docker/containers/<id>/ mount in /proc/self/mountinfo")
	}
	return id, nil
}

// selfImage is the image the fixer runs: Config.FixerImage (development,
// HUB_FIXER_IMAGE with HUB_DEV=1; pulled if missing), else the image ID of
// the Hub's own container (R53): its full ID from mountinfo
// (selfContainerID), inspected by that ID, which must come back equal and
// carry the labels com.docker.compose.project=portcullis and
// com.docker.compose.service=hub. Any failure is a 503 with no fallback
// (no hostname lookup), retried on the next run; cached once found.
func (h *Hub) selfImage(ctx context.Context) (string, error) {
	h.fixerMu.Lock()
	defer h.fixerMu.Unlock()
	if h.fixerImage != "" {
		return h.fixerImage, nil
	}
	fail := func(format string, args ...any) (string, error) {
		return "", statusErr(http.StatusServiceUnavailable, "the Hub can't find its own image: "+format, args...)
	}
	if ref := h.cfg.FixerImage; ref != "" {
		if err := h.engine.EnsureImage(ctx, ref); err != nil {
			return fail("%v", err)
		}
		h.fixerImage = ref
		return ref, nil
	}
	mi, err := h.mountinfo()
	if err != nil {
		return fail("reading mountinfo: %v", err)
	}
	id, err := selfContainerID(mi)
	if err != nil {
		return fail("%v", err)
	}
	ci, err := h.engine.InspectContainer(ctx, id)
	if err != nil {
		return fail("inspecting container %s: %v", id[:12], err)
	}
	if ci.ID != id {
		return fail("inspecting %s answered container %q", id[:12], ci.ID)
	}
	if ci.Labels[docker.LabelProject] != coreProject || ci.Labels[docker.LabelService] != hubService {
		return fail("container %s is not core's hub service (project %q, service %q)", id[:12], ci.Labels[docker.LabelProject], ci.Labels[docker.LabelService])
	}
	if !docker.PinnedImage(ci.Image) || !strings.HasPrefix(ci.Image, "sha256:") {
		return fail("container %s reports image %q, not an image ID", id[:12], ci.Image)
	}
	h.fixerImage = ci.Image
	return ci.Image, nil
}
