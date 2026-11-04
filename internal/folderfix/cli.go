package folderfix

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
)

// ArgsExtra holds the flags of one mode beyond Options.
type ArgsExtra struct {
	Expect int64    // apply
	Out    string   // snapshot: the directory snapshot.ndjson.gz is written to
	In     string   // restore, undo snapshot: the apply snapshot
	Kind   string   // snapshot: "apply" (default) | "undo"
	Rel    string   // probe
	Create bool     // probe
	Subs   []string // probe: subpaths below Rel, probed in the same run (H1)
	DryRun bool     // restore: count, write nothing (R56)
}

var digestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SnapshotName is the file snapshot writes in --out and restore reads.
const SnapshotName = "snapshot.ndjson.gz"

var modeFlags = map[string][]string{
	"probe":    {"root", "rel", "create", "sub"},
	"scan":     {"root", "expect-dev", "expect-ino", "expect-mount-root", "gid", "files", "owner", "principal", "children", "max-entries", "max-time"},
	"snapshot": {"root", "expect-dev", "expect-ino", "expect-mount-root", "gid", "files", "owner", "out", "kind", "in", "expect-snapshot-root"},
	"apply":    {"root", "expect-dev", "expect-ino", "expect-mount-root", "expect-digest", "gid", "files", "owner", "expect", "mkdir"},
	"restore":  {"root", "expect-dev", "expect-ino", "expect-mount-root", "gid", "in", "dry-run", "expect-snapshot-root"},
}

// Args is the argv (after "hub folderfix") for a run: the only form the Hub
// builds, from a struct, never a shell. Main parses it back.
func Args(mode string, o Options, x ArgsExtra) []string {
	a := []string{mode, "--root=" + o.Root}
	add := func(name, v string) { a = append(a, "--"+name+"="+v) }
	switch mode {
	case "probe":
		add("rel", x.Rel)
		for _, sub := range x.Subs {
			add("sub", sub)
		}
		if x.Create {
			a = append(a, "--create")
		}
		return a
	}
	if o.ExpectDev != 0 || o.ExpectIno != 0 {
		add("expect-dev", strconv.FormatUint(o.ExpectDev, 10))
		add("expect-ino", strconv.FormatUint(o.ExpectIno, 10))
	}
	if o.ExpectMountRoot != "" {
		add("expect-mount-root", o.ExpectMountRoot)
	}
	if o.SnapshotRootDev != 0 || o.SnapshotRootIno != 0 {
		add("expect-snapshot-root", strconv.FormatUint(o.SnapshotRootDev, 10)+":"+strconv.FormatUint(o.SnapshotRootIno, 10))
	}
	if o.Target.GID != 0 {
		add("gid", strconv.Itoa(o.Target.GID))
		if mode != "restore" {
			add("files", o.Target.Files)
		}
	}
	if o.Target.OwnerUID != nil && mode != "restore" {
		add("owner", strconv.Itoa(*o.Target.OwnerUID))
	}
	if mode == "scan" {
		for _, p := range o.Principals {
			add("principal", formatPrincipal(p))
		}
		if o.Children {
			a = append(a, "--children")
		}
	}
	if mode == "scan" {
		if o.MaxEntries > 0 {
			add("max-entries", strconv.FormatInt(o.MaxEntries, 10))
		}
		if o.MaxTime > 0 {
			add("max-time", o.MaxTime.String())
		}
	}
	switch mode {
	case "snapshot":
		add("out", x.Out)
		if x.Kind == "undo" {
			add("kind", "undo")
			add("in", x.In)
		}
	case "apply":
		add("expect", strconv.FormatInt(x.Expect, 10))
		add("expect-digest", o.ExpectDigest)
		for _, m := range o.Target.Mkdir {
			add("mkdir", m)
		}
	case "restore":
		add("in", x.In)
		if x.DryRun {
			a = append(a, "--dry-run")
		}
	}
	return a
}

func formatPrincipal(p Principal) string {
	g := make([]string, len(p.GIDs))
	for i, id := range p.GIDs {
		g[i] = strconv.Itoa(id)
	}
	s := p.Name + ":" + strconv.Itoa(p.UID) + ":" + strings.Join(g, ",")
	if p.Write {
		s += ":w"
	}
	return s
}

func parsePrincipal(s string) (Principal, error) {
	f := strings.Split(s, ":")
	if len(f) < 3 || len(f) > 4 || (len(f) == 4 && f[3] != "w") {
		return Principal{}, fmt.Errorf("principal %q: want name:uid:gid[,gid…][:w]", clip(s, 80))
	}
	p := Principal{Name: f[0], Write: len(f) == 4}
	if p.Name == "" || len(p.Name) > 64 || strings.ContainsFunc(p.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return Principal{}, fmt.Errorf("principal %q: bad name", clip(s, 80))
	}
	var err error
	if p.UID, err = parseID(f[1]); err != nil {
		return Principal{}, fmt.Errorf("principal %q: uid: %v", clip(s, 80), err)
	}
	for _, g := range strings.Split(f[2], ",") {
		id, err := parseID(g)
		if err != nil {
			return Principal{}, fmt.Errorf("principal %q: gid: %v", clip(s, 80), err)
		}
		p.GIDs = append(p.GIDs, id)
	}
	return p, nil
}

func parseID(s string) (int, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v >= 0xFFFFFFFF {
		return 0, fmt.Errorf("%q is not an id", clip(s, 20))
	}
	return int(v), nil
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cleanAbs(name, p string) error {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		return fmt.Errorf("--%s %q: want an absolute, clean path", name, clip(p, 80))
	}
	return nil
}

// parseArgs parses Main's argv: the mode, then only that mode's flags.
func parseArgs(args []string) (string, Options, ArgsExtra, error) {
	var o Options
	var x ArgsExtra
	if len(args) == 0 {
		return "", o, x, errors.New("usage: folderfix probe|scan|snapshot|apply|restore --root=… [flags]")
	}
	mode := args[0]
	allowed, ok := modeFlags[mode]
	if !ok {
		return "", o, x, fmt.Errorf("unknown mode %q", clip(mode, 40))
	}
	fs := flag.NewFlagSet("folderfix "+mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "", "")
	rel := fs.String("rel", "", "")
	create := fs.Bool("create", false, "")
	dev := fs.Uint64("expect-dev", 0, "")
	ino := fs.Uint64("expect-ino", 0, "")
	mroot := fs.String("expect-mount-root", "", "")
	gid := fs.String("gid", "", "")
	files := fs.String("files", "", "")
	owner := fs.String("owner", "", "")
	var principals, mkdirs, subs listFlag
	fs.Var(&subs, "sub", "")
	fs.Var(&principals, "principal", "")
	children := fs.Bool("children", false, "")
	maxEntries := fs.Int64("max-entries", 0, "")
	maxTime := fs.Duration("max-time", 0, "")
	out := fs.String("out", "", "")
	in := fs.String("in", "", "")
	kind := fs.String("kind", "apply", "")
	dryRun := fs.Bool("dry-run", false, "")
	expect := fs.Int64("expect", -1, "")
	digest := fs.String("expect-digest", "", "")
	snapRoot := fs.String("expect-snapshot-root", "", "")
	fs.Var(&mkdirs, "mkdir", "")
	if err := fs.Parse(args[1:]); err != nil {
		return "", o, x, err
	}
	if fs.NArg() > 0 {
		return "", o, x, fmt.Errorf("unexpected argument %q", clip(fs.Arg(0), 40))
	}
	var bad error
	fs.Visit(func(f *flag.Flag) {
		if bad == nil && !slices.Contains(allowed, f.Name) {
			bad = fmt.Errorf("--%s is not a flag of %s", f.Name, mode)
		}
	})
	if bad != nil {
		return "", o, x, bad
	}
	if err := cleanAbs("root", *root); err != nil {
		return "", o, x, err
	}
	o.Root = *root
	if mode == "probe" {
		if err := validSubpath(*rel); err != nil {
			return "", o, x, err
		}
		if len(subs) > 0 && *create {
			return "", o, x, errors.New("--sub doesn't go with --create")
		}
		for _, sub := range subs {
			if err := validSubpath(sub); err != nil {
				return "", o, x, fmt.Errorf("--sub: %v", err)
			}
		}
		x.Rel, x.Create = *rel, *create
		if len(subs) > 0 {
			x.Subs = []string(subs)
		}
		return mode, o, x, nil
	}
	if (*dev == 0) != (*ino == 0) {
		return "", o, x, errors.New("--expect-dev and --expect-ino go together")
	}
	o.ExpectDev, o.ExpectIno, o.ExpectMountRoot = *dev, *ino, *mroot
	if *snapRoot != "" {
		ds, is, ok := strings.Cut(*snapRoot, ":")
		d, err1 := strconv.ParseUint(ds, 10, 64)
		i, err2 := strconv.ParseUint(is, 10, 64)
		if !ok || err1 != nil || err2 != nil || d == 0 || i == 0 {
			return "", o, x, fmt.Errorf("--expect-snapshot-root %q: want <dev>:<ino>", clip(*snapRoot, 40))
		}
		o.SnapshotRootDev, o.SnapshotRootIno = d, i
	}
	if *mroot != "" && !strings.HasPrefix(*mroot, "/") {
		return "", o, x, errors.New("--expect-mount-root: want an absolute path")
	}
	if *gid != "" {
		g, err := parseID(*gid)
		if err != nil || g == 0 {
			return "", o, x, fmt.Errorf("--gid %q: want a gid above 0", clip(*gid, 20))
		}
		o.Target.GID = g
	}
	if mode != "restore" {
		if (*files != "") != (o.Target.GID != 0) {
			return "", o, x, errors.New("--gid and --files go together")
		}
		if *files != "" && *files != "rw" && *files != "r" {
			return "", o, x, fmt.Errorf("--files %q: want rw or r", clip(*files, 20))
		}
		o.Target.Files = *files
	}
	if *owner != "" {
		u, err := parseID(*owner)
		if err != nil || o.Target.GID == 0 {
			return "", o, x, fmt.Errorf("--owner %q: want a uid, with --gid", clip(*owner, 20))
		}
		o.Target.OwnerUID = &u
	}
	for _, s := range principals {
		p, err := parsePrincipal(s)
		if err != nil {
			return "", o, x, err
		}
		o.Principals = append(o.Principals, p)
	}
	o.Children = *children
	if *maxEntries < 0 || *maxTime < 0 {
		return "", o, x, errors.New("--max-entries and --max-time can't be negative")
	}
	o.MaxEntries, o.MaxTime = *maxEntries, *maxTime
	switch mode {
	case "snapshot":
		if o.Target.GID == 0 {
			return "", o, x, errors.New("snapshot needs --gid and --files")
		}
		if err := cleanAbs("out", *out); err != nil {
			return "", o, x, err
		}
		x.Out, x.Kind = *out, *kind
		switch *kind {
		case "apply":
			if *in != "" || o.SnapshotRootDev != 0 {
				return "", o, x, errors.New("--in and --expect-snapshot-root go with --kind=undo")
			}
		case "undo":
			if err := cleanAbs("in", *in); err != nil {
				return "", o, x, err
			}
			x.In = *in
		default:
			return "", o, x, fmt.Errorf("--kind %q: want apply or undo", clip(*kind, 20))
		}
	case "apply":
		if o.Target.GID == 0 || *expect < 0 || o.ExpectDev == 0 || o.ExpectMountRoot == "" || !digestRe.MatchString(*digest) {
			return "", o, x, errors.New("apply needs --gid, --files, --expect-dev, --expect-ino, --expect-mount-root, --expect and --expect-digest (64 hex)")
		}
		o.ExpectDigest = *digest
		x.Expect = *expect
		for _, m := range mkdirs {
			if err := validSubpath(m); err != nil {
				return "", o, x, fmt.Errorf("--mkdir: %v", err)
			}
		}
		o.Target.Mkdir = mkdirs
	case "restore":
		if o.Target.GID == 0 || o.ExpectDev == 0 || o.ExpectMountRoot == "" {
			return "", o, x, errors.New("restore needs --gid, --expect-dev, --expect-ino and --expect-mount-root")
		}
		if err := cleanAbs("in", *in); err != nil {
			return "", o, x, err
		}
		x.In, x.DryRun = *in, *dryRun
	}
	return mode, o, x, nil
}

// maxReport: above this the samples are dropped (the Hub reads ≤ 256 KiB).
const maxReport = 200 << 10

// Main is `hub folderfix <mode> <flags>…`: one JSON report line on stdout.
// Exit 0 = done, 2 = refused (nothing changed; the report's first error
// says why), 1 = failed or bad arguments (no report for those). stderr only
// for crashes and argument errors.
func Main(args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintf(stderr, "folderfix: panic: %v\n%s", p, debug.Stack())
			code = 1 // never 2: a crash is no refusal
		}
	}()
	mode, o, x, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "folderfix: %v\n", err)
		return 1
	}
	var rep any
	var r *Report
	switch mode {
	case "probe":
		var p *ProbeReport
		if len(x.Subs) > 0 {
			p, err = ProbeSubs(o.Root, x.Rel, x.Subs)
		} else {
			p, err = Probe(o.Root, x.Rel, x.Create)
		}
		if err != nil {
			p.Errors = append([]string{clip(err.Error(), maxErrRunes)}, p.Errors...)
		}
		rep = p
	case "scan":
		r, err = Scan(o)
	case "snapshot":
		r, err = runSnapshot(o, x)
	case "apply":
		r, err = Apply(o, x.Expect)
	case "restore":
		if x.DryRun {
			r, err = runFile(x.In, func(f *os.File) (*Report, error) { return RestoreDryRun(o, f) })
		} else {
			r, err = runFile(x.In, func(f *os.File) (*Report, error) { return Restore(o, f) })
		}
	}
	if r != nil {
		if err != nil {
			r.Errors = append([]string{clip(err.Error(), maxErrRunes)}, r.Errors...)
			if len(r.Errors) > maxErrors {
				r.Errors = r.Errors[:maxErrors]
			}
		}
		rep = r
	}
	b, merr := json.Marshal(rep)
	if merr == nil && len(b) > maxReport && r != nil {
		dropSamples(r)
		r.Errors = append(r.Errors[:min(len(r.Errors), maxErrors-1)], "report too large: path samples dropped")
		b, merr = json.Marshal(r)
	}
	if merr != nil {
		fmt.Fprintf(stderr, "folderfix: report: %v\n", merr)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", b)
	switch {
	case err == nil:
		return 0
	case IsRefused(err):
		return 2
	}
	return 1
}

func runFile(name string, f func(*os.File) (*Report, error)) (*Report, error) {
	in, err := os.OpenFile(name, os.O_RDONLY|syscallNoFollow, 0)
	if err != nil {
		return &Report{Version: 1, Mode: "restore"}, err
	}
	defer in.Close()
	return f(in)
}

func runSnapshot(o Options, x ArgsExtra) (*Report, error) {
	name := path.Join(x.Out, SnapshotName)
	out, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscallNoFollow, 0o600)
	if err != nil {
		return &Report{Version: 1, Mode: "snapshot", Root: o.Root}, err
	}
	var r *Report
	if x.Kind == "undo" {
		r, err = runFile(x.In, func(in *os.File) (*Report, error) { return WriteUndoSnapshot(o, in, out) })
	} else {
		r, err = WriteSnapshot(o, out)
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return r, err
}

// DropSamples clears every Count's sample paths (the Hub's size-bounded
// scan cache).
func (r *Report) DropSamples() { dropSamples(r) }

func dropSamples(r *Report) {
	cs := []*Count{&r.HardLinks, &r.MountPoints, &r.Specials, &r.Symlinks, &r.SetID, &r.Races, &r.BadACL, &r.Failed, &r.ChangedSince,
		&r.Skipped.PathTooLong, &r.Skipped.ACLTooLarge, &r.Skipped.FileCaps}
	if e := r.Expected; e != nil {
		cs = append(cs, &e.Group, &e.Setgid, &e.DefaultACL, &e.Mode, &e.Owner)
	}
	if p := r.Plan; p != nil {
		cs = append(cs, &p.ChangeGroup, &p.AddSetgid, &p.AddDefaultACL, &p.ChangeOwner, &p.Narrowed, &p.LoseAccess)
	}
	for i := range r.Principals {
		cs = append(cs, &r.Principals[i].CantRead, &r.Principals[i].CantWrite)
	}
	for _, c := range cs {
		c.Sample = nil
	}
}
