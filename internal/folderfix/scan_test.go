//go:build unix

package folderfix

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// writeFile creates a file with exactly mode (umask ignored).
func writeFile(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// countTree: root + 2 dirs (3), 4 files + a hard link to one (5 names), a
// symlink to an existing directory outside the tree holding 3 files, a FIFO.
func countTree(t *testing.T) (root, outside string) {
	t.Helper()
	root = t.TempDir()
	outside = t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"o1", "o2", "o3"} {
		writeFile(t, filepath.Join(outside, n), 0o644)
	}
	mkdir(t, filepath.Join(root, "a"), 0o755)
	mkdir(t, filepath.Join(root, "b"), 0o755)
	for _, f := range []string{"a/f1", "a/f2", "b/f3", "f4"} {
		writeFile(t, filepath.Join(root, f), 0o644)
	}
	if err := os.Link(filepath.Join(root, "a/f1"), filepath.Join(root, "b/f1-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, outside
}

func TestScanCounts(t *testing.T) {
	root, outside := countTree(t)
	check := func(r *Report) {
		t.Helper()
		if r.Dirs != 3 || r.Files != 5 || r.Entries != 10 {
			t.Errorf("dirs %d files %d entries %d, want 3 5 10", r.Dirs, r.Files, r.Entries)
		}
		if r.HardLinks.N != 2 || r.Symlinks.N != 1 || r.Specials.N != 1 || r.MountPoints.N != 0 {
			t.Errorf("hard links %d symlinks %d specials %d mounts %d, want 2 1 1 0", r.HardLinks.N, r.Symlinks.N, r.Specials.N, r.MountPoints.N)
		}
		if !slices.Equal(r.HardLinks.Sample, []string{"a/f1", "b/f1-link"}) || !slices.Equal(r.Symlinks.Sample, []string{"out"}) ||
			!slices.Equal(r.Specials.Sample, []string{"fifo"}) {
			t.Errorf("samples: %v %v %v", r.HardLinks.Sample, r.Symlinks.Sample, r.Specials.Sample)
		}
		if len(r.Errors) != 0 || r.Failed.N != 0 || r.Races.N != 0 || r.Partial {
			t.Errorf("errors %v failed %d races %d partial %v", r.Errors, r.Failed.N, r.Races.N, r.Partial)
		}
		if r.Expected != nil || r.Plan != nil {
			t.Error("no target: want no conformance or plan")
		}
	}
	r, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	check(r)
	st, _ := os.Stat(root)
	if r.Ino != st.Sys().(*syscall.Stat_t).Ino {
		t.Errorf("ino %d, want the root's", r.Ino)
	}
	if len(r.Owners) != 1 || r.Owners[0].N != 8 || r.Owners[0].UID != os.Getuid() {
		t.Errorf("owners %+v, want one owner of the 8 files and dirs", r.Owners)
	}
	// The symlink's target is never stat'ed: dangling, the same report.
	if err := os.Remove(filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "missing"), filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}
	r, err = Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	check(r)
}

func TestScanCap(t *testing.T) {
	root, _ := countTree(t)
	r, err := Scan(Options{Root: root, MaxEntries: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Partial || r.PartialReason != "entries" || r.Entries != 3 {
		t.Fatalf("partial %v %q entries %d, want true entries 3", r.Partial, r.PartialReason, r.Entries)
	}
	r, err = Scan(Options{Root: root, MaxTime: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Partial || r.PartialReason != "time" {
		t.Fatalf("partial %v %q, want time", r.Partial, r.PartialReason)
	}
}

func TestScanPrincipals(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "secret"), 0o600)
	writeFile(t, filepath.Join(root, "open"), 0o644)
	mkdir(t, filepath.Join(root, "closed"), 0o700)
	writeFile(t, filepath.Join(root, "closed", "inner"), 0o644) // unreachable: its directory can't be traversed
	r, err := Scan(Options{Root: root, Principals: []Principal{{Name: "app", UID: 4242, GIDs: []int{4242}, Write: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Principals) != 1 {
		t.Fatalf("principals %+v", r.Principals)
	}
	p := r.Principals[0]
	if p.Name != "app" || p.UID != 4242 || p.CantRead.N != 3 || !slices.Equal(p.CantRead.Sample, []string{"closed", "closed/inner", "secret"}) {
		t.Errorf("cant read %+v, want closed, closed/inner, secret", p.CantRead)
	}
	if p.CantWrite.N != 5 { // nothing is writable by others
		t.Errorf("cant write %d, want 5", p.CantWrite.N)
	}
}

func TestScanChildren(t *testing.T) {
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "a"), 0o755)
	writeFile(t, filepath.Join(root, "a", "x"), 0o644)
	writeFile(t, filepath.Join(root, "b"), 0o644)
	r, err := Scan(Options{Root: root, Children: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []ChildOwner{{Name: "a", UID: os.Getuid(), GID: r.Children[0].GID, Entries: 2}, {Name: "b", UID: os.Getuid(), GID: r.Children[1].GID, Entries: 1}}
	if !reflect.DeepEqual(r.Children, want) {
		t.Errorf("children %+v, want %+v", r.Children, want)
	}
}

// treeState is every entry's mode, owner and mtime (for "nothing changed").
func treeState(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		out[p] = fi.Mode().String() + " " + strconv.Itoa(int(st.Uid)) + ":" + strconv.Itoa(int(st.Gid)) + " " + fi.ModTime().String()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rootIDs(t *testing.T, p string) (uint64, uint64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return uint64(st.Dev), uint64(st.Ino)
}

// needWritableFS: apply runs only on ext4/xfs/btrfs/zfs (M6); the temp
// dir of a developer Mac isn't one.
func needWritableFS(t *testing.T) {
	t.Helper()
	r, err := Scan(Options{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !writableFS[r.FSType] {
		if runtime.GOOS == "linux" && os.Getenv("CI") != "" {
			t.Fatalf("the CI temp dir is %s", r.FSType)
		}
		t.Skipf("apply refuses %s", r.FSType)
	}
}

func runMain(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Main(args, &out, &errb)
	return code, out.String(), errb.String()
}

func simpleTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	mkdir(t, filepath.Join(root, "d"), 0o755)
	writeFile(t, filepath.Join(root, "d", "f"), 0o644)
	writeFile(t, filepath.Join(root, "g"), 0o644)
	return root
}

func TestApplyRefusesWrongRoot(t *testing.T) {
	root := simpleTree(t)
	dev, _ := rootIDs(t, root)
	_, otherIno := rootIDs(t, t.TempDir())
	before := treeState(t, root)
	code, out, _ := runMain("apply", "--root="+root, "--expect-dev="+strconv.FormatUint(dev, 10), "--expect-ino="+strconv.FormatUint(otherIno, 10),
		"--expect-mount-root=/srv/x", "--expect-digest="+strings.Repeat("0", 64), "--gid=60001", "--files=rw", "--expect=4")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (refused); out %s", code, out)
	}
	var r Report
	if err := json.Unmarshal([]byte(out), &r); err != nil || len(r.Errors) == 0 || !strings.Contains(r.Errors[0], "not the folder's directory") {
		t.Fatalf("report %q: %v", out, err)
	}
	if after := treeState(t, root); !reflect.DeepEqual(before, after) {
		t.Fatalf("changed:\n%v\n%v", before, after)
	}
	// The mount root check: a temp dir isn't a mount point, so any expected
	// mount root is refused.
	_, ino := rootIDs(t, root)
	_, err := Apply(Options{Root: root, ExpectDev: dev, ExpectIno: ino, ExpectMountRoot: "/srv/photos", Target: Target{GID: 60001, Files: "rw"}}, 4)
	if !IsRefused(err) {
		t.Fatalf("mount root: %v, want a refusal", err)
	}
	// Without the expected identity a run that changes is refused.
	if _, err := Apply(Options{Root: root, Target: Target{GID: 60001, Files: "rw"}}, 4); !IsRefused(err) {
		t.Fatalf("no expect-dev: %v, want a refusal", err)
	}
	if after := treeState(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("changed")
	}
}

func TestApplyExpectMismatch(t *testing.T) {
	needWritableFS(t)
	root := simpleTree(t)
	dev, ino := rootIDs(t, root)
	o := Options{Root: root, ExpectDev: dev, ExpectIno: ino, Target: Target{GID: 60001, Files: "rw"}}
	r, err := Scan(o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Plan == nil || r.Plan.Changes != 4 || r.Expected.Group.N != 4 || r.Plan.AddSetgid.N != 2 {
		t.Fatalf("plan %+v expected %+v, want 4 changes (4 group, 2 setgid)", r.Plan, r.Expected)
	}
	before := treeState(t, root)
	if _, err := Apply(o, r.Plan.Changes-1); !IsRefused(err) || !strings.Contains(err.Error(), "changed since the preview") {
		t.Fatalf("err %v, want the count refusal", err)
	}
	o.ExpectDigest = r.Plan.Digest
	if _, err := Apply(o, 3); !IsRefused(err) || !strings.Contains(err.Error(), "expected 3") {
		t.Fatalf("err %v", err)
	}
	if after := treeState(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("changed")
	}
}

func TestApplyRefusesMkdirThroughSymlink(t *testing.T) {
	needWritableFS(t)
	root := simpleTree(t)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, "movies")); err != nil {
		t.Fatal(err)
	}
	dev, ino := rootIDs(t, root)
	o := Options{Root: root, ExpectDev: dev, ExpectIno: ino, Target: Target{GID: 60001, Files: "rw", Mkdir: []string{"movies/hd"}}}
	r, _ := Scan(o)
	before := treeState(t, root)
	if _, err := Apply(o, r.Plan.Changes); !IsRefused(err) || !strings.Contains(err.Error(), "movies is a symlink") {
		t.Fatalf("err %v, want the symlink refusal", err)
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Fatal("created through the symlink")
	}
	if after := treeState(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("changed")
	}
}

func TestCLIArgs(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("ab", 32)
	for _, args := range [][]string{
		nil,
		{"bogus", "--root=" + root},
		{"scan", "--root=relative/path"},
		{"scan", "--root=" + root + "/../x"},
		{"apply", "--root=" + root, "--expect-dev=1", "--expect-ino=2", "--gid=60001", "--files=rw", "--expect=1", "--mkdir=../x"},
		{"apply", "--root=" + root, "--expect-dev=1", "--expect-ino=2", "--gid=60001", "--files=rw", "--expect=1", "--mkdir=a:b"},
		{"apply", "--root=" + root, "--gid=60001", "--files=rw", "--expect=1"}, // no expected identity
		{"scan", "--root=" + root, "--gid=60001"}, // no --files
		{"scan", "--root=" + root, "--mkdir=x"},   // not a scan flag
		{"scan", "--root=" + root, "--principal=a:b:c"},
		{"scan", "--root=" + root, "extra"},
		{"restore", "--root=" + root, "--expect-dev=1", "--expect-ino=2", "--in=/in/s.gz"}, // no --gid
		{"probe", "--root=" + root, "--rel=../etc"},
		// M2: apply and restore need the mount root; M5: apply the digest;
		// M4: no caps on apply or snapshot.
		{"apply", "--root=" + root, "--expect-dev=1", "--expect-ino=2", "--gid=60001", "--files=rw", "--expect=1", "--expect-digest=" + digest},
		{"apply", "--root=" + root, "--expect-dev=1", "--expect-ino=2", "--expect-mount-root=/srv/x", "--gid=60001", "--files=rw", "--expect=1"},
		{"apply", "--root=" + root, "--expect-dev=1", "--expect-ino=2", "--expect-mount-root=/srv/x", "--gid=60001", "--files=rw", "--expect=1", "--expect-digest=" + digest, "--max-time=1m"},
		{"apply", "--root=" + root, "--expect-dev=1", "--expect-ino=2", "--expect-mount-root=/srv/x", "--gid=60001", "--files=rw", "--expect=1", "--expect-digest=xyz"},
		{"snapshot", "--root=" + root, "--gid=60001", "--files=rw", "--out=/out", "--max-entries=5"},
		{"restore", "--root=" + root, "--expect-dev=1", "--expect-ino=2", "--gid=60001", "--in=/in/s.gz"},
	} {
		code, out, _ := runMain(args...)
		if code != 1 || out != "" {
			t.Errorf("%q: exit %d out %q, want 1 and no report", args, code, out)
		}
	}

	// Args round-trips through the parser.
	owner := 2000
	cases := []struct {
		mode string
		o    Options
		x    ArgsExtra
	}{
		{"probe", Options{Root: "/broot"}, ArgsExtra{Rel: "photos/2024", Create: true}},
		{"scan", Options{Root: "/folder", ExpectDev: 64, ExpectIno: 2, ExpectMountRoot: "/srv/pho tos",
			Target:     Target{GID: 60001, Files: "r", OwnerUID: &owner},
			Principals: []Principal{{Name: "immich", UID: 1000, GIDs: []int{1000, 60001}}, {Name: "samba", UID: 0, GIDs: []int{0}, Write: true}},
			Children:   true, MaxEntries: 1000, MaxTime: 30 * time.Second}, ArgsExtra{}},
		{"snapshot", Options{Root: "/folder", ExpectDev: 64, ExpectIno: 2, ExpectMountRoot: "/p", Target: Target{GID: 60001, Files: "rw"}}, ArgsExtra{Out: "/out", Kind: "apply"}},
		{"snapshot", Options{Root: "/folder", ExpectDev: 64, ExpectIno: 2, ExpectMountRoot: "/p", Target: Target{GID: 60001, Files: "rw"}}, ArgsExtra{Out: "/out", Kind: "undo", In: "/in/snapshot.ndjson.gz"}},
		{"apply", Options{Root: "/folder", ExpectDev: 64, ExpectIno: 2, ExpectMountRoot: "/p", ExpectDigest: digest, Target: Target{GID: 60001, Files: "rw", Mkdir: []string{"movies/hd", "tv"}}}, ArgsExtra{Expect: 12}},
		{"restore", Options{Root: "/folder", ExpectDev: 64, ExpectIno: 2, ExpectMountRoot: "/p", Target: Target{GID: 60001}}, ArgsExtra{In: "/in/snapshot.ndjson.gz"}},
		{"restore", Options{Root: "/folder", ExpectDev: 64, ExpectIno: 2, ExpectMountRoot: "/p", Target: Target{GID: 60001}}, ArgsExtra{In: "/in/snapshot.ndjson.gz", DryRun: true}},
	}
	for _, c := range cases {
		args := Args(c.mode, c.o, c.x)
		mode, o, x, err := parseArgs(args)
		if err != nil {
			t.Errorf("%s: %q: %v", c.mode, args, err)
			continue
		}
		if c.mode == "snapshot" && c.x.Kind == "" {
			c.x.Kind = "apply"
		}
		if mode != c.mode || !reflect.DeepEqual(o, c.o) || !reflect.DeepEqual(x, c.x) {
			t.Errorf("%s round trip:\n got %+v %+v\nwant %+v %+v", c.mode, o, x, c.o, c.x)
		}
	}
}

func TestMainScanReport(t *testing.T) {
	root := simpleTree(t)
	code, out, errOut := runMain("scan", "--root="+root, "--gid=60001", "--files=rw")
	if code != 0 || errOut != "" || strings.Count(out, "\n") != 1 {
		t.Fatalf("exit %d stderr %q out %q", code, errOut, out)
	}
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil || r.Mode != "scan" || r.Files != 2 || r.Plan.Changes != 4 {
		t.Fatalf("report %s: %v", out, err)
	}
	for _, k := range []string{`"hard_links":`, `"keep_group":`, `"fs_type":`, `"mount_root":`} {
		if !strings.Contains(out, k) {
			t.Errorf("report lacks %s", k)
		}
	}
}

func TestProbe(t *testing.T) {
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "a"), 0o755)
	mkdir(t, filepath.Join(root, "a", "b"), 0o755)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, "l")); err != nil {
		t.Fatal(err)
	}
	p, err := Probe(root, "a/b", false)
	dev, ino := rootIDs(t, filepath.Join(root, "a", "b"))
	if err != nil || !p.Exists || p.Symlink != "" || p.Dev != dev || p.Ino != ino || p.Created {
		t.Fatalf("a/b: %+v %v", p, err)
	}
	if p, err := Probe(root, "a/missing", false); err != nil || p.Exists || p.Ino != 0 {
		t.Fatalf("missing: %+v %v", p, err)
	}
	if p, err := Probe(root, "l/x", true); err != nil || p.Symlink != "l" || p.Exists || p.Created {
		t.Fatalf("symlink: %+v %v", p, err)
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Fatal("created through the symlink")
	}
	p, err = Probe(root, "a/new/deeper", true)
	if err != nil || !p.Exists || !p.Created {
		t.Fatalf("create: %+v %v", p, err)
	}
	if fi, err := os.Lstat(filepath.Join(root, "a", "new", "deeper")); err != nil || !fi.IsDir() {
		t.Fatalf("not created: %v", err)
	}
	writeFile(t, filepath.Join(root, "file"), 0o644)
	if _, err := Probe(root, "file/x", true); !IsRefused(err) {
		t.Fatalf("through a file: %v, want a refusal", err)
	}
	if _, err := Probe(root, "../x", false); err == nil {
		t.Fatal("../x accepted")
	}
	code, out, _ := runMain("probe", "--root="+root, "--rel=l/x")
	if code != 0 || !strings.Contains(out, `"symlink":"l"`) {
		t.Fatalf("CLI probe: %d %s", code, out)
	}
}

// H1: one probe run checks the folder root and every subpath below it,
// each walked from the root's own fd (no symlink component).
func TestProbeSubs(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a", "a/b", "a/c", "a/c/d"} {
		mkdir(t, filepath.Join(root, d), 0o755)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "a", "l")); err != nil {
		t.Fatal(err)
	}
	p, err := ProbeSubs(root, "a", []string{"b", "c/d", "l/x", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	dev, ino := rootIDs(t, filepath.Join(root, "a"))
	if !p.Exists || p.Dev != dev || p.Ino != ino || p.Symlink != "" || len(p.Subs) != 4 {
		t.Fatalf("root: %+v", p)
	}
	bdev, bino := rootIDs(t, filepath.Join(root, "a", "b"))
	ddev, dino := rootIDs(t, filepath.Join(root, "a", "c", "d"))
	want := []SubProbe{
		{Rel: "b", Exists: true, Dev: bdev, Ino: bino},
		{Rel: "c/d", Exists: true, Dev: ddev, Ino: dino},
		{Rel: "l/x", Symlink: "l"},
		{Rel: "missing"},
	}
	if !reflect.DeepEqual(p.Subs, want) {
		t.Fatalf("subs:\n got %+v\nwant %+v", p.Subs, want)
	}
	// A symlinked root: no subpath is walked.
	if err := os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "s")); err != nil {
		t.Fatal(err)
	}
	if p, err := ProbeSubs(root, "s", []string{"b"}); err != nil || p.Symlink != "s" || p.Exists || len(p.Subs) != 0 {
		t.Fatalf("symlinked root: %+v %v", p, err)
	}
	// Through the CLI; --sub never goes with --create, nor a bad subpath.
	code, out, _ := runMain("probe", "--root="+root, "--rel=a", "--sub=b", "--sub=l/x")
	if code != 0 || !strings.Contains(out, `"subs":[{"rel":"b"`) || !strings.Contains(out, `"symlink":"l"`) {
		t.Fatalf("CLI probe: %d %s", code, out)
	}
	for _, args := range [][]string{
		{"probe", "--root=" + root, "--rel=a", "--sub=b", "--create"},
		{"probe", "--root=" + root, "--rel=a", "--sub=../x"},
	} {
		if code, out, _ := runMain(args...); code != 1 || out != "" {
			t.Errorf("%q: exit %d out %q, want 1", args, code, out)
		}
	}
	args := Args("probe", Options{Root: "/broot"}, ArgsExtra{Rel: "media", Subs: []string{"movies", "tv/hd"}})
	if _, _, x, err := parseArgs(args); err != nil || !reflect.DeepEqual(x.Subs, []string{"movies", "tv/hd"}) || x.Rel != "media" {
		t.Fatalf("round trip %q: %+v %v", args, x, err)
	}
}

func gzLines(t *testing.T, lines ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	for _, l := range lines {
		gz.Write([]byte(l + "\n"))
	}
	gz.Close()
	return b.Bytes()
}

func TestRestoreRefusesBadSnapshots(t *testing.T) {
	root := simpleTree(t)
	dev, ino := rootIDs(t, root)
	_, fino := rootIDs(t, filepath.Join(root, "g"))
	hdr := func(kind string, gid int, rdev, rino uint64, n int) string {
		return `{"version":1,"kind":"` + kind + `","rules":` + strconv.Itoa(planRules) + `,"root_dev":` + strconv.FormatUint(rdev, 10) + `,"root_ino":` + strconv.FormatUint(rino, 10) +
			`,"gid":` + strconv.Itoa(gid) + `,"files":"rw","owner_uid":null,"created_at":"2026-11-03T00:00:00Z","entries":` + strconv.Itoa(n) + `}`
	}
	line := func(p string) string {
		return `{"p":"` + p + `","t":"f","ino":` + strconv.FormatUint(fino, 10) + `,"u":0,"g":0,"m":420,"a":"","d":""}`
	}
	o := Options{Root: root, ExpectDev: dev, ExpectIno: ino, Target: Target{GID: 60001}}
	before := treeState(t, root)
	for name, snap := range map[string][]byte{
		"undo kind":      gzLines(t, hdr("undo", 60001, dev, ino, 1), line("g")),
		"other gid":      gzLines(t, hdr("apply", 60002, dev, ino, 1), line("g")),
		"other root":     gzLines(t, hdr("apply", 60001, dev, ino+1, 1), line("g")),
		"dotdot":         gzLines(t, hdr("apply", 60001, dev, ino, 2), line("g"), line("../g")),
		"absolute":       gzLines(t, hdr("apply", 60001, dev, ino, 2), line("g"), line("/etc/passwd")),
		"unclean":        gzLines(t, hdr("apply", 60001, dev, ino, 2), line("g"), line("d/../g")),
		"count":          gzLines(t, hdr("apply", 60001, dev, ino, 3), line("g")),
		"extra lines":    gzLines(t, hdr("apply", 60001, dev, ino, 1), line("g"), line("g")),
		"unknown field":  gzLines(t, hdr("apply", 60001, dev, ino, 1), strings.Replace(line("g"), `"d":""`, `"d":"","x":1`, 1)),
		"bad acl":        gzLines(t, hdr("apply", 60001, dev, ino, 1), strings.Replace(line("g"), `"a":""`, `"a":"AgAAAA=="`, 1)+``),
		"not gzip":       []byte("{}"),
		"mode type bits": gzLines(t, hdr("apply", 60001, dev, ino, 1), strings.Replace(line("g"), `"m":420`, `"m":33188`, 1)),
		// M10: another rules version
		"rules":    gzLines(t, strings.Replace(hdr("apply", 60001, dev, ino, 1), `"rules":`+strconv.Itoa(planRules), `"rules":`+strconv.Itoa(planRules+1), 1), line("g")),
		"no rules": gzLines(t, strings.Replace(hdr("apply", 60001, dev, ino, 1), `"rules":`+strconv.Itoa(planRules)+`,`, ``, 1), line("g")),
		// R48: pb only for a name that isn't UTF-8, and valid base64 of a clean path
		"pb utf8":   gzLines(t, hdr("apply", 60001, dev, ino, 1), strings.Replace(line("g"), `"d":""`, `"d":"","pb":"Zw=="`, 1)),
		"pb bad":    gzLines(t, hdr("apply", 60001, dev, ino, 1), strings.Replace(line("g"), `"d":""`, `"d":"","pb":"!!"`, 1)),
		"pb dotdot": gzLines(t, hdr("apply", 60001, dev, ino, 1), strings.Replace(line("g"), `"d":""`, `"d":"","pb":"Li4v6Q=="`, 1)),
	} {
		if name == "bad acl" {
			// a header-only ACL is fine; an invalid one (no USER_OBJ) isn't
			snap = gzLines(t, hdr("apply", 60001, dev, ino, 1), strings.Replace(line("g"), `"a":""`, `"a":"AgAAAAQABAD/////"`, 1))
		}
		r, err := Restore(o, bytes.NewReader(snap))
		if !IsRefused(err) || r.Changed != 0 {
			t.Errorf("%s: err %v changed %d, want a refusal", name, err, r.Changed)
		}
	}
	if after := treeState(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("changed")
	}
}

// Follow-up (a): after a device-only re-check the apply snapshot's header
// still names the old device: restore takes it as the expected snapshot
// root (--expect-snapshot-root), the walk root stays checked against the
// current identity, and the inode must be the same.
func TestRestoreExpectSnapshotRoot(t *testing.T) {
	root := simpleTree(t)
	dev, ino := rootIDs(t, root)
	_, fino := rootIDs(t, filepath.Join(root, "g"))
	hdr := `{"version":1,"kind":"apply","rules":` + strconv.Itoa(planRules) + `,"root_dev":` + strconv.FormatUint(dev+7, 10) + `,"root_ino":` + strconv.FormatUint(ino, 10) +
		`,"gid":60001,"files":"rw","owner_uid":null,"created_at":"2026-11-03T00:00:00Z","entries":1}`
	snap := gzLines(t, hdr, `{"p":"g","t":"f","ino":`+strconv.FormatUint(fino, 10)+`,"u":0,"g":0,"m":420,"a":"","d":""}`)
	o := Options{Root: root, ExpectDev: dev, ExpectIno: ino, Target: Target{GID: 60001}}
	if _, err := RestoreDryRun(o, bytes.NewReader(snap)); !IsRefused(err) {
		t.Fatalf("old device without the flag: %v, want a refusal", err)
	}
	o.SnapshotRootDev, o.SnapshotRootIno = dev+7, ino
	if _, err := RestoreDryRun(o, bytes.NewReader(snap)); err != nil {
		t.Fatalf("with the snapshot root: %v", err)
	}
	bad := o
	bad.SnapshotRootIno = ino + 1
	if _, err := RestoreDryRun(bad, bytes.NewReader(snap)); !IsRefused(err) {
		t.Fatalf("another inode: %v, want a refusal", err)
	}
	bad = o
	bad.SnapshotRootDev = dev + 8
	if _, err := RestoreDryRun(bad, bytes.NewReader(snap)); !IsRefused(err) {
		t.Fatalf("another recorded device: %v, want a refusal", err)
	}
	// Through the argv (restore and the undo snapshot).
	for _, mode := range []string{"restore", "snapshot"} {
		x := ArgsExtra{In: "/in/snapshot.ndjson.gz"}
		if mode == "snapshot" {
			x = ArgsExtra{Out: "/out", Kind: "undo", In: "/in/snapshot.ndjson.gz"}
		}
		oo := Options{Root: "/folder", ExpectDev: 64, ExpectIno: 2, ExpectMountRoot: "/p", Target: Target{GID: 60001, Files: "rw"}, SnapshotRootDev: 63, SnapshotRootIno: 2}
		if mode == "restore" {
			oo.Target.Files = ""
		}
		args := Args(mode, oo, x)
		_, got, _, err := parseArgs(args)
		if err != nil || got.SnapshotRootDev != 63 || got.SnapshotRootIno != 2 {
			t.Errorf("%s %q: %+v %v", mode, args, got, err)
		}
	}
	if code, _, _ := runMain("scan", "--root="+root, "--expect-snapshot-root=1:2"); code != 1 {
		t.Error("--expect-snapshot-root accepted on a scan")
	}
}

func TestFSName(t *testing.T) {
	for magic, want := range map[int64]string{0xEF53: "ext4", 0x58465342: "xfs", 0x9123683E: "btrfs", 0x2FC12FC1: "zfs",
		0x6969: "nfs", 0xFF534D42: "cifs", 0xFE534D42: "cifs", int64(int32(-11317950)): "cifs", 0x65735546: "fuse",
		0x794C7630: "overlay", 0x01021994: "tmpfs", 0x01021997: "9p", 0x00C36400: "ceph", 0x858458F6: "ramfs",
		0xF15F: "ecryptfs", 0x1234: "other"} {
		if got := FSName(magic); got != want {
			t.Errorf("%#x: %s, want %s", magic, got, want)
		}
	}
	for name := range writableFS {
		if !slices.Contains([]string{"ext4", "xfs", "btrfs", "zfs"}, name) {
			t.Errorf("writable %s", name)
		}
	}
	if len(writableFS) != 4 || writableFS["other"] {
		t.Errorf("writableFS %v", writableFS)
	}
	for name := range Unsupported {
		if !slices.Contains([]string{"nfs", "cifs", "fuse", "overlay", "tmpfs", "9p", "virtiofs", "ceph", "ramfs", "ecryptfs"}, name) {
			t.Errorf("unexpected %s", name)
		}
	}
	for _, name := range []string{"9p", "virtiofs", "ceph", "ramfs", "ecryptfs"} {
		if !Unsupported[name] {
			t.Errorf("%s is not refused", name)
		}
	}
}

func TestParseMountinfo(t *testing.T) {
	in := `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
95 22 8:1 /srv/photos /folder rw,relatime - ext4 /dev/sda1 rw
96 95 0:50 / /folder/tmp rw - tmpfs tmpfs rw
97 22 8:1 /srv/with\040space /folder rw - ext4 /dev/sda1 rw
`
	ms, err := parseMountinfo(strings.NewReader(in))
	if err != nil || len(ms) != 4 {
		t.Fatalf("%+v %v", ms, err)
	}
	if root, ok := mountRootOf(ms, "/folder"); !ok || root != "/srv/with space" {
		t.Errorf("topmost /folder root %q %v", root, ok)
	}
	if _, ok := mountRootOf(ms, "/other"); ok {
		t.Error("found /other")
	}
	if ms[2].ID != 96 || ms[2].Point != "/folder/tmp" {
		t.Errorf("%+v", ms[2])
	}
}

func TestIdentityMap(t *testing.T) {
	for s, want := range map[string]bool{
		"         0          0 4294967295\n": true,
		"0 100000 65536\n":                   false,
		"0 0 65536\n":                        false,
		"0 0 4294967295\n1 1 1\n":            false,
	} {
		if identityMap(s) != want {
			t.Errorf("%q: want %v", s, want)
		}
	}
}

func TestValidPaths(t *testing.T) {
	for _, p := range []string{".", "a", "a/b", "a b/c"} {
		if err := validRel(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"", "/a", "a/", "a//b", "a/./b", "../a", "a/..", "a\x00b", strings.Repeat("x", 256)} {
		if validRel(p) == nil {
			t.Errorf("%q accepted", p)
		}
	}
	for _, p := range []string{".", "a:b", "a\nb", strings.Repeat("x", 256)} {
		if validSubpath(p) == nil {
			t.Errorf("subpath %q accepted", p)
		}
	}
}

// M3: once a --mkdir or probe --create made something, a later refusal is
// a failure (exit 1), never "refused, nothing changed".
func TestCreateThenFailIsNoRefusal(t *testing.T) {
	root := t.TempDir()
	testHookMkdir = func(rel string) {
		if rel == "a/b" {
			writeFile(t, filepath.Join(root, "a", "b"), 0o644) // b appears as a file
		}
	}
	defer func() { testHookMkdir = nil }()
	p, err := Probe(root, "a/b/c", true)
	if err == nil || IsRefused(err) || !p.Created {
		t.Fatalf("probe: %v created %v, want a failure", err, p.Created)
	}

	needWritableFS(t)
	root = simpleTree(t)
	dev, ino := rootIDs(t, root)
	o := Options{Root: root, ExpectDev: dev, ExpectIno: ino, Target: Target{GID: 60001, Files: "rw", Mkdir: []string{"one", "two/x"}}}
	s, _ := Scan(o)
	testHookMkdir = func(rel string) {
		if rel == "one" {
			must(t, os.Symlink(t.TempDir(), filepath.Join(root, "two")))
		}
	}
	r, err := Apply(o, s.Plan.Changes)
	if err == nil || IsRefused(err) || r.Created != 1 {
		t.Fatalf("apply: %v created %d, want a failure", err, r.Created)
	}
}

// M7: a directory with more names than the cap makes the walk partial.
func TestScanDirNameCap(t *testing.T) {
	root := simpleTree(t)
	old := maxDirNames
	maxDirNames = 1
	defer func() { maxDirNames = old }()
	r, err := Scan(Options{Root: root})
	if err != nil || !r.Partial || r.PartialReason != "names" {
		t.Fatalf("%v partial %v %q", err, r.Partial, r.PartialReason)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// R55: an entry the walk can't read for lack of permission is a failure
// (failed, the scan exits 1), never a race. Unprivileged: root reads all.
func TestScanUnreadableIsFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything (TestRootUnreadableIsFailure covers root)")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "locked"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "locked", "inner"), 0o644)
	os.Chmod(filepath.Join(root, "locked"), 0)
	t.Cleanup(func() { os.Chmod(filepath.Join(root, "locked"), 0o700) })
	writeFile(t, filepath.Join(root, "secret"), 0)
	writeFile(t, filepath.Join(root, "open"), 0o644)
	r, err := Scan(Options{Root: root})
	if err == nil || IsRefused(err) {
		t.Fatalf("scan err = %v, want a failure", err)
	}
	if r.Failed.N != 2 || !slices.Equal(r.Failed.Sample, []string{"locked", "secret"}) || r.Races.N != 0 {
		t.Fatalf("failed %+v races %+v errors %q", r.Failed, r.Races, r.Errors)
	}
	for _, e := range r.Errors {
		if strings.Contains(e, "changed during the walk") {
			t.Errorf("reported as a race: %q", e)
		}
	}
	var out, errb bytes.Buffer
	if code := Main([]string{"scan", "--root=" + root}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1 (%s)", code, errb.String())
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.Failed.N != 2 || len(rep.Errors) == 0 {
		t.Fatalf("report %s: %v", out.Bytes(), err)
	}
}
