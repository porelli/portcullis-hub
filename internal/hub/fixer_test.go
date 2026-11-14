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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/runtime"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/idmap"
	"github.com/portcullis/hub/internal/state"
)

var testSelfImage = "sha256:" + strings.Repeat("c", 64)

// testSelfID is the Hub's own container; testMountinfo its mountinfo.
var (
	testSelfID    = strings.Repeat("9", 64)
	testMountinfo = mountinfoFor(testSelfID)
	selfLabels    = map[string]string{docker.LabelProject: "portcullis", docker.LabelService: "hub"}
)

func mountinfoFor(id string) string {
	return "340 300 0:50 / / ro,relatime - overlay overlay rw\n" +
		"349 340 254:1 /docker/containers/" + id + "/hostname /etc/hostname rw,relatime - ext4 /dev/vda1 rw\n" +
		"350 340 254:1 /docker/containers/" + id + "/hosts /etc/hosts rw,relatime - ext4 /dev/vda1 rw\n" +
		"351 340 254:1 /docker/containers/" + id + "/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw\n"
}

// newFixerFixture: a Hub whose own container (testSelfID, core's hub
// service) runs testSelfImage.
func newFixerFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	fx := f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	return f
}

var testDigest = strings.Repeat("d", 64)

func applyOpts() folderfix.Options {
	return folderfix.Options{ExpectDev: 2049, ExpectIno: 12, ExpectMountRoot: "/photos", ExpectDigest: testDigest,
		Target: folderfix.Target{GID: 60001, Files: "rw"}}
}

// The spec follows the mode: capabilities, read-only bind, scratch
// volumes, argv (contract §6).
func TestFixerCapsByMode(t *testing.T) {
	// DAC_OVERRIDE only for apply --mkdir: the empirical minimum
	// (fixer_docker_test.go TestDockerFixerCapsMinimal).
	writeCaps := []string{"CHOWN", "FOWNER", "FSETID", "DAC_READ_SEARCH"}
	mkdirCaps := []string{"CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE", "DAC_READ_SEARCH"}
	mkdirOpts := applyOpts()
	mkdirOpts.Target.Mkdir = []string{"movies"}
	snap := func(io.Reader) error { return nil }
	for _, c := range []struct {
		name     string
		run      fixerRun
		caps     []string
		ro       bool
		target   string
		scratch  []string
		inPath   string
		outPath  string
		wantArgs []string
	}{
		{"scan", fixerRun{Mode: "scan", Folder: "photos", Source: "/srv/photos", Opts: folderfix.Options{ExpectDev: 2049, ExpectIno: 12, MaxEntries: 10}, Unchecked: true},
			[]string{"DAC_READ_SEARCH"}, true, "/folder", nil, "", "",
			[]string{"scan", "--root=/folder", "--expect-dev=2049", "--expect-ino=12", "--max-entries=10"}},
		{"snapshot", fixerRun{Mode: "snapshot", Folder: "photos", Source: "/srv/photos", Opts: applyOpts(), Out: snap},
			[]string{"DAC_READ_SEARCH"}, true, "/folder", []string{"/out"}, "", "/out", nil},
		{"undo snapshot", fixerRun{Mode: "snapshot", Folder: "photos", Source: "/srv/photos", Opts: applyOpts(),
			Extra: folderfix.ArgsExtra{Kind: "undo"}, In: strings.NewReader("SNAP"), InSize: 4, Out: snap},
			[]string{"DAC_READ_SEARCH"}, true, "/folder", []string{"/in", "/out"}, "/in", "/out", nil},
		{"probe", fixerRun{Mode: "probe", Folder: "photos", Source: "/srv", Extra: folderfix.ArgsExtra{Rel: "photos"}},
			[]string{"DAC_READ_SEARCH"}, true, "/broot", nil, "", "",
			[]string{"probe", "--root=/broot", "--rel=photos"}},
		{"probe create", fixerRun{Mode: "probe", Source: "/srv", Extra: folderfix.ArgsExtra{Rel: "photos/new", Create: true}},
			[]string{"DAC_READ_SEARCH"}, false, "/broot", nil, "", "",
			[]string{"probe", "--root=/broot", "--rel=photos/new", "--create"}},
		{"apply", fixerRun{Mode: "apply", Folder: "photos", Source: "/srv/photos", Opts: applyOpts(), Extra: folderfix.ArgsExtra{Expect: 7}},
			writeCaps, false, "/folder", nil, "", "", nil},
		{"apply mkdir", fixerRun{Mode: "apply", Folder: "photos", Source: "/srv/photos", Opts: mkdirOpts, Extra: folderfix.ArgsExtra{Expect: 7}},
			mkdirCaps, false, "/folder", nil, "", "", nil},
		{"restore", fixerRun{Mode: "restore", Folder: "photos", Source: "/srv/photos", Opts: applyOpts(), In: strings.NewReader("SNAP"), InSize: 4},
			writeCaps, false, "/folder", []string{"/in"}, "/in", "", nil},
		// F33: childfix: the bind root read-write, CHOWN FOWNER only.
		{"childfix", fixerRun{Mode: "childfix", Source: "/srv", Opts: childOpts(), Extra: folderfix.ArgsExtra{Rel: "homes", Child: folderfix.ChildFix{Name: "alice", UID: 20000, Owner: 20000}}},
			[]string{"CHOWN", "FOWNER"}, false, "/broot", nil, "", "",
			[]string{"childfix", "--root=/broot", "--rel=homes", "--child=alice:20000", "--expect-uid=20000", "--expect-dev=2049", "--expect-ino=77", "--expect-mount-root=/srv/homes/alice"}},
		// R56: a dry-run restore only reads.
		{"restore dry run", fixerRun{Mode: "restore", Folder: "photos", Source: "/srv/photos", Opts: applyOpts(), In: strings.NewReader("SNAP"), InSize: 4, Extra: folderfix.ArgsExtra{DryRun: true}},
			[]string{"DAC_READ_SEARCH"}, true, "/folder", []string{"/in"}, "/in", "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixerFixture(t)
			var err error
			if c.run.Mode == "probe" {
				_, err = f.h.runProbe(context.Background(), c.run)
			} else {
				if c.outPath != "" {
					f.engine.fx().run = func(s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
						if err := out(snapshotTar(t, "SNAPBYTES")); err != nil {
							return nil, err
						}
						return &docker.RunResult{Stdout: []byte(`{"version":1,"mode":"snapshot"}` + "\n")}, nil
					}
				}
				_, err = f.h.runFixer(context.Background(), c.run)
			}
			if err != nil {
				t.Fatal(err)
			}
			specs := f.engine.fx().Specs()
			if len(specs) != 1 {
				t.Fatalf("runs = %d", len(specs))
			}
			s := specs[0]
			if !slices.Equal(s.CapAdd, c.caps) {
				t.Errorf("caps = %v, want %v", s.CapAdd, c.caps)
			}
			if len(s.Binds) != 1 || s.Binds[0].ReadOnly != c.ro || s.Binds[0].Target != c.target || s.Binds[0].Source != c.run.Source {
				t.Errorf("binds = %+v", s.Binds)
			}
			if !slices.Equal(s.Scratch, c.scratch) || s.InPath != c.inPath || s.OutPath != c.outPath {
				t.Errorf("scratch %v in %q out %q", s.Scratch, s.InPath, s.OutPath)
			}
			if !slices.Equal(s.Cmd[:3], []string{"/usr/local/bin/hub", "folderfix", c.run.Mode}) {
				t.Errorf("argv = %v", s.Cmd)
			}
			if c.wantArgs != nil && !slices.Equal(s.Cmd[2:], c.wantArgs) {
				t.Errorf("argv = %v, want %v", s.Cmd[2:], c.wantArgs)
			}
			if s.Image != testSelfImage || s.User != "0:0" || s.Pids != 16 || s.Memory != 256<<20 || s.Timeout <= 0 {
				t.Errorf("spec = %+v", s)
			}
			wantLabel := "folder:photos"
			if c.run.Folder == "" {
				wantLabel = "path-check"
			}
			if s.Label != wantLabel {
				t.Errorf("label = %q", s.Label)
			}
			if !slices.Contains(s.Env, "GOMAXPROCS=2") {
				t.Errorf("env = %v", s.Env)
			}
		})
	}
}

// The argv is folderfix.Args (ruling 38), with the paths the helper has.
func TestFixerArgv(t *testing.T) {
	f := newFixerFixture(t)
	o := applyOpts()
	o.Target.Mkdir = []string{"movies"}
	if _, err := f.h.runFixer(context.Background(), fixerRun{Mode: "apply", Folder: "photos", Source: "/srv/photos", Opts: o, Extra: folderfix.ArgsExtra{Expect: 7}}); err != nil {
		t.Fatal(err)
	}
	o.Root = "/folder"
	want := append([]string{"/usr/local/bin/hub", "folderfix"}, folderfix.Args("apply", o, folderfix.ArgsExtra{Expect: 7})...)
	got := f.engine.fx().Specs()[0].Cmd
	if !slices.Equal(got, want) {
		t.Errorf("argv = %v\nwant %v", got, want)
	}
	for _, a := range []string{"--expect-digest=" + testDigest, "--expect-mount-root=/photos", "--expect-dev=2049", "--expect=7", "--mkdir=movies"} {
		if !slices.Contains(got, a) {
			t.Errorf("argv lacks %s: %v", a, got)
		}
	}

	// restore: --gid and --expect-mount-root, the snapshot at /in.
	f.engine.fx().specs = nil
	if _, err := f.h.runFixer(context.Background(), fixerRun{Mode: "restore", Folder: "photos", Source: "/srv/photos", Opts: applyOpts(),
		In: strings.NewReader("SNAP"), InSize: 4}); err != nil {
		t.Fatal(err)
	}
	got = f.engine.fx().Specs()[0].Cmd
	for _, a := range []string{"--gid=60001", "--expect-mount-root=/photos", "--in=/in/" + folderfix.SnapshotName} {
		if !slices.Contains(got, a) {
			t.Errorf("restore argv lacks %s: %v", a, got)
		}
	}
	// The In stream is a tar of exactly the snapshot file.
	ins := f.engine.fx().inputs
	in := ins[len(ins)-1]
	tr := tar.NewReader(bytes.NewReader(in))
	hdr, err := tr.Next()
	if err != nil || hdr.Name != folderfix.SnapshotName || hdr.Typeflag != tar.TypeReg || hdr.Size != 4 || hdr.Uid != 0 || hdr.Mode != 0o600 {
		t.Fatalf("in tar: %+v, %v", hdr, err)
	}
	if b, _ := io.ReadAll(tr); string(b) != "SNAP" {
		t.Errorf("in body = %q", b)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Errorf("in tar has more entries: %v", err)
	}
}

// Runs the T4 carries forbid are refused before any helper starts.
func childOpts() folderfix.Options {
	return folderfix.Options{ExpectDev: 2049, ExpectIno: 77, ExpectMountRoot: "/srv/homes/alice"}
}

func childOptsWith(f func(*folderfix.Options)) folderfix.Options {
	o := childOpts()
	f(&o)
	return o
}

func child(rel, name string, uid int) folderfix.ArgsExtra {
	return folderfix.ArgsExtra{Rel: rel, Child: folderfix.ChildFix{Name: name, UID: uid, Owner: uid}}
}

func TestFixerRefusesBadRuns(t *testing.T) {
	f := newFixerFixture(t)
	noDigest := applyOpts()
	noDigest.ExpectDigest = ""
	noRoot := applyOpts()
	noRoot.ExpectMountRoot = ""
	noDev := applyOpts()
	noDev.ExpectDev, noDev.ExpectIno = 0, 0
	capped := applyOpts()
	capped.MaxEntries = 5
	snap := func(io.Reader) error { return nil }
	in := func() io.Reader { return strings.NewReader("S") }
	for name, r := range map[string]fixerRun{
		"unknown mode":       {Mode: "chmod", Source: "/srv/x"},
		"apply no digest":    {Mode: "apply", Folder: "x", Source: "/srv/x", Opts: noDigest},
		"apply no mountroot": {Mode: "apply", Folder: "x", Source: "/srv/x", Opts: noRoot},
		"apply no dev":       {Mode: "apply", Folder: "x", Source: "/srv/x", Opts: noDev},
		"apply max":          {Mode: "apply", Folder: "x", Source: "/srv/x", Opts: capped},
		"apply no folder":    {Mode: "apply", Source: "/srv/x", Opts: applyOpts()},
		"snapshot max":       {Mode: "snapshot", Folder: "x", Source: "/srv/x", Opts: capped, Out: snap},
		"snapshot no out":    {Mode: "snapshot", Folder: "x", Source: "/srv/x", Opts: applyOpts()},
		"undo no in":         {Mode: "snapshot", Folder: "x", Source: "/srv/x", Opts: applyOpts(), Extra: folderfix.ArgsExtra{Kind: "undo"}, Out: snap},
		"restore no in":      {Mode: "restore", Folder: "x", Source: "/srv/x", Opts: applyOpts()},
		"restore no root":    {Mode: "restore", Folder: "x", Source: "/srv/x", Opts: noRoot, In: in(), InSize: 1},
		"restore no gid":     {Mode: "restore", Folder: "x", Source: "/srv/x", Opts: folderfix.Options{ExpectDev: 1, ExpectIno: 2, ExpectMountRoot: "/x"}, In: in(), InSize: 1},
		"scan with in":       {Mode: "scan", Source: "/srv/x", In: in(), InSize: 1},
		"relative source":    {Mode: "scan", Source: "srv/x"},
		"unclean source":     {Mode: "scan", Source: "/srv/../etc"},
		"root source":        {Mode: "scan", Source: "/"},
		"bad folder id":      {Mode: "scan", Folder: "Photos!", Source: "/srv/x"},
		"probe no rel":       {Mode: "probe", Source: "/srv"},
		// H5: a folder scan and every snapshot check the identity; only a
		// create / check-path / re-check scan says it is learning it
		// (Unchecked: dev/ino still required, no mount root yet).
		"snapshot no dev":            {Mode: "snapshot", Folder: "x", Source: "/srv/x", Opts: noDev, Out: snap},
		"snapshot no mountroot":      {Mode: "snapshot", Folder: "x", Source: "/srv/x", Opts: noRoot, Out: snap},
		"folder scan no dev":         {Mode: "scan", Folder: "x", Source: "/srv/x"},
		"folder scan no mountroot":   {Mode: "scan", Folder: "x", Source: "/srv/x", Opts: folderfix.Options{ExpectDev: 1, ExpectIno: 2}},
		"unchecked scan no dev":      {Mode: "scan", Folder: "x", Source: "/srv/x", Unchecked: true},
		"unchecked on a non-scan":    {Mode: "restore", Folder: "x", Source: "/srv/x", Opts: applyOpts(), In: in(), InSize: 1, Unchecked: true},
		"unchecked without a folder": {Mode: "scan", Source: "/srv/x", Opts: folderfix.Options{ExpectDev: 1, ExpectIno: 2}, Unchecked: true},
		// F33: childfix needs one child, a uid, the identity; never a
		// folder, a target or principals.
		"childfix no identity": {Mode: "childfix", Source: "/srv", Extra: child("homes", "alice", 20000)},
		"childfix folder":      {Mode: "childfix", Folder: "x", Source: "/srv", Opts: childOpts(), Extra: child("homes", "alice", 20000)},
		"childfix no tree":     {Mode: "childfix", Source: "/srv", Opts: childOpts(), Extra: child("", "alice", 20000)},
		"childfix bad tree":    {Mode: "childfix", Source: "/srv", Opts: childOpts(), Extra: child("../etc", "alice", 20000)},
		"childfix nested":      {Mode: "childfix", Source: "/srv", Opts: childOpts(), Extra: child("homes", "alice/x", 20000)},
		"childfix other owner": {Mode: "childfix", Source: "/srv", Opts: childOpts(), Extra: folderfix.ArgsExtra{Rel: "homes", Child: folderfix.ChildFix{Name: "alice", UID: 20000, Owner: 20023}}},
		"childfix uid 0":       {Mode: "childfix", Source: "/srv", Opts: childOpts(), Extra: child("homes", "alice", 0)},
		"childfix target":      {Mode: "childfix", Source: "/srv", Opts: childOptsWith(func(o *folderfix.Options) { o.Target.GID = 60001 }), Extra: child("homes", "alice", 20000)},
		"childfix principals":  {Mode: "childfix", Source: "/srv", Opts: childOptsWith(func(o *folderfix.Options) { o.Principals = []folderfix.Principal{{Name: "a"}} }), Extra: child("homes", "alice", 20000)},
	} {
		var err error
		if r.Mode == "probe" {
			_, err = f.h.runProbe(context.Background(), r)
		} else {
			_, err = f.h.runFixer(context.Background(), r)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// runFixer never runs a probe (its report has another shape).
	if _, err := f.h.runFixer(context.Background(), fixerRun{Mode: "probe", Source: "/srv", Extra: folderfix.ArgsExtra{Rel: "x"}}); err == nil {
		t.Error("runFixer ran a probe")
	}
	if n := len(f.engine.fx().Specs()); n != 0 {
		t.Errorf("%d helpers started", n)
	}
}

// HUB_FIXER_IMAGE must be pinned; otherwise the Hub inspects its own
// container; not found = 503 for every run.
func TestFixerImageResolution(t *testing.T) {
	root := t.TempDir()
	st := state.New()
	os.MkdirAll(filepath.Join(root, "data"), 0755)
	st.Save(filepath.Join(root, "data", "state.yaml"))
	for _, img := range []string{"ghcr.io/porelli/portcullis-hub:edge", "sha256:" + strings.Repeat("a", 64), "x@sha256:abc"} {
		if _, err := newTestHub(Config{ProjectDir: root, DataDir: filepath.Join(root, "data"), FixerImage: img}, newFakeRunner(), &fakeEngine{}, nil); err == nil {
			t.Errorf("FixerImage %q accepted", img)
		}
	}
	dev := "ghcr.io/porelli/portcullis-hub:dev@sha256:" + strings.Repeat("e", 64)
	eng := &fakeEngine{}
	h, err := newTestHub(Config{ProjectDir: root, DataDir: filepath.Join(root, "data"), FixerImage: dev}, newFakeRunner(), eng, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.mountinfo = func() ([]byte, error) { t.Error("inspected itself with FixerImage set"); return nil, errors.New("x") }
	if img, err := h.selfImage(context.Background()); err != nil || img != dev {
		t.Errorf("selfImage = %q, %v", img, err)
	}
	if v := eng.vol(); !slices.Equal(v.images, []string{dev}) {
		t.Errorf("pulled %v", v.images)
	}

	// Unset: the Hub's own container's image ID, inspected by its full ID
	// from mountinfo (R53), cached.
	f := newFixerFixture(t)
	for range 2 {
		if img, err := f.h.selfImage(context.Background()); err != nil || img != testSelfImage {
			t.Errorf("selfImage = %q, %v", img, err)
		}
	}
	if got := f.engine.fx().inspected; !slices.Equal(got, []string{testSelfID}) {
		t.Errorf("inspected %v", got)
	}

	other := strings.Repeat("7", 64)
	short := testSelfID[:12]
	hostname, _ := os.Hostname()
	for name, fix := range map[string]func(*fixture){
		"not found": func(f *fixture) { f.engine.fx().inspect = nil },
		"error":     func(f *fixture) { f.engine.fx().inspectErr = errors.New("proxy down") },
		"tag": func(f *fixture) {
			f.engine.fx().inspect[testSelfID] = docker.ContainerInfo{ID: testSelfID, Image: "ghcr.io/x:edge", Labels: selfLabels}
		},
		// Another container answers for the Hub's id (a name or prefix
		// that shadows it): its ID differs.
		"shadowing container": func(f *fixture) {
			f.engine.fx().inspect[testSelfID] = docker.ContainerInfo{ID: other, Image: testSelfImage, Labels: selfLabels}
		},
		// A container named after the Hub's hostname or short id is never
		// consulted: mountinfo names another container, which isn't there.
		"hostname shadow": func(f *fixture) {
			fx := f.engine.fx()
			fx.inspect[hostname] = docker.ContainerInfo{ID: other, Image: testSelfImage, Labels: selfLabels}
			fx.inspect[short] = docker.ContainerInfo{ID: other, Image: testSelfImage, Labels: selfLabels}
			delete(fx.inspect, testSelfID)
		},
		"label project": func(f *fixture) {
			f.engine.fx().inspect[testSelfID] = docker.ContainerInfo{ID: testSelfID, Image: testSelfImage,
				Labels: map[string]string{docker.LabelProject: "portcullis-evil", docker.LabelService: "hub"}}
		},
		"label service": func(f *fixture) {
			f.engine.fx().inspect[testSelfID] = docker.ContainerInfo{ID: testSelfID, Image: testSelfImage,
				Labels: map[string]string{docker.LabelProject: "portcullis", docker.LabelService: "hubx"}}
		},
		"no labels": func(f *fixture) {
			f.engine.fx().inspect[testSelfID] = docker.ContainerInfo{ID: testSelfID, Image: testSelfImage}
		},
		"mountinfo unreadable": func(f *fixture) { f.h.mountinfo = func() ([]byte, error) { return nil, errors.New("no /proc") } },
		"mountinfo garbage":    func(f *fixture) { f.h.mountinfo = func() ([]byte, error) { return []byte("garbage\n\x00\x01 x"), nil } },
		"mountinfo no docker mount": func(f *fixture) {
			f.h.mountinfo = func() ([]byte, error) { return []byte("340 300 0:50 / / ro - overlay overlay rw\n"), nil }
		},
		"mountinfo short id": func(f *fixture) {
			f.h.mountinfo = func() ([]byte, error) {
				return []byte("349 340 254:1 /docker/containers/" + short + "/hostname /etc/hostname rw - ext4 /dev/vda1 rw\n"), nil
			}
		},
		"mountinfo two ids": func(f *fixture) {
			mi := mountinfoFor(testSelfID) + strings.Replace(mountinfoFor(other), "/etc/hostname", "/etc/hosts", 1)
			f.h.mountinfo = func() ([]byte, error) { return []byte(mi), nil }
		},
		// A container's hosts file bound as /etc/hostname is not the
		// Docker-made mount.
		"mountinfo crossed file": func(f *fixture) {
			f.h.mountinfo = func() ([]byte, error) {
				return []byte("349 340 254:1 /docker/containers/" + testSelfID + "/hosts /etc/hostname rw - ext4 /dev/vda1 rw\n"), nil
			}
		},
		"mountinfo wrong mount point": func(f *fixture) {
			f.h.mountinfo = func() ([]byte, error) {
				return []byte("349 340 254:1 /docker/containers/" + testSelfID + "/hostname /srv/x rw - ext4 /dev/vda1 rw\n"), nil
			}
		},
	} {
		f := newFixerFixture(t)
		fix(f)
		_, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/x"})
		if statusOf(err) != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "the Hub can't find its own image") {
			t.Errorf("%s: err = %v", name, err)
		}
		if n := len(f.engine.fx().Specs()); n != 0 {
			t.Errorf("%s: %d helpers started", name, n)
		}
		for _, id := range f.engine.fx().inspected {
			if id != testSelfID {
				t.Errorf("%s: inspected %q, not the full id from mountinfo", name, id)
			}
		}
		// A failure is not cached: the next run tries again.
		f.engine.fx().inspectErr = nil
		f.engine.fx().inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
		f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
		if _, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/x"}); err != nil {
			t.Errorf("%s: retry: %v", name, err)
		}
	}
}

// The native layout (/var/lib/docker on the root filesystem) parses too.
func TestSelfContainerID(t *testing.T) {
	native := "1 0 8:1 /var/lib/docker/containers/" + testSelfID + "/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n"
	if id, err := selfContainerID([]byte(native), runtime.KindDocker); err != nil || id != testSelfID {
		t.Errorf("native: %q, %v", id, err)
	}
	if _, err := selfContainerID([]byte("1 0 8:1 /var/lib/podman/containers/"+testSelfID+"/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"), runtime.KindDocker); err == nil {
		t.Error("a non-docker path accepted")
	}
}

// P2: under podman the root is …/overlay-containers/<id>/userdata/<file>,
// from the graph root or the run root on the /run/user/<uid> tmpfs; under
// docker neither is accepted, and docker's form isn't accepted under podman.
func TestSelfContainerIDPodman(t *testing.T) {
	graph := "100 90 0:44 /home/p/.local/share/containers/storage/overlay-containers/" + testSelfID + "/userdata/hostname /etc/hostname rw,nosuid - ext4 /dev/sda1 rw\n"
	run := "101 90 0:45 /containers/overlay-containers/" + testSelfID + "/userdata/hostname /etc/hostname rw,nosuid - tmpfs tmpfs rw,size=100k,uid=1001\n" +
		"102 90 0:45 /containers/overlay-containers/" + testSelfID + "/userdata/resolv.conf /etc/resolv.conf rw - tmpfs tmpfs rw\n" +
		"103 90 0:45 /containers/overlay-containers/" + testSelfID + "/userdata/hosts /etc/hosts rw - tmpfs tmpfs rw\n"
	for name, mi := range map[string]string{"graphroot": graph, "runroot": run} {
		if id, err := selfContainerID([]byte(mi), runtime.KindPodman); err != nil || id != testSelfID {
			t.Errorf("%s under podman: %q, %v", name, id, err)
		}
		if id, err := selfContainerID([]byte(mi), runtime.KindDocker); err == nil {
			t.Errorf("%s under docker: accepted %q", name, id)
		}
	}
	// Mounted at the wrong file, or two ids: refused.
	wrong := "1 0 0:45 /containers/overlay-containers/" + testSelfID + "/userdata/hosts /etc/hostname rw - tmpfs tmpfs rw\n"
	if _, err := selfContainerID([]byte(wrong), runtime.KindPodman); err == nil {
		t.Error("hosts mounted at /etc/hostname accepted")
	}
	other := strings.Repeat("b", 64)
	two := graph + "2 0 0:45 /containers/overlay-containers/" + other + "/userdata/hosts /etc/hosts rw - tmpfs tmpfs rw\n"
	if _, err := selfContainerID([]byte(two), runtime.KindPodman); err == nil {
		t.Error("two ids accepted")
	}
	docker := "1 0 8:1 /var/lib/docker/containers/" + testSelfID + "/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n"
	if _, err := selfContainerID([]byte(docker), "podman"); err == nil {
		t.Error("docker's form accepted under podman")
	}
}

// Under userns-remap or rootless Docker every run is refused (ruling 28).
func TestFixerRefusesRemappedIDs(t *testing.T) {
	for _, opts := range [][]string{{"name=userns"}, {"name=seccomp,profile=builtin", "name=rootless"}} {
		f := newFixerFixture(t)
		f.engine.fx().secOpts = opts
		_, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/x"})
		if statusOf(err) != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "ids") {
			t.Errorf("%v: err = %v", opts, err)
		}
		if n := len(f.engine.fx().Specs()); n != 0 {
			t.Errorf("%v: %d helpers started", opts, n)
		}
	}
	f := newFixerFixture(t)
	f.engine.fx().secErr = errors.New("info denied")
	if _, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/x"}); statusOf(err) != http.StatusServiceUnavailable {
		t.Errorf("info error: %v", err)
	}
}

func reportLine(t *testing.T, r folderfix.Report) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The report is the last non-empty stdout line, decoded strictly; exit 2
// with a report = 409, anything else non-zero = 500 (T4 carry: exit 2
// without a report is a crash, not a refusal).
func TestFixerExitCodes(t *testing.T) {
	good := reportLine(t, folderfix.Report{Version: 1, Mode: "scan", Entries: 3})
	refused := reportLine(t, folderfix.Report{Version: 1, Mode: "scan", Errors: []string{"/folder is not the folder's directory", "x"}})
	for _, c := range []struct {
		name   string
		res    docker.RunResult
		status int // 0 = ok
		msg    string
		report bool
	}{
		{"ok", docker.RunResult{Stdout: []byte("noise\n" + good + "\n\n")}, 0, "", true},
		{"garbage", docker.RunResult{Stdout: []byte("not json\n")}, 500, "report", false},
		{"no output", docker.RunResult{}, 500, "report", false},
		{"unknown field", docker.RunResult{Stdout: []byte(`{"version":1,"mode":"scan","extra":1}` + "\n")}, 500, "report", false},
		{"two documents", docker.RunResult{Stdout: []byte(good + good + "\n")}, 500, "report", false},
		{"wrong mode", docker.RunResult{Stdout: []byte(`{"version":1,"mode":"apply"}` + "\n")}, 500, "report", false},
		{"wrong version", docker.RunResult{Stdout: []byte(`{"version":2,"mode":"scan"}` + "\n")}, 500, "report", false},
		{"clipped", docker.RunResult{Stdout: []byte(good + "\n"), StdoutClipped: true}, 0, "", true},
		{"refused", docker.RunResult{ExitCode: 2, Stdout: []byte(refused + "\n")}, 409, "/folder is not the folder's directory", true},
		{"exit 2 no report", docker.RunResult{ExitCode: 2, Stderr: []byte("fatal error: out of memory\n")}, 500, "out of memory", false},
		{"failed", docker.RunResult{ExitCode: 1, Stdout: []byte(refused + "\n")}, 500, "/folder is not the folder's directory", true},
		{"failed argv", docker.RunResult{ExitCode: 1, Stderr: []byte("folderfix: --x is not a flag of scan\n")}, 500, "--x is not a flag", false},
		{"killed", docker.RunResult{ExitCode: 137}, 500, "137", false},
	} {
		f := newFixerFixture(t)
		res := c.res
		f.engine.fx().run = func(docker.RunSpec, func(io.Reader) error) (*docker.RunResult, error) { return &res, nil }
		rep, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/x"})
		if c.status == 0 {
			if err != nil || rep == nil || rep.Entries != 3 {
				t.Errorf("%s: %+v, %v", c.name, rep, err)
			}
			continue
		}
		if statusOf(err) != c.status || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: err = %v (status %d), want %d with %q", c.name, err, statusOf(err), c.status, c.msg)
		}
		if (rep != nil) != c.report {
			t.Errorf("%s: report = %+v", c.name, rep)
		}
	}

	// A Docker error is a 500 naming the fixer.
	f := newFixerFixture(t)
	f.engine.fx().run = func(docker.RunSpec, func(io.Reader) error) (*docker.RunResult, error) {
		return nil, errors.New("helper timed out after 2m0s (killed)")
	}
	if _, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/x"}); statusOf(err) != 500 || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("docker error: %v", err)
	}
}

func TestProbeReport(t *testing.T) {
	f := newFixerFixture(t)
	f.engine.fx().reports = map[string]string{"probe": `{"version":1,"mode":"probe","root":"/broot","rel":"photos","dev":7,"ino":9,"symlink":"","exists":true,"created":false,"mount_root":"/","fs_type":"ext4"}`}
	p, err := f.h.runProbe(context.Background(), fixerRun{Mode: "probe", Source: "/srv", Extra: folderfix.ArgsExtra{Rel: "photos"}})
	if err != nil || !p.Exists || p.Dev != 7 || p.Ino != 9 || p.FSType != "ext4" {
		t.Errorf("probe = %+v, %v", p, err)
	}
	f.engine.fx().reports = map[string]string{"probe": `{"version":1,"mode":"probe","bogus":1}`}
	if _, err := f.h.runProbe(context.Background(), fixerRun{Mode: "probe", Source: "/srv", Extra: folderfix.ArgsExtra{Rel: "photos"}}); statusOf(err) != 500 {
		t.Errorf("unknown field: %v", err)
	}
}

// snapshotTar is the archive endpoint's answer for /out.
func snapshotTar(t *testing.T, body string, extra ...tar.Header) io.Reader {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "out/", Typeflag: tar.TypeDir, Mode: 0o755})
	if body != "" {
		tw.WriteHeader(&tar.Header{Name: "out/" + folderfix.SnapshotName, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	for _, h := range extra {
		tw.WriteHeader(&h)
		if h.Size > 0 {
			tw.Write(make([]byte, h.Size))
		}
	}
	tw.Close()
	return &b
}

// The snapshot comes out as exactly one regular tar entry (ruling 31).
func TestFixerSnapshotTransfer(t *testing.T) {
	for _, c := range []struct {
		name string
		tar  func(t *testing.T) io.Reader
		ok   bool
	}{
		{"one file", func(t *testing.T) io.Reader { return snapshotTar(t, "SNAPBYTES") }, true},
		{"missing", func(t *testing.T) io.Reader { return snapshotTar(t, "") }, false},
		{"extra file", func(t *testing.T) io.Reader {
			return snapshotTar(t, "SNAPBYTES", tar.Header{Name: "out/other", Typeflag: tar.TypeReg, Size: 1})
		}, false},
		{"symlink", func(t *testing.T) io.Reader {
			return snapshotTar(t, "", tar.Header{Name: "out/" + folderfix.SnapshotName, Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"})
		}, false},
		{"twice", func(t *testing.T) io.Reader {
			return snapshotTar(t, "SNAPBYTES", tar.Header{Name: "out/" + folderfix.SnapshotName, Typeflag: tar.TypeReg, Size: 2})
		}, false},
		{"subdir", func(t *testing.T) io.Reader {
			return snapshotTar(t, "SNAPBYTES", tar.Header{Name: "out/d/", Typeflag: tar.TypeDir})
		}, false},
		{"not a tar", func(t *testing.T) io.Reader { return strings.NewReader("garbage") }, false},
	} {
		f := newFixerFixture(t)
		f.engine.fx().run = func(s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
			if err := out(c.tar(t)); err != nil {
				return &docker.RunResult{}, err
			}
			return &docker.RunResult{Stdout: []byte(`{"version":1,"mode":"snapshot"}` + "\n")}, nil
		}
		var got []byte
		_, err := f.h.runFixer(context.Background(), fixerRun{Mode: "snapshot", Folder: "photos", Source: "/srv/photos", Opts: applyOpts(),
			Out: func(r io.Reader) error {
				var err error
				got, err = io.ReadAll(r)
				return err
			}})
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if c.ok && string(got) != "SNAPBYTES" {
			t.Errorf("%s: snapshot = %q", c.name, got)
		}
	}
	// The snapshot never exceeds the cap.
	old := maxSnapshotBytes
	maxSnapshotBytes = 4
	defer func() { maxSnapshotBytes = old }()
	f := newFixerFixture(t)
	f.engine.fx().run = func(s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
		return &docker.RunResult{}, out(snapshotTar(t, "SNAPBYTES"))
	}
	if _, err := f.h.runFixer(context.Background(), fixerRun{Mode: "snapshot", Folder: "photos", Source: "/srv/photos", Opts: applyOpts(),
		Out: func(r io.Reader) error { _, err := io.ReadAll(r); return err }}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversized snapshot: %v", err)
	}
}

// Entries the fixer left alone because they changed under it reach the
// caller as a warning (T4 carry: apply exits 0 with races).
func TestFixerRaceWarning(t *testing.T) {
	if w := fixerWarnings(&folderfix.Report{}); len(w) != 0 {
		t.Errorf("no races: %v", w)
	}
	w := fixerWarnings(&folderfix.Report{Races: folderfix.Count{N: 2, Sample: []string{"a/b", "c"}}})
	if len(w) != 1 || !strings.Contains(w[0], "2 entries changed while the fixer ran") || !strings.Contains(w[0], "a/b") {
		t.Errorf("warnings = %v", w)
	}
}

// A fixer left behind (Hub restart mid-run) is removed at start like the
// backup helpers.
func TestSweepRemovesFixers(t *testing.T) {
	f := newFixture(t)
	f.engine.mu.Lock()
	f.engine.containers = append(f.engine.containers,
		docker.Container{ID: "fixer1", Names: []string{"/fixer1"}, State: "running", Labels: map[string]string{docker.LabelHelper: "folder:x"}},
		docker.Container{ID: "app1", Names: []string{"/app1"}, State: "running", Labels: map[string]string{docker.LabelProject: "portcullis-x"}})
	f.engine.mu.Unlock()
	f.h.SweepBackupLeftovers()
	if v := f.engine.vol(); !slices.Contains(v.removed, "fixer1") || slices.Contains(v.removed, "app1") {
		t.Errorf("removed = %v", v.removed)
	}
}

func podmanMountinfoFor(id string) string {
	return "340 300 0:50 / / ro,relatime - overlay overlay rw\n" +
		"349 340 0:45 /containers/overlay-containers/" + id + "/userdata/hostname /etc/hostname rw - tmpfs tmpfs rw\n"
}

// Rootless Podman (contract §6): name=rootless is allowed only under
// HUB_CONTAINER_RUNTIME=podman; userns is always refused.
func TestRunFixerRootlessPodman(t *testing.T) {
	for _, c := range []struct {
		name string
		rt   runtime.Kind
		opts []string
		ok   bool
	}{
		{"rootless podman", runtime.KindPodman, []string{"name=seccomp,profile=default", "name=rootless"}, true},
		{"rootless docker", runtime.KindDocker, []string{"name=rootless"}, false},
		{"userns under podman", runtime.KindPodman, []string{"name=userns"}, false},
		{"plain podman", runtime.KindPodman, []string{"name=seccomp"}, true},
	} {
		f := newFixerFixture(t)
		f.h.cfg.Runtime = c.rt
		if c.rt == runtime.KindPodman {
			f.h.mountinfo = func() ([]byte, error) { return []byte(podmanMountinfoFor(testSelfID)), nil }
		}
		f.engine.fx().secOpts = c.opts
		_, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/x"})
		n := len(f.engine.fx().Specs())
		if c.ok {
			if err != nil || n != 1 {
				t.Errorf("%s: err %v, %d runs", c.name, err, n)
			}
			continue
		}
		if statusOf(err) != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "user and group ids inside the fixer are translated") || n != 0 {
			t.Errorf("%s: err %v, %d runs", c.name, err, n)
		}
	}
	if err := fixerIDsAllowed(runtime.KindDocker, []string{"name=rootless"}); err == nil || !strings.Contains(err.Error(), "Docker runs with rootless") {
		t.Errorf("message = %v", err)
	}
}

// The unmapped-owner refusal gets the host step: the operator uid (the
// report's id_map uid container 0) and the host path (folder + rel).
func TestFixerUnmappedMessage(t *testing.T) {
	f := newFixerFixture(t)
	f.h.cfg.Runtime = runtime.KindPodman
	f.h.mountinfo = func() ([]byte, error) { return []byte(podmanMountinfoFor(testSelfID)), nil }
	f.engine.fx().secOpts = []string{"name=rootless"}
	um, _ := idmap.Parse("0 1001 1\n1 100000 65536")
	rep := reportLine(t, folderfix.Report{Version: 1, Mode: "scan", IDMap: &folderfix.IDMaps{UID: um, GID: um},
		Unmapped: folderfix.Count{N: 1, Sample: []string{"x"}}, Errors: []string{fmt.Sprintf(folderfix.UnmappedMsg, "x")}})
	f.engine.fx().run = func(docker.RunSpec, func(io.Reader) error) (*docker.RunResult, error) {
		return &docker.RunResult{ExitCode: 2, Stdout: []byte(rep + "\n")}, nil
	}
	_, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/media"})
	want := "x is owned by a host account outside Portcullis' id range; run sudo chown -R '1001:1001' '/srv/media/x' once, then re-check"
	if statusOf(err) != http.StatusConflict || err.Error() != want {
		t.Errorf("err = %v (%d), want %q", err, statusOf(err), want)
	}
	// The root itself.
	rep = reportLine(t, folderfix.Report{Version: 1, Mode: "scan", IDMap: &folderfix.IDMaps{UID: um, GID: um},
		Errors: []string{fmt.Sprintf(folderfix.UnmappedMsg, ".")}})
	_, err = f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/media"})
	if want := ". is owned by a host account outside Portcullis' id range; run sudo chown -R '1001:1001' '/srv/media' once, then re-check"; err == nil || err.Error() != want {
		t.Errorf("root: %v", err)
	}
	// Without an id map (never under podman): no step.
	rep = reportLine(t, folderfix.Report{Version: 1, Mode: "scan", Errors: []string{fmt.Sprintf(folderfix.UnmappedMsg, "x")}})
	_, err = f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/media"})
	if err == nil || strings.Contains(err.Error(), "sudo") {
		t.Errorf("no map: %v", err)
	}
}

// The host step is pasted into a root shell: the path is one POSIX
// single-quoted word, and a name that can't be (a control character) or
// that folderfix clipped gets no step at all.
func TestUnmappedHintQuoting(t *testing.T) {
	um, _ := idmap.Parse("0 1001 1\n1 100000 65536")
	gm, _ := idmap.Parse("0 1002 1\n1 200000 65536")
	rep := &folderfix.Report{IDMap: &folderfix.IDMaps{UID: um, GID: gm}}
	msg := func(rel string) string { return fmt.Sprintf(folderfix.UnmappedMsg, rel) }
	step := func(q string) string { return "; run sudo chown -R '1001:1002' " + q + " once, then re-check" }
	for _, c := range []struct {
		name, rel, want string
	}{
		{"plain", "photos/a.jpg", step("'/srv/media/photos/a.jpg'")},
		{"spaces", "my photos/a b.jpg", step("'/srv/media/my photos/a b.jpg'")},
		{"single quote", "it's", step(`'/srv/media/it'\''s'`)},
		{"command substitution", "$(id)", step("'/srv/media/$(id)'")},
		{"backticks", "`id`", step("'/srv/media/`id`'")},
		{"semicolon", "x; rm -rf ~", step("'/srv/media/x; rm -rf ~'")},
		{"newline", "x\nrm -rf ~", ""},
		{"carriage return", "x\rrm", ""},
		{"tab", "x\ty", ""},
		{"line separator", "x\u2028y", ""},
		{"invalid UTF-8", "x\xffy", ""},
		{"clipped name", "very/long/name…", ""},
		{"root", ".", step("'/srv/media'")},
	} {
		if got := unmappedHint(msg(c.rel), rep, "/srv/media"); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// Not the unmapped refusal, or no map: no step.
	if got := unmappedHint("something else", rep, "/srv/media"); got != "" {
		t.Errorf("other refusal: %q", got)
	}
	if got := unmappedHint(msg("x"), &folderfix.Report{}, "/srv/media"); got != "" {
		t.Errorf("no map: %q", got)
	}
}

// I2: a folder refused only for an unmapped group gets the uid:gid step
// (a uid-only chown would leave the group, and the re-check refuse again).
func TestFixerUnmappedGroupOnly(t *testing.T) {
	f := newFixerFixture(t)
	f.h.cfg.Runtime = runtime.KindPodman
	f.h.mountinfo = func() ([]byte, error) { return []byte(podmanMountinfoFor(testSelfID)), nil }
	f.engine.fx().secOpts = []string{"name=rootless"}
	um, _ := idmap.Parse("0 1001 1\n1 100000 65536")
	gm, _ := idmap.Parse("0 1001 1\n1 200000 65536")
	rep := reportLine(t, folderfix.Report{Version: 1, Mode: "scan", IDMap: &folderfix.IDMaps{UID: um, GID: gm},
		Owners:   []folderfix.OwnerCount{{UID: 0, GID: idmap.Overflow, N: 1}},
		Unmapped: folderfix.Count{N: 1, Sample: []string{"shared"}}, Errors: []string{fmt.Sprintf(folderfix.UnmappedMsg, "shared")}})
	f.engine.fx().run = func(docker.RunSpec, func(io.Reader) error) (*docker.RunResult, error) {
		return &docker.RunResult{ExitCode: 2, Stdout: []byte(rep + "\n")}, nil
	}
	_, err := f.h.runFixer(context.Background(), fixerRun{Mode: "scan", Source: "/srv/media"})
	if want := "; run sudo chown -R '1001:1001' '/srv/media/shared' once, then re-check"; err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Errorf("err = %v, want the uid:gid step %q", err, want)
	}
}
