package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/state"
)

// ── a fake host disk behind the fixer's probe and scan ───

// diskPath is one directory of the fake host.
type diskPath struct {
	fs         string
	dev, ino   uint64
	mountRoot  string
	acl, xattr bool
	files      int64
	dirs       int64
	owners     []folderfix.OwnerCount
}

// fakeDisk answers probe and scan runs from its paths (host path →
// directory) and symlinks (host paths that are symlinks).
type fakeDisk struct {
	mu       sync.Mutex
	paths    map[string]*diskPath
	symlinks map[string]bool
	nextIno  uint64
	// scanDev, if set, is the device a scan reports instead of the
	// path's (the path changed between probe and scan).
	scanDev uint64
	// refuseSub: subpaths (host paths) a probe refuses (exit 2: "not a
	// directory"), the subpaths before them reported.
	refuseSub map[string]bool
	// onScan, if set, runs (outside mu and the disk's lock) before a
	// scan answers: another request racing this one.
	onScan func(src string)
}

func argValue(cmd []string, flag string) (string, bool) {
	for _, a := range cmd {
		if a == "--"+flag {
			return "", true
		}
		if v, ok := strings.CutPrefix(a, "--"+flag+"="); ok {
			return v, true
		}
	}
	return "", false
}

// argValues are every value of a repeated flag.
func argValues(cmd []string, flag string) []string {
	var out []string
	for _, a := range cmd {
		if v, ok := strings.CutPrefix(a, "--"+flag+"="); ok {
			out = append(out, v)
		}
	}
	return out
}

// add makes p an existing directory on fs.
func (d *fakeDisk) add(p, fs string) *diskPath {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addLocked(p, fs)
}

func (d *fakeDisk) addLocked(p, fs string) *diskPath {
	d.nextIno++
	e := &diskPath{fs: fs, dev: 2049, ino: 100 + d.nextIno, mountRoot: p, acl: true, xattr: true, files: 12410, dirs: 312,
		owners: []folderfix.OwnerCount{{UID: 1000, GID: 1000, N: 12410 + 312 + 1}}}
	d.paths[p] = e
	return e
}

func (d *fakeDisk) run(s docker.RunSpec, _ func(io.Reader) error) (*docker.RunResult, error) {
	if hook := d.onScan; hook != nil && fixerMode(s.Cmd) == "scan" {
		d.onScan = nil
		hook(s.Binds[0].Source)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	src := s.Binds[0].Source
	var rep any
	switch fixerMode(s.Cmd) {
	case "probe":
		rel, _ := argValue(s.Cmd, "rel")
		_, create := argValue(s.Cmd, "create")
		p := &folderfix.ProbeReport{Version: 1, Mode: "probe", Root: "/broot", Rel: rel, MountRoot: "/"}
		parts := strings.Split(rel, "/")
		for i := range parts {
			if d.symlinks[path.Join(src, path.Join(parts[:i+1]...))] {
				p.Symlink = path.Join(parts[:i+1]...)
				break
			}
		}
		if p.Symlink == "" {
			e := d.paths[path.Join(src, rel)]
			if e == nil && create {
				e = d.addLocked(path.Join(src, rel), "ext4")
				p.Created = true
			}
			if e != nil {
				p.Exists, p.Dev, p.Ino, p.FSType = true, e.dev, e.ino, e.fs
			}
		}
		if p.Exists {
			for _, sub := range argValues(s.Cmd, "sub") {
				sp := folderfix.SubProbe{Rel: sub}
				parts := strings.Split(sub, "/")
				for i := range parts {
					if d.symlinks[path.Join(src, rel, path.Join(parts[:i+1]...))] {
						sp.Symlink = path.Join(parts[:i+1]...)
						break
					}
				}
				if d.refuseSub[path.Join(src, rel, sub)] {
					p.Errors = []string{sub + " is not a directory"}
					b, _ := json.Marshal(p)
					return &docker.RunResult{ExitCode: 2, Stdout: append(b, '\n')}, nil
				}
				if e := d.paths[path.Join(src, rel, sub)]; e != nil && sp.Symlink == "" {
					sp.Exists, sp.Dev, sp.Ino = true, e.dev, e.ino
				}
				p.Subs = append(p.Subs, sp)
			}
		}
		rep = p
	case "scan":
		e := d.paths[src]
		if e == nil {
			return &docker.RunResult{ExitCode: 2, Stdout: []byte(`{"version":1,"mode":"scan","errors":["no such directory"]}` + "\n")}, nil
		}
		dev := e.dev
		if d.scanDev != 0 {
			dev = d.scanDev
		}
		rep = &folderfix.Report{Version: 1, Mode: "scan", Root: "/folder", Dev: dev, Ino: e.ino, MountRoot: e.mountRoot, FSType: e.fs,
			ACL: e.acl, Xattr: e.xattr, Entries: e.files + e.dirs + 1, Files: e.files, Dirs: e.dirs, Owners: e.owners}
	default:
		return nil, fmt.Errorf("unexpected fixer mode %q", fixerMode(s.Cmd))
	}
	b, _ := json.Marshal(rep)
	return &docker.RunResult{Stdout: append(b, '\n')}, nil
}

// folderFixture is the immich fixture with the fixer's own image found
// and a fake disk holding /srv/photos (ext4).
func folderFixture(t *testing.T) (*fixture, *fakeAudit, *fakeDisk) {
	t.Helper()
	f, audit := immichFixture(t)
	fx := f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	d := &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}
	d.add("/srv/photos", "ext4")
	fx.run = d.run
	return f, audit, d
}

func fixerModes(f *fixture) []string {
	var out []string
	for _, s := range f.engine.fx().Specs() {
		out = append(out, fixerMode(s.Cmd))
	}
	return out
}

func storedFolder(f *fixture, id string) (state.Folder, bool) {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	fo, ok := f.h.st.Folders[id]
	return fo, ok
}

func createFolder(t *testing.T, f *fixture, id, p string) *FolderView {
	t.Helper()
	v, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: id, Name: "Folder " + id, Path: p}, "admin")
	if err != nil {
		t.Fatalf("create %s at %s: %v", id, p, err)
	}
	return v
}

// The Global Constraints path rules, each refusal with its reason, before
// any fixer run (contract §14.1).
func TestFolderPathRules(t *testing.T) {
	f, _, d := folderFixture(t)
	f.h.cfg.AppFilesHostDir = "/srv/data/appfiles"
	for _, p := range []string{"/srv/data/appfiles/x", "/srv/data", "/var/lib/docker/x"} {
		d.add(p, "ext4")
	}
	for p, why := range map[string]string{
		"/srv":                 "bind root",
		"/srv/":                "bind root",
		"/mnt":                 "bind root",
		"/etc/x":               "system path /etc",
		"/var/lib/docker/x":    "system path /var/lib",
		"/host/project/x":      "core checkout",
		"/host":                "core checkout",
		"/srv/data/appfiles":   "data files",
		"/srv/data/appfiles/x": "data files",
		"/srv/data":            "data files",
		"/home/x":              "not under a bind root",
		"/srv/a/../b":          "..",
		"srv/photos":           "absolute",
		"/srv/a:b":             ":",
		"/srv/$HOME":           "$",
		"/srv/a\nb":            "control",
		"":                     "host path",
		"/":                    "bind root",
	} {
		_, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "x", Name: "X", Path: p}, "admin")
		if statusOf(err) != 400 || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, want 400 naming %q", p, err, why)
		}
		if _, err := f.h.CheckFolderPath(context.Background(), p, true); statusOf(err) != 400 {
			t.Errorf("check %q: %v, want 400", p, err)
		}
	}
	if n := len(f.engine.fx().Specs()); n != 0 {
		t.Errorf("%d fixer runs for refused paths", n)
	}
	if _, ok := storedFolder(f, "x"); ok {
		t.Error("a refused folder was stored")
	}
	if v := createFolder(t, f, "photos", "/srv/photos"); v.Path != "/srv/photos" {
		t.Errorf("view = %+v", v)
	}
}

// Paths are cleaned before any comparison; overlaps are 409 (Review
// Focus 1).
func TestFolderPathNormalised(t *testing.T) {
	f, _, d := folderFixture(t)
	d.add("/srv/photos/2026", "ext4")
	d.add("/srv/media/tv", "ext4")
	d.add("/srv/media", "ext4")
	if v := createFolder(t, f, "photos", "/srv/photos/"); v.Path != "/srv/photos" {
		t.Errorf("stored %q", v.Path)
	}
	if fo, _ := storedFolder(f, "photos"); fo.Path != "/srv/photos" {
		t.Errorf("state %q", fo.Path)
	}
	for _, p := range []string{"/srv//photos", "/srv/photos/2026", "/srv/photos/./2026/"} {
		_, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "other", Name: "O", Path: p}, "admin")
		if statusOf(err) != 409 || !strings.Contains(err.Error(), "photos") {
			t.Errorf("%q: %v, want 409 overlap", p, err)
		}
	}
	createFolder(t, f, "tv", "/srv/media/tv")
	if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "media", Name: "M", Path: "/srv/media"}, "admin"); statusOf(err) != 409 {
		t.Errorf("a folder above another: %v", err)
	}
	// Check path reports the overlap as a problem.
	pc, err := f.h.CheckFolderPath(context.Background(), "/srv//photos/2026/", false)
	if err != nil || pc.Path != "/srv/photos/2026" || len(pc.Problems) == 0 || !strings.Contains(pc.Problems[0], "photos") {
		t.Errorf("check = %+v, %v", pc, err)
	}
}

// A symlink below the bind root is refused by the probe (Review Focus 1).
func TestFolderPathSymlinkRefused(t *testing.T) {
	f, _, d := folderFixture(t)
	d.symlinks["/srv/photos"] = true
	_, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "photos", Name: "P", Path: "/srv/photos"}, "admin")
	if statusOf(err) != 409 || err.Error() != "/srv/photos is a symlink; give the real path" {
		t.Errorf("err = %v", err)
	}
	specs := f.engine.fx().Specs()
	if len(specs) != 1 || fixerMode(specs[0].Cmd) != "probe" {
		t.Fatalf("runs = %v, want the probe only", fixerModes(f))
	}
	b := specs[0].Binds
	if len(b) != 1 || b[0].Source != "/srv" || b[0].Target != "/broot" || !b[0].ReadOnly {
		t.Errorf("probe bind = %+v", b)
	}
	if rel, _ := argValue(specs[0].Cmd, "rel"); rel != "photos" {
		t.Errorf("probe argv = %v", specs[0].Cmd)
	}
	if _, create := argValue(specs[0].Cmd, "create"); create {
		t.Errorf("probe created: %v", specs[0].Cmd)
	}
	// An ancestor below the root, through check path too.
	d.symlinks["/mnt/a"] = true
	if _, err := f.h.CheckFolderPath(context.Background(), "/mnt/a/b", true); statusOf(err) != 409 || err.Error() != "/mnt/a is a symlink; give the real path" {
		t.Errorf("check = %v", err)
	}
	if _, ok := storedFolder(f, "photos"); ok {
		t.Error("stored")
	}
}

// Create probes, then scans the folder; refused filesystems are 409;
// gids are the lowest free, never reused.
func TestCreateFolderRunsCheck(t *testing.T) {
	f, _, d := folderFixture(t)
	d.add("/srv/nas", "nfs")
	_, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "nas", Name: "NAS", Path: "/srv/nas"}, "admin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "nfs") || !strings.Contains(err.Error(), "file server") {
		t.Errorf("nfs: %v", err)
	}
	for _, fs := range []string{"cifs", "fuse", "overlay", "tmpfs"} {
		d.add("/srv/"+fs, fs)
		if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: fs, Name: fs, Path: "/srv/" + fs}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), fs) {
			t.Errorf("%s: %v", fs, err)
		}
	}
	// A missing path without Create is refused; nothing was created.
	if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "new", Name: "N", Path: "/srv/new"}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "doesn't exist") {
		t.Errorf("missing: %v", err)
	}
	f.engine.fx().fmu.Lock()
	f.engine.fx().specs = nil
	f.engine.fx().fmu.Unlock()

	v := createFolder(t, f, "photos", "/srv/photos")
	if v.GID != 60000 || v.Adopted || v.ID != "photos" || v.Name != "Folder photos" || v.Uses == nil || len(v.Uses) != 0 {
		t.Errorf("view = %+v", v)
	}
	if m := fixerModes(f); !slices.Equal(m, []string{"probe", "scan"}) {
		t.Errorf("runs = %v", m)
	}
	scan := f.engine.fx().Specs()[1]
	if b := scan.Binds; len(b) != 1 || b[0].Source != "/srv/photos" || b[0].Target != "/folder" || !b[0].ReadOnly {
		t.Errorf("scan bind = %+v", b)
	}
	disk := d.paths["/srv/photos"]
	for flag, want := range map[string]string{"expect-dev": "2049", "expect-ino": fmt.Sprint(disk.ino), "max-time": "30s", "max-entries": "2000000"} {
		if got, _ := argValue(scan.Cmd, flag); got != want {
			t.Errorf("scan --%s = %q, want %q (%v)", flag, got, want, scan.Cmd)
		}
	}
	// R41 / R43: dev and inode from the probe, the mount root from the
	// scan of /folder.
	fo, _ := storedFolder(f, "photos")
	if fo.Dev != 2049 || fo.Ino != disk.ino || fo.MountRoot != "/srv/photos" || fo.CreatedAt.IsZero() {
		t.Errorf("stored = %+v", fo)
	}
	d.add("/srv/music", "xfs")
	if v := createFolder(t, f, "music", "/srv/music"); v.GID != 60001 {
		t.Errorf("second gid = %d", v.GID)
	}
	if err := f.h.DeleteFolder("photos", "admin"); err != nil {
		t.Fatal(err)
	}
	d.add("/srv/docs", "btrfs")
	if v := createFolder(t, f, "docs", "/srv/docs"); v.GID != 60002 {
		t.Errorf("third gid = %d, want 60002 (never reused)", v.GID)
	}
	f.h.mu.RLock()
	gids := slices.Clone(f.h.st.FolderGIDs)
	f.h.mu.RUnlock()
	if !slices.Equal(gids, []int{60000, 60001, 60002}) {
		t.Errorf("folder_gids = %v", gids)
	}
	// Persisted: a restart sees the same.
	st, err := state.Load(f.h.statePath())
	if err != nil || !slices.Equal(st.FolderGIDs, gids) || st.Folders["docs"].GID != 60002 || len(st.Folders) != 2 {
		t.Errorf("reloaded: %+v %v", st.Folders, err)
	}
	// The path changed between probe and scan: refused.
	d.add("/srv/swap", "ext4")
	d.scanDev = 7
	if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "swap", Name: "S", Path: "/srv/swap"}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "changed") {
		t.Errorf("swapped: %v", err)
	}
	d.scanDev = 0
	// Create makes a missing path through the probe.
	if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "fresh", Name: "F", Path: "/srv/fresh/one", Create: true}, "admin"); err != nil {
		t.Errorf("create a missing path: %v", err)
	}
}

func TestAdoptGID(t *testing.T) {
	f, _, d := folderFixture(t)
	d.add("/srv/music", "ext4")
	d.add("/srv/docs", "ext4")
	adopt := func(id, p string, gid int) (*FolderView, []string, error) {
		return f.h.CreateFolder(context.Background(), FolderInput{ID: id, Name: id, Path: p, GID: &gid}, "admin")
	}
	for _, gid := range []int{999, 65534, 60500, 60000, 60999, 10001, 10002, -1, 0} {
		if _, _, err := adopt("photos", "/srv/photos", gid); statusOf(err) != 400 {
			t.Errorf("adopt %d: %v, want 400", gid, err)
		}
	}
	if len(f.engine.fx().Specs()) != 0 {
		t.Error("refused adoptions ran the fixer")
	}
	v, warns, err := adopt("photos", "/srv/photos", 1000)
	if err != nil || v.GID != 1000 || !v.Adopted {
		t.Fatalf("adopt 1000: %+v %v", v, err)
	}
	if !slices.Contains(warns, "anything mounted with gid 1000 becomes reachable by this folder's apps") {
		t.Errorf("warnings = %q", warns)
	}
	if _, _, err := adopt("music", "/srv/music", 1000); statusOf(err) != 409 || !strings.Contains(err.Error(), "photos") {
		t.Errorf("a gid another folder uses: %v", err)
	}
	f.h.mu.RLock()
	gids := slices.Clone(f.h.st.FolderGIDs)
	f.h.mu.RUnlock()
	if len(gids) != 0 {
		t.Errorf("adoption allocated %v", gids)
	}
	// The next allocated one is still the first of the range.
	if v := createFolder(t, f, "docs", "/srv/docs"); v.GID != 60000 {
		t.Errorf("allocated after adoption: %d", v.GID)
	}
}

func TestGIDRangeExhausted(t *testing.T) {
	f, _, _ := folderFixture(t)
	f.h.mu.Lock()
	for g := FolderGIDMin; g <= FolderGIDMax; g++ {
		f.h.st.FolderGIDs = append(f.h.st.FolderGIDs, g)
	}
	f.h.mu.Unlock()
	_, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "photos", Name: "P", Path: "/srv/photos"}, "admin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "no free folder group") {
		t.Errorf("err = %v", err)
	}
	if len(f.engine.fx().Specs()) != 0 {
		t.Error("ran the fixer with no gid to give")
	}
	// One freed by hand in the middle: the lowest free one.
	f.h.mu.Lock()
	f.h.st.FolderGIDs = slices.DeleteFunc(f.h.st.FolderGIDs, func(g int) bool { return g == 60417 })
	f.h.mu.Unlock()
	if v := createFolder(t, f, "photos", "/srv/photos"); v.GID != 60417 {
		t.Errorf("gid = %d", v.GID)
	}
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	if !slices.IsSorted(f.h.st.FolderGIDs) || len(f.h.st.FolderGIDs) != 1000 {
		t.Errorf("folder_gids not kept sorted and complete")
	}
}

func TestCheckFolderPath(t *testing.T) {
	f, _, d := folderFixture(t)
	pc, err := f.h.CheckFolderPath(context.Background(), "/srv/new", false)
	if err != nil || pc.Exists || pc.Created || pc.Path != "/srv/new" || pc.Summary != "missing" {
		t.Fatalf("missing = %+v, %v", pc, err)
	}
	specs := f.engine.fx().Specs()
	if len(specs) != 1 || fixerMode(specs[0].Cmd) != "probe" || !specs[0].Binds[0].ReadOnly {
		t.Fatalf("runs = %v", fixerModes(f))
	}
	if _, c := argValue(specs[0].Cmd, "create"); c {
		t.Errorf("probe without create got --create: %v", specs[0].Cmd)
	}
	if d.paths["/srv/new"] != nil {
		t.Error("created without create")
	}
	pc, err = f.h.CheckFolderPath(context.Background(), "/srv/new", true)
	if err != nil || !pc.Exists || !pc.Created {
		t.Fatalf("create = %+v, %v", pc, err)
	}
	specs = f.engine.fx().Specs()
	if _, c := argValue(specs[1].Cmd, "create"); !c || specs[1].Binds[0].ReadOnly {
		t.Errorf("probe --create = %v %+v", specs[1].Cmd, specs[1].Binds)
	}
	pc, err = f.h.CheckFolderPath(context.Background(), "/srv/photos", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := "exists · ext4 · ACLs and xattrs supported · 12,410 files · owners 1000:1000 (all)"; pc.Summary != want {
		t.Errorf("summary = %q\nwant      %q", pc.Summary, want)
	}
	if pc.FSType != "ext4" || !pc.ACL || !pc.Xattr || pc.Files != 12410 || pc.Dirs != 312 || len(pc.Owners) != 1 || len(pc.Problems) != 0 {
		t.Errorf("check = %+v", pc)
	}
	b, _ := json.Marshal(pc)
	for _, k := range []string{`"path"`, `"exists"`, `"created"`, `"fs_type"`, `"acl"`, `"xattr"`, `"files"`, `"dirs"`, `"partial"`, `"owners"`, `"summary"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("JSON lacks %s: %s", k, b)
		}
	}
	// Mixed owners, no ACLs, a refused filesystem: its problem in words.
	e := d.add("/srv/nas", "nfs")
	e.acl = false
	e.owners = []folderfix.OwnerCount{{UID: 1000, GID: 1000, N: 12000}, {UID: 0, GID: 0, N: 723}}
	pc, err = f.h.CheckFolderPath(context.Background(), "/srv/nas", false)
	if err != nil || len(pc.Problems) != 1 || !strings.Contains(pc.Problems[0], "nfs") {
		t.Errorf("nfs = %+v, %v", pc, err)
	}
	if want := "exists · nfs · xattrs supported, no ACLs · 12,410 files · owners 1000:1000 (12,000), 0:0 (723)"; pc.Summary != want {
		t.Errorf("summary = %q\nwant      %q", pc.Summary, want)
	}
}

func TestDeleteFolderRefusedWhileUsed(t *testing.T) {
	f, _, _ := folderFixture(t)
	createFolder(t, f, "photos", "/srv/photos")
	f.h.mu.Lock()
	s := f.h.st.Settings["immich"]
	s.Values = map[string]any{"library": "folder:photos/2024"}
	f.h.st.Settings["immich"] = s
	f.h.mu.Unlock()
	runs := len(f.engine.fx().Specs())
	err := f.h.DeleteFolder("photos", "admin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "immich") {
		t.Errorf("used: %v", err)
	}
	vs := f.h.Folders()
	if len(vs) != 1 || len(vs[0].Uses) != 1 {
		t.Fatalf("folders = %+v", vs)
	}
	if u := vs[0].Uses[0]; u != (FolderUseView{Instance: "immich", Key: "library", Label: "Library", Subpath: "2024", Access: "read", ReadOnly: true}) {
		t.Errorf("use = %+v", u)
	}
	// A confirmed write on an undeclared template.
	f.h.mu.Lock()
	fo := f.h.st.Folders["photos"]
	fo.WriteConfirmed = map[string]bool{"immich/library": true}
	f.h.st.Folders["photos"] = fo
	f.h.mu.Unlock()
	if u := f.h.Folders()[0].Uses[0]; u.Access != "write" || u.ReadOnly {
		t.Errorf("confirmed write = %+v", u)
	}
	// An instance whose template is gone: still a use (fail closed).
	f.h.mu.Lock()
	f.h.st.Settings["immich"] = state.InstanceSettings{}
	f.h.st.Settings["gone"] = state.InstanceSettings{Values: map[string]any{"media": "folder:photos"}}
	f.h.mu.Unlock()
	if err := f.h.DeleteFolder("photos", "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "gone") {
		t.Errorf("template gone: %v", err)
	}
	f.h.mu.Lock()
	delete(f.h.st.Settings, "gone")
	// Another folder's ref and a non-path option's text don't count.
	f.h.st.Settings["immich"] = state.InstanceSettings{Values: map[string]any{"library": "folder:music", "version": "folder:photos"}}
	f.h.mu.Unlock()
	if err := f.h.DeleteFolder("nope", "admin"); statusOf(err) != 404 {
		t.Errorf("unknown: %v", err)
	}
	if err := f.h.DeleteFolder("photos", "admin"); err != nil {
		t.Fatalf("unused: %v", err)
	}
	if _, ok := storedFolder(f, "photos"); ok {
		t.Error("still stored")
	}
	if n := len(f.engine.fx().Specs()); n != runs {
		t.Errorf("delete ran the fixer (%d runs)", n-runs)
	}
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	if !slices.Equal(f.h.st.FolderGIDs, []int{60000}) {
		t.Errorf("gid freed: %v", f.h.st.FolderGIDs)
	}
}

func TestUpdateFolder(t *testing.T) {
	f, _, d := folderFixture(t)
	createFolder(t, f, "photos", "/srv/photos")
	before, _ := storedFolder(f, "photos")
	v, err := f.h.UpdateFolder(context.Background(), "photos", FolderInput{Name: "Family photos", Description: "since 2001"}, "admin")
	if err != nil || v.Name != "Family photos" || v.Description != "since 2001" || v.Path != "/srv/photos" || v.ID != "photos" {
		t.Fatalf("update = %+v, %v", v, err)
	}
	for name, in := range map[string]FolderInput{
		"id change":  {ID: "pics", Name: "P"},
		"no name":    {Name: ""},
		"long name":  {Name: strings.Repeat("n", 65)},
		"name lines": {Name: "a\nb"},
		"long desc":  {Name: "P", Description: strings.Repeat("d", 501)},
		"gid change": {Name: "P", GID: new(int)},
		"bad path":   {Name: "P", Path: "/etc/photos"},
	} {
		if _, err := f.h.UpdateFolder(context.Background(), "photos", in, "admin"); statusOf(err) != 400 {
			t.Errorf("%s: %v, want 400", name, err)
		}
	}
	if _, err := f.h.UpdateFolder(context.Background(), "nope", FolderInput{Name: "N"}, "admin"); statusOf(err) != 404 {
		t.Errorf("unknown: %v", err)
	}
	// A path change while used: 409.
	d.add("/srv/pictures", "ext4")
	f.h.mu.Lock()
	f.h.st.Settings["immich"] = state.InstanceSettings{Values: map[string]any{"library": "folder:photos"}}
	f.h.mu.Unlock()
	if _, err := f.h.UpdateFolder(context.Background(), "photos", FolderInput{Name: "P", Path: "/srv/pictures"}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "immich") {
		t.Errorf("path change while used: %v", err)
	}
	// Names may change while used.
	if _, err := f.h.UpdateFolder(context.Background(), "photos", FolderInput{Name: "Pics", Path: "/srv/photos/"}, "admin"); err != nil {
		t.Errorf("rename while used: %v", err)
	}
	f.h.mu.Lock()
	f.h.st.Settings["immich"] = state.InstanceSettings{}
	fo := f.h.st.Folders["photos"]
	fo.LastApply = &state.FolderApply{Files: "rw"}
	f.h.st.Folders["photos"] = fo
	f.h.mu.Unlock()
	runs := len(f.engine.fx().Specs())
	v, err = f.h.UpdateFolder(context.Background(), "photos", FolderInput{Name: "Pics", Path: "/srv/pictures"}, "admin")
	if err != nil || v.Path != "/srv/pictures" || v.ID != "photos" || v.GID != before.GID {
		t.Fatalf("path change = %+v, %v", v, err)
	}
	if m := fixerModes(f)[runs:]; !slices.Equal(m, []string{"probe", "scan"}) {
		t.Errorf("path change ran %v", m)
	}
	after, _ := storedFolder(f, "photos")
	if after.Ino != d.paths["/srv/pictures"].ino || after.MountRoot != "/srv/pictures" || after.LastApply != nil || !after.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf("after the path change = %+v", after)
	}
	// Overlap with another folder.
	d.add("/srv/pictures/raw", "ext4")
	d.add("/srv/other", "ext4")
	createFolder(t, f, "other", "/srv/other")
	if _, err := f.h.UpdateFolder(context.Background(), "other", FolderInput{Name: "O", Path: "/srv/pictures/raw"}, "admin"); statusOf(err) != 409 {
		t.Errorf("overlap: %v", err)
	}
}

func TestFolderAudit(t *testing.T) {
	f, audit, d := folderFixture(t)
	createFolder(t, f, "photos", "/srv/photos")
	if e := audit.last(); e.Action != "folder.create" || e.Target != "photos" || e.Detail != "gid=60000 path=/srv/photos" || e.Result != "ok" || e.Actor != "admin" {
		t.Errorf("create = %+v", e)
	}
	if _, err := f.h.UpdateFolder(context.Background(), "photos", FolderInput{Name: "Family"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "folder.update" || e.Target != "photos" || e.Result != "ok" || !strings.Contains(e.Detail, "name") {
		t.Errorf("update = %+v", e)
	}
	_, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "etc", Name: "E", Path: "/etc/x"}, "admin")
	if e := audit.last(); err == nil || e.Action != "folder.create" || e.Result != "refused" || e.Target != "etc" || e.Error == "" {
		t.Errorf("refused create = %+v", e)
	}
	d.symlinks["/srv/link"] = true
	f.h.CreateFolder(context.Background(), FolderInput{ID: "link", Name: "L", Path: "/srv/link"}, "admin")
	if e := audit.last(); e.Result != "refused" || !strings.Contains(e.Error, "symlink") {
		t.Errorf("refused symlink = %+v", e)
	}
	f.h.UpdateFolder(context.Background(), "photos", FolderInput{Name: ""}, "admin")
	if e := audit.last(); e.Action != "folder.update" || e.Result != "refused" {
		t.Errorf("refused update = %+v", e)
	}
	f.h.DeleteFolder("nope", "admin")
	if e := audit.last(); e.Action != "folder.delete" || e.Result != "refused" || e.Target != "nope" {
		t.Errorf("refused delete = %+v", e)
	}
	if err := f.h.DeleteFolder("photos", "admin"); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "folder.delete" || e.Target != "photos" || e.Result != "ok" || e.Detail != "gid=60000 path=/srv/photos" {
		t.Errorf("delete = %+v", e)
	}
	// The audit is written after mu is released: an auditor that takes
	// the Hub's lock doesn't deadlock.
	f.h.SetAudit(lockingAudit{f.h, audit})
	d.add("/srv/music", "ext4")
	createFolder(t, f, "music", "/srv/music")
	f.h.DeleteFolder("music", "admin")
}

// lockingAudit takes the Hub's lock in Append (deadlocks if called under mu).
type lockingAudit struct {
	h *Hub
	a *fakeAudit
}

func (l lockingAudit) Append(e directory.AuditEntry) error {
	l.h.mu.Lock()
	l.h.mu.Unlock()
	return l.a.Append(e)
}

func TestFolderHostPath(t *testing.T) {
	f, _, d := folderFixture(t)
	d.add("/srv/media", "ext4")
	createFolder(t, f, "photos", "/srv/media")
	f.h.mu.RLock()
	src := f.h.folders
	p, err := src.FolderHostPath("photos", "movies/hd")
	_, unknown := src.FolderHostPath("nope", "")
	_, escape := src.FolderHostPath("photos", "../x")
	root, _ := src.FolderHostPath("photos", "")
	f.h.mu.RUnlock()
	if err != nil || p != "/srv/media/movies/hd" || root != "/srv/media" {
		t.Errorf("FolderHostPath = %q %q, %v", p, root, err)
	}
	if unknown == nil || escape == nil {
		t.Errorf("unknown = %v, escape = %v", unknown, escape)
	}
	// P8: resolved under the caller's lock, also from PathUsages and the
	// settings save (which resolve outside a write lock), while folders
	// are created: no race (-race).
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	s := f.h.st.Settings["immich"]
	s.Values = map[string]any{"library": "folder:photos/x"}
	f.h.st.Settings["immich"] = s
	f.h.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			f.h.PathUsages()
			f.h.PreviewSettings(context.Background(), "immich", SettingsUpdate{Values: vals("library", "folder:photos/y")})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			id := fmt.Sprintf("f%d", i)
			d.add("/mnt/"+id, "ext4")
			createFolder(t, f, id, "/mnt/"+id)
		}
	}()
	wg.Wait()
	us := f.h.PathUsages()
	if len(us) == 0 || us[0].HostPath != "/srv/media/x" {
		t.Errorf("usages = %+v", us)
	}
}

// The save re-checks under mu what the probe and check ran without: a
// folder created meanwhile at an overlapping path, or adopting the same
// gid, wins; the loser is 409 and stores nothing.
func TestCreateFolderLostRace(t *testing.T) {
	f, _, d := folderFixture(t)
	d.add("/srv/photos/2026", "ext4")
	d.onScan = func(string) { createFolder(t, f, "year", "/srv/photos/2026") }
	_, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "photos", Name: "P", Path: "/srv/photos"}, "admin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "year") {
		t.Errorf("lost overlap race: %v", err)
	}
	if _, ok := storedFolder(f, "photos"); ok {
		t.Error("the loser was stored")
	}
	gid := 2000
	d.add("/srv/a", "ext4")
	d.add("/srv/b", "ext4")
	d.onScan = func(string) {
		g := gid
		if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "b", Name: "B", Path: "/srv/b", GID: &g}, "admin"); err != nil {
			t.Errorf("winner: %v", err)
		}
	}
	if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "a", Name: "A", Path: "/srv/a", GID: &gid}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "gid 2000") {
		t.Errorf("lost gid race: %v", err)
	}
	// The same id twice at once: the second is busy or exists.
	d.add("/srv/c", "ext4")
	d.onScan = func(string) {
		if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "c", Name: "C", Path: "/srv/c"}, "admin"); statusOf(err) != 409 {
			t.Errorf("same id meanwhile: %v", err)
		}
	}
	createFolder(t, f, "c", "/srv/c")
}

// A stored folder this configuration refuses stops the Hub at start (P24).
func TestFolderRefusedAtStart(t *testing.T) {
	f, _, _ := folderFixture(t)
	createFolder(t, f, "photos", "/srv/photos")
	cfg := f.h.cfg
	cfg.OverrideBindRoots = "/mnt"
	if _, err := New(cfg, f.runner, f.engine, f.idp); err == nil || !strings.Contains(err.Error(), "photos") {
		t.Errorf("New with /srv no longer a bind root = %v", err)
	}
	if _, err := New(f.h.cfg, f.runner, f.engine, f.idp); err != nil {
		t.Errorf("New = %v", err)
	}
}

// ── fix round 1 ──────────────────────────────────────────

// I1: one directory reached through two paths (a host bind mount, a
// case-insensitive filesystem) is one folder: the probed root's dev/ino
// equal to a stored folder's is 409, under mu.
func TestFolderSameDirectoryRefused(t *testing.T) {
	f, _, d := folderFixture(t)
	createFolder(t, f, "photos", "/srv/photos")
	orig := d.paths["/srv/photos"]
	alias := d.add("/mnt/alias", "ext4")
	alias.dev, alias.ino = orig.dev, orig.ino
	_, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "alias", Name: "A", Path: "/mnt/alias"}, "admin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "photos") {
		t.Errorf("same dev/ino: %v", err)
	}
	if _, ok := storedFolder(f, "alias"); ok {
		t.Error("stored")
	}
	// An update onto it too.
	d.add("/srv/other", "ext4")
	createFolder(t, f, "other", "/srv/other")
	if _, err := f.h.UpdateFolder(context.Background(), "other", FolderInput{Name: "O", Path: "/mnt/alias"}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "photos") {
		t.Errorf("update onto the same directory: %v", err)
	}
	// Its own directory again (a rename of the path that probes the
	// same inode) is no conflict with itself.
	self := d.add("/mnt/self", "ext4")
	o := d.paths["/srv/other"]
	self.dev, self.ino = o.dev, o.ino
	if _, err := f.h.UpdateFolder(context.Background(), "other", FolderInput{Name: "O", Path: "/mnt/self"}, "admin"); err != nil {
		t.Errorf("own inode: %v", err)
	}
}

// I1: the overlap and the core / data-files rules also compare a
// case-folded, NFC form (fail closed: an alias on a case-insensitive or
// normalising filesystem).
func TestFolderPathFolded(t *testing.T) {
	f, _, d := folderFixture(t)
	f.h.cfg.AppFilesHostDir = "/srv/data/appfiles"
	f.h.cfg.ProjectHostDir = "/srv/core"
	createFolder(t, f, "photos", "/srv/photos")
	d.add("/srv/café", "ext4")
	createFolder(t, f, "cafe", "/srv/café")
	for _, p := range []string{"/srv/Photos", "/srv/PHOTOS/2026", "/srv/café", "/srv/CAFÉ/x", "/srv/Straße"} {
		d.add(p, "ext4")
	}
	d.add("/srv/strasse", "ext4")
	createFolder(t, f, "strasse", "/srv/strasse")
	for _, p := range []string{"/srv/Photos", "/srv/PHOTOS/2026", "/srv/café", "/srv/CAFÉ/x", "/srv/Straße"} {
		if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "x", Name: "X", Path: p}, "admin"); statusOf(err) != 409 {
			t.Errorf("%q: %v, want 409 overlap", p, err)
		}
	}
	for _, p := range []string{"/srv/Data/AppFiles/x", "/srv/DATA", "/srv/Core/x", "/srv/CORE"} {
		if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "x", Name: "X", Path: p}, "admin"); statusOf(err) != 400 {
			t.Errorf("%q: %v, want 400", p, err)
		}
	}
	if len(foldPath("/srv/x")) == 0 || foldPath("/srv/Straße") != foldPath("/srv/strasse") || foldPath("/srv/café") != foldPath("/srv/café") {
		t.Errorf("foldPath")
	}
}

// I2: a state save that fails undoes the change in memory and is a 500.
func TestFolderSaveFailure(t *testing.T) {
	f, audit, d := folderFixture(t)
	createFolder(t, f, "photos", "/srv/photos")
	before, _ := storedFolder(f, "photos")
	breakState := func() {
		os.Remove(f.h.statePath())
		os.Mkdir(f.h.statePath(), 0o755)
	}
	fixState := func() { os.Remove(f.h.statePath()) }
	breakState()
	d.add("/srv/music", "ext4")
	if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "music", Name: "M", Path: "/srv/music"}, "admin"); statusOf(err) != 500 {
		t.Errorf("create = %v, want 500", err)
	}
	if e := audit.last(); e.Action != "folder.create" || e.Result != "error" {
		t.Errorf("audit = %+v", e)
	}
	f.h.mu.RLock()
	_, kept := f.h.st.Folders["music"]
	gids := slices.Clone(f.h.st.FolderGIDs)
	f.h.mu.RUnlock()
	if kept || !slices.Equal(gids, []int{60000}) {
		t.Errorf("after a failed create: kept %v, gids %v", kept, gids)
	}
	d.add("/srv/pictures", "ext4")
	if _, err := f.h.UpdateFolder(context.Background(), "photos", FolderInput{Name: "Renamed", Path: "/srv/pictures"}, "admin"); statusOf(err) != 500 {
		t.Errorf("update = %v, want 500", err)
	}
	if fo, _ := storedFolder(f, "photos"); !reflect.DeepEqual(fo, before) {
		t.Errorf("after a failed update: %+v", fo)
	}
	if err := f.h.DeleteFolder("photos", "admin"); statusOf(err) != 500 {
		t.Errorf("delete = %v, want 500", err)
	}
	if fo, ok := storedFolder(f, "photos"); !ok || !reflect.DeepEqual(fo, before) {
		t.Errorf("after a failed delete: %+v %v", fo, ok)
	}
	fixState()
	if v := createFolder(t, f, "music", "/srv/music"); v.GID != 60001 {
		t.Errorf("gid after the failure = %d", v.GID)
	}
}

// I3: Docker's data root (wherever the daemon has it) is no folder, nor
// anything at, above or under it; unreadable = 503.
func TestFolderDockerRootRefused(t *testing.T) {
	f, _, d := folderFixture(t)
	fx := f.engine.fx()
	fx.fmu.Lock()
	fx.dockerRoot = "/mnt/ssd/docker"
	fx.fmu.Unlock()
	for _, p := range []string{"/mnt/ssd/docker", "/mnt/ssd/docker/volumes/x", "/mnt/ssd", "/mnt/SSD"} {
		d.add(p, "ext4")
		if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "x", Name: "X", Path: p}, "admin"); statusOf(err) != 400 || !strings.Contains(err.Error(), "Docker") {
			t.Errorf("create %q: %v, want 400", p, err)
		}
		if _, err := f.h.CheckFolderPath(context.Background(), p, false); statusOf(err) != 400 {
			t.Errorf("check %q: %v, want 400", p, err)
		}
	}
	if n := len(fx.Specs()); n != 0 {
		t.Errorf("%d fixer runs", n)
	}
	createFolder(t, f, "photos", "/srv/photos")
	if _, err := f.h.UpdateFolder(context.Background(), "photos", FolderInput{Name: "P", Path: "/mnt/ssd/docker/x"}, "admin"); statusOf(err) != 400 {
		t.Errorf("update into it: %v", err)
	}
	fx.fmu.Lock()
	fx.dockerRoot, fx.rootErr = "", errors.New("daemon down")
	fx.fmu.Unlock()
	d.add("/srv/music", "ext4")
	if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "music", Name: "M", Path: "/srv/music"}, "admin"); statusOf(err) != 503 {
		t.Errorf("unreadable root: %v, want 503", err)
	}
	if _, err := f.h.CheckFolderPath(context.Background(), "/srv/music", false); statusOf(err) != 503 {
		t.Errorf("check, unreadable root: %v", err)
	}
	fx.fmu.Lock()
	fx.dockerRoot, fx.rootErr = "relative", nil
	fx.fmu.Unlock()
	if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "music", Name: "M", Path: "/srv/music"}, "admin"); statusOf(err) != 503 {
		t.Errorf("relative root: %v, want 503", err)
	}
}

// M4: check path never creates inside another folder.
func TestCheckFolderPathOverlapNoCreate(t *testing.T) {
	f, _, d := folderFixture(t)
	createFolder(t, f, "photos", "/srv/photos")
	pc, err := f.h.CheckFolderPath(context.Background(), "/srv/photos/2026", true)
	if err != nil || pc.Exists || pc.Created || len(pc.Problems) == 0 {
		t.Errorf("check = %+v, %v", pc, err)
	}
	specs := f.engine.fx().Specs()
	last := specs[len(specs)-1]
	if _, c := argValue(last.Cmd, "create"); c || !last.Binds[0].ReadOnly {
		t.Errorf("probe = %v %+v", last.Cmd, last.Binds)
	}
	if d.paths["/srv/photos/2026"] != nil {
		t.Error("created inside a folder")
	}
}

// M5: invisible and lookalike characters, and whitespace around a
// component, are refused; inner spaces are fine.
func TestFolderPathInvisibleRefused(t *testing.T) {
	f, _, d := folderFixture(t)
	for _, p := range []string{"/srv/photos\u200e", "/srv/photos\u200f", "/srv/photos\u061c", "/srv/pho\u200btos", "/srv/photos\ufeff",
		"/srv/photos\u00a0", "/srv/photos\u00a0x", "/srv/photos ", "/srv/ photos", "/srv/a /b", "/srv/\u3000a"} {
		if _, err := cleanFolderPath(p); statusOf(err) != 400 {
			t.Errorf("%q: %v, want 400", p, err)
		}
	}
	d.add("/srv/My Photos", "ext4")
	if v := createFolder(t, f, "mine", "/srv/My Photos"); v.Path != "/srv/My Photos" {
		t.Errorf("inner space: %+v", v)
	}
}

// M6: FolderInput decodes from the API's snake_case JSON (contract §14.8).
func TestFolderInputJSON(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(`{"id":"photos","name":"P","path":"/srv/photos","description":"d","gid":1000,"create":true}`))
	dec.DisallowUnknownFields()
	var in FolderInput
	if err := dec.Decode(&in); err != nil || in.ID != "photos" || in.Name != "P" || in.Path != "/srv/photos" || in.Description != "d" || in.GID == nil || *in.GID != 1000 || !in.Create {
		t.Errorf("decoded %+v, %v", in, err)
	}
	b, _ := json.Marshal(in)
	if want := `{"id":"photos","name":"P","path":"/srv/photos","description":"d","gid":1000,"create":true}`; string(b) != want {
		t.Errorf("encoded %s\nwant    %s", b, want)
	}
}

// M7: the Hub refuses every filesystem folderfix.Unsupported names,
// 9p, virtiofs, ceph, ramfs and ecryptfs included.
func TestFolderRefusedFilesystems(t *testing.T) {
	f, _, d := folderFixture(t)
	for fs := range folderfix.Unsupported {
		if refusedFS[fs] == "" {
			t.Errorf("%s has no reason", fs)
		}
	}
	for _, fs := range []string{"9p", "virtiofs", "ceph", "ramfs", "ecryptfs"} {
		d.add("/srv/"+fs, fs)
		if _, _, err := f.h.CreateFolder(context.Background(), FolderInput{ID: "f" + fs, Name: fs, Path: "/srv/" + fs}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), fs) {
			t.Errorf("%s: %v", fs, err)
		}
	}
}
