package hub

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/state"
)

// Task 11: scan targets, scheduled and on-demand disk scans, the scan
// cache and the runtime gid check (contract §14.5).

// scanFixture: the assign fixture (folders media /srv/media, docs
// /srv/docs) with Users & Groups, immich, nas, arr and samba enabled in
// state, hand-typed paths: /srv/shared (immich extra + nas data: two uses),
// /srv/photos (immich library: one reader), /opt/elsewhere (samba share:
// outside the bind roots), /srv/dl and /srv/dl/media (arr: nested).
func scanFixture(t *testing.T) (*fixture, *assignDisk) {
	t.Helper()
	f, d, _ := assignFixture(t)
	f.h.SetPeople(newFakePeople())
	enableQuiet(f, "immich", "nas", "arr", "samba")
	setStored(f, "immich", "extra", "/srv/shared", "library", "/srv/photos")
	setStored(f, "nas", "data", "/srv/shared")
	setStored(f, "samba", "share", "/opt/elsewhere")
	setStored(f, "arr", "downloads", "/srv/dl", "media", "/srv/dl/media")
	for _, p := range []string{"/srv/shared", "/srv/photos", "/srv/dl", "/srv/dl/media"} {
		d.add(p, "ext4")
	}
	// Saved: a reopened Hub (restart tests) sees the same setup.
	f.h.mu.Lock()
	err := f.h.saveStateLocked()
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return f, d
}

// reopenInit is a restarted Hub with its catalog loaded.
func reopenInit(t *testing.T, f *fixture) *Hub {
	t.Helper()
	h := reopen(t, f)
	h.Init()
	h.Wait()
	h.SetPeople(newFakePeople())
	return h
}

func waitDoctorOp(t *testing.T, h *Hub) *OpRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r := h.LastOp(opKeyDoctor); r != nil && !r.Running {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("doctor scan still running")
	return nil
}

func TestScanTargets(t *testing.T) {
	f, _ := scanFixture(t)
	f.h.mu.RLock()
	ts := f.h.scanTargetsLocked()
	f.h.mu.RUnlock()
	var got []string
	for _, x := range ts {
		got = append(got, x.Path+"|"+x.Folder)
	}
	want := []string{"/srv/dl|", "/srv/docs|docs", "/srv/media|media", "/srv/shared|"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	byPath := map[string]ScanTarget{}
	for _, x := range ts {
		byPath[x.Path] = x
	}
	// /srv/shared: nas (runs_as 3000:3000, writes); immich's extra has no
	// declared owner, so it is no principal.
	if p := byPath["/srv/shared"].Principals; len(p) != 1 || p[0].Name != "nas" || p[0].UID != 3000 || !p[0].Write || !slices.Contains(p[0].GIDs, 3000) {
		t.Errorf("/srv/shared principals = %+v", p)
	}
	// Nested: one target, the outer path's own use judged.
	if p := byPath["/srv/dl"].Principals; len(p) != 1 || p[0].Name != "arr" || p[0].UID != 1000 {
		t.Errorf("/srv/dl principals = %+v", p)
	}
	if byPath["/srv/media"].Target != nil {
		t.Errorf("a never-applied folder has no target: %+v", byPath["/srv/media"].Target)
	}
}

// A folder with a last apply is scanned against it; its uses are principals.
func TestScanTargetsFolderUses(t *testing.T) {
	f, _, _ := assignFixture(t)
	enableQuiet(f, "nas")
	setStored(f, "nas", "data", "folder:media")
	owner := 3000
	f.h.mu.Lock()
	m := f.h.st.Folders["media"]
	m.LastApply = &state.FolderApply{At: time.Now(), Files: "rw", OwnerUID: &owner}
	f.h.st.Folders["media"] = m
	f.h.mu.Unlock()
	f.h.mu.RLock()
	ts := f.h.scanTargetsLocked()
	f.h.mu.RUnlock()
	var media ScanTarget
	for _, x := range ts {
		if x.Folder == "media" {
			media = x
		}
	}
	if media.Target == nil || media.Target.GID != 60001 || media.Target.Files != "rw" || *media.Target.OwnerUID != 3000 {
		t.Fatalf("target = %+v", media.Target)
	}
	if len(media.Principals) != 1 || media.Principals[0].Name != "nas" || !slices.Contains(media.Principals[0].GIDs, 60001) || !media.Principals[0].Write {
		t.Errorf("principals = %+v", media.Principals)
	}
}

func TestScanAfterApply(t *testing.T) {
	f, _, _ := assignFixture(t)
	enable(t, f, "immich")
	before := time.Now().Add(-time.Second)
	if _, rec := assign(t, f, "media", AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}}); !rec.OK {
		t.Fatalf("assign: %+v", rec)
	}
	e, ok := f.h.scanCache()["/srv/media"]
	if !ok || e.Folder != "media" || e.Report == nil || e.Report.Expected == nil || e.At.Before(before) {
		t.Fatalf("cache entry = %+v (ok %t)", e, ok)
	}
	// The folder view shows it.
	for _, v := range f.h.Folders() {
		if v.ID == "media" && (v.LastCheck == nil || !v.LastCheck.At.Equal(e.At)) {
			t.Errorf("last_check = %+v", v.LastCheck)
		}
	}
}

func TestDoctorScanBusy(t *testing.T) {
	f, d := scanFixture(t)
	entered, gate := make(chan struct{}, 1), make(chan struct{})
	f.engine.fx().run = func(s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
		if fixerMode(s.Cmd) == "scan" {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-gate
		}
		return d.run(s, out)
	}
	if _, err := f.h.StartDoctorScan("admin"); err != nil {
		t.Fatal(err)
	}
	<-entered
	if _, err := f.h.StartDoctorScan("admin"); errStatus(err) != 409 {
		t.Errorf("second scan: %v", err)
	}
	close(gate)
	if r := waitDoctorOp(t, f.h); !r.OK {
		t.Fatalf("op = %+v", r)
	}
	// Free again.
	if _, err := f.h.StartDoctorScan("admin"); err != nil {
		t.Errorf("third scan: %v", err)
	}
	waitDoctorOp(t, f.h)
}

func TestDoctorScanNeedsDirectory(t *testing.T) {
	f, _ := scanFixture(t)
	f.h.SetPeople(nil)
	if _, err := f.h.StartDoctorScan("admin"); errStatus(err) != 503 {
		t.Errorf("err = %v", err)
	}
}

func TestScanCacheSurvivesRestart(t *testing.T) {
	f, _ := scanFixture(t)
	if _, err := f.h.StartDoctorScan("admin"); err != nil {
		t.Fatal(err)
	}
	if r := waitDoctorOp(t, f.h); !r.OK {
		t.Fatalf("op = %+v", r)
	}
	c1 := f.h.scanCache()
	if len(c1) != 4 {
		t.Fatalf("cache = %v", c1)
	}
	st, err := os.Stat(filepath.Join(f.data, "doctor", "scans.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("scans.json: %v %v", st, err)
	}
	h2 := reopenInit(t, f)
	c2 := h2.scanCache()
	if len(c2) != len(c1) {
		t.Fatalf("after restart: %v", c2)
	}
	for k, a := range c1 {
		b := c2[k]
		if !a.At.Equal(b.At) || a.Folder != b.Folder || (a.Report == nil) != (b.Report == nil) || (a.Report != nil && a.Report.Entries != b.Report.Entries) {
			t.Errorf("%s: %+v vs %+v", k, a, b)
		}
	}
	r1, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := h2.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Scans) != 4 || len(r1.Scans) != 4 {
		t.Fatalf("scans %v / %v", r1.Scans, r2.Scans)
	}
	for i := range r1.Scans {
		if r1.Scans[i].Target != r2.Scans[i].Target || !r1.Scans[i].At.Equal(r2.Scans[i].At) {
			t.Errorf("scan %d: %+v vs %+v", i, r1.Scans[i], r2.Scans[i])
		}
	}
}

func TestScanCacheCorrupt(t *testing.T) {
	f, _ := scanFixture(t)
	dir := filepath.Join(f.data, "doctor")
	os.MkdirAll(dir, 0o700)
	for _, junk := range []string{"{not json", `{"version":99,"scans":{}}`, `{"version":1,"scans":{"/srv/x":{"target":"/elsewhere"}}}`} {
		os.WriteFile(filepath.Join(dir, "scans.json"), []byte(junk), 0o600)
		h2 := reopen(t, f)
		if c := h2.scanCache(); len(c) != 0 {
			t.Errorf("%q: cache = %v", junk, c)
		}
		if !h2.lastFullScan().IsZero() {
			t.Errorf("%q: a corrupt cache must mean a rescan", junk)
		}
	}
	// A rescan rewrites it.
	h2 := reopenInit(t, f)
	h2.runDoctorScan(context.Background())
	h3 := reopen(t, f)
	if len(h3.scanCache()) != 4 || h3.lastFullScan().IsZero() {
		t.Errorf("after the rescan: %v", h3.scanCache())
	}
}

// The cache stays bounded: entries beyond the cap go (the oldest), and a
// file over the byte cap loses the reports' sample paths first.
func TestScanCacheBounded(t *testing.T) {
	f, _ := scanFixture(t)
	big := func() *folderfix.Report {
		r := &folderfix.Report{Version: 1, Mode: "scan"}
		for _, c := range []*folderfix.Count{&r.HardLinks, &r.MountPoints, &r.Specials, &r.Symlinks, &r.SetID, &r.Races, &r.BadACL, &r.Failed} {
			c.N = 20
			for i := 0; i < 20; i++ {
				c.Sample = append(c.Sample, strings.Repeat("x", 200))
			}
		}
		return r
	}
	h := f.h
	h.scanCacheMu.Lock()
	sf := h.scanFileLocked()
	t0 := time.Now().UTC()
	for i := 0; i < 600; i++ {
		p := "/srv/t" + strconv.Itoa(i)
		sf.Scans[p] = scanEntry{Target: p, At: t0.Add(time.Duration(i) * time.Second), Report: big()}
	}
	h.saveScanFileLocked(sf)
	h.scanCacheMu.Unlock()
	st, err := os.Stat(filepath.Join(f.data, "doctor", "scans.json"))
	if err != nil || st.Size() > maxScanCacheBytes {
		t.Fatalf("size %v (max %d): %v", st, maxScanCacheBytes, err)
	}
	c := reopen(t, f).scanCache()
	if len(c) != maxScanCacheEntries {
		t.Fatalf("%d entries", len(c))
	}
	if _, ok := c["/srv/t0"]; ok {
		t.Error("the oldest entry was kept")
	}
	e := c["/srv/t599"]
	if e.Report == nil || e.Report.HardLinks.N != 20 || e.Report.HardLinks.Sample != nil {
		t.Errorf("newest entry = %+v", e.Report)
	}
}

func TestScanRunsReadOnlyWithCaps(t *testing.T) {
	f, d := scanFixture(t)
	f.h.runDoctorScan(context.Background())
	var folderScan, pathScan []string
	for _, s := range f.engine.fx().Specs() {
		if fixerMode(s.Cmd) != "scan" {
			continue
		}
		if !s.Binds[0].ReadOnly || !reflect.DeepEqual(s.CapAdd, []string{"DAC_READ_SEARCH"}) {
			t.Errorf("scan spec: bind %+v caps %v", s.Binds[0], s.CapAdd)
		}
		switch s.Binds[0].Source {
		case "/srv/media":
			folderScan = s.Cmd
		case "/srv/shared":
			pathScan = s.Cmd
		}
	}
	for _, cmd := range [][]string{folderScan, pathScan} {
		if v, _ := argValue(cmd, "max-entries"); v != "2000000" {
			t.Errorf("%v: max-entries %q", cmd, v)
		}
		if v, _ := argValue(cmd, "max-time"); v != "10m0s" {
			t.Errorf("%v: max-time %q", cmd, v)
		}
		for _, fl := range []string{"expect-dev", "expect-ino"} {
			if _, ok := argValue(cmd, fl); !ok {
				t.Errorf("%v without --%s", cmd, fl)
			}
		}
	}
	if v, _ := argValue(folderScan, "expect-mount-root"); v != "/srv/media" {
		t.Errorf("folder scan mount root %q", v)
	}
	if p, _ := argValue(pathScan, "principal"); p != "nas:3000:3000:w" {
		t.Errorf("path scan principal %q", p)
	}
	// The hand-typed target was probed before it was bound.
	probed := false
	for _, s := range f.engine.fx().Specs() {
		if fixerMode(s.Cmd) == "probe" {
			if rel, _ := argValue(s.Cmd, "rel"); rel == "shared" && s.Binds[0].Source == "/srv" && s.Binds[0].ReadOnly {
				probed = true
			}
		}
	}
	if !probed {
		t.Error("no read-only probe of /srv/shared")
	}
	_ = d
}

func TestHandTypedTargetRefused(t *testing.T) {
	f, d := scanFixture(t)
	d.fakeDisk.mu.Lock()
	d.symlinks["/srv/shared"] = true
	d.paths["/srv/dl"].mountRoot = "/elsewhere"
	d.fakeDisk.mu.Unlock()
	f.h.runDoctorScan(context.Background())
	for _, s := range f.engine.fx().Specs() {
		if fixerMode(s.Cmd) == "scan" && s.Binds[0].Source == "/srv/shared" {
			t.Error("a symlinked target was bound")
		}
	}
	c := f.h.scanCache()
	if e := c["/srv/shared"]; e.Report != nil || !strings.Contains(e.Err, "symlink") {
		t.Errorf("/srv/shared = %+v", e)
	}
	if e := c["/srv/dl"]; e.Report != nil || !strings.Contains(e.Err, "mount root") {
		t.Errorf("/srv/dl = %+v", e)
	}
	// The others continued.
	if e := c["/srv/media"]; e.Report == nil {
		t.Errorf("/srv/media = %+v", e)
	}
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range r.Findings {
		if x.Kind == doctor.KindScanFailed {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d scan_failed findings", n)
	}
}

func TestScheduledScanSkipsBusyFolder(t *testing.T) {
	f, _ := scanFixture(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.h.putScan(scanEntry{Target: "/srv/media", Folder: "media", At: t0, Report: &folderfix.Report{Version: 1, Mode: "scan"}})
	unlock, err := f.h.folderLock("media")
	if err != nil {
		t.Fatal(err)
	}
	_, warns := f.h.runDoctorScan(context.Background())
	unlock()
	c := f.h.scanCache()
	if !c["/srv/media"].At.Equal(t0) {
		t.Errorf("busy folder rescanned: %+v", c["/srv/media"])
	}
	if c["/srv/docs"].Report == nil || c["/srv/docs"].At.Equal(t0) {
		t.Errorf("docs not scanned: %+v", c["/srv/docs"])
	}
	if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "Family media") && strings.Contains(w, "busy") }) {
		t.Errorf("warnings = %v", warns)
	}
}

func TestRuntimeGIDCheck(t *testing.T) {
	f, _ := scanFixture(t)
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{
		container("c-nas", "portcullis-nas", "nas", "running"),
		container("c-arr", "portcullis-arr", "arr", "exited"),
	}
	f.engine.fixer.inspect["c-nas"] = docker.ContainerInfo{ID: "c-nas"}
	var calls [][]string
	f.engine.execFn = func(id string, cmd []string) (*docker.ExecResult, error) {
		calls = append(calls, append([]string{id}, cmd...))
		if cmd[0] == "ls" {
			return &docker.ExecResult{Output: []byte("1\n7\nself\nnet\n"), ExitCode: 0}, nil
		}
		return &docker.ExecResult{Output: []byte("Name:\ts6\nGid:\t0\t0\t0\t0\nGroups:\t0 \nName:\tapp\nGid:\t3000\t3000\t3000\t3000\nGroups:\t3000 60002 \ncat: /proc/9/status: No such file\n"), ExitCode: 1}, nil
	}
	f.engine.mu.Unlock()
	f.h.runDoctorScan(context.Background())
	f.engine.mu.Lock()
	got := slices.Clone(calls)
	f.engine.mu.Unlock()
	want := [][]string{{"c-nas", "ls", "/proc"}, {"c-nas", "cat", "/proc/1/status", "/proc/7/status"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("execs = %v", got)
	}
	rt := f.h.scanRuntime()
	if len(rt) != 1 || rt[0].Instance != "nas" || rt[0].Service != "nas" || !reflect.DeepEqual(rt[0].GIDs, []int{0, 3000, 60002}) {
		t.Fatalf("runtime = %+v", rt)
	}
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range r.Findings {
		if x.Kind == doctor.KindGIDCollision && x.FP == doctor.Fingerprint(doctor.KindGIDCollision, "nas", "docs") && x.Severity == doctor.Problem {
			found = true
		}
	}
	if !found {
		t.Errorf("no runtime gid_collision: %+v", r.Findings)
	}
	// Survives a restart with the scans.
	if rt := reopenInit(t, f).scanRuntime(); len(rt) != 1 {
		t.Errorf("runtime after restart = %+v", rt)
	}
}

func TestContainerGIDsFallback(t *testing.T) {
	f, _ := scanFixture(t)
	f.engine.mu.Lock()
	var calls [][]string
	f.engine.execFn = func(id string, cmd []string) (*docker.ExecResult, error) {
		calls = append(calls, cmd)
		if cmd[0] == "ls" {
			return &docker.ExecResult{Output: []byte("exec: ls: not found"), ExitCode: 127}, nil
		}
		return &docker.ExecResult{Output: []byte("Gid:\t5\t5\t5\t5\nGroups:\t60001\n"), ExitCode: 0}, nil
	}
	f.engine.mu.Unlock()
	gids, err := f.h.containerGIDs(context.Background(), "c")
	if err != nil || !reflect.DeepEqual(gids, []int{5, 60001}) {
		t.Errorf("gids %v err %v", gids, err)
	}
	if len(calls) != 2 || !reflect.DeepEqual(calls[1], []string{"cat", "/proc/1/status"}) {
		t.Errorf("calls = %v", calls)
	}
	// Nothing readable: an error, no gids.
	f.engine.mu.Lock()
	f.engine.execFn = func(id string, cmd []string) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte("not found"), ExitCode: 127}, nil
	}
	f.engine.mu.Unlock()
	if _, err := f.h.containerGIDs(context.Background(), "c"); err == nil {
		t.Error("no error")
	}
}

func TestRunDoctorScansStops(t *testing.T) {
	f, _ := scanFixture(t)
	f.h.scanStartDelay = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); f.h.RunDoctorScans(ctx, time.Hour) }()
	deadline := time.Now().Add(10 * time.Second)
	for f.h.lastFullScan().IsZero() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.h.lastFullScan().IsZero() {
		t.Fatal("no scheduled scan ran")
	}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunDoctorScans didn't stop")
	}
}

// ── fix round 1 ─────────────────────────────────────────

// I1: on-demand scans are audited doctor.scan (refusals "refused", the
// counts in the detail, written after the locks are released).
func TestDoctorScanAudited(t *testing.T) {
	f, d := scanFixture(t)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	if _, err := f.h.StartDoctorScan(""); errStatus(err) != 401 {
		t.Fatalf("no actor: %v", err)
	}
	f.h.SetPeople(nil)
	if _, err := f.h.StartDoctorScan("admin"); errStatus(err) != 503 {
		t.Fatalf("no directory: %v", err)
	}
	f.h.SetPeople(newFakePeople())
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	var unlocked sync.Once
	f.engine.fx().run = func(s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
		if fixerMode(s.Cmd) == "scan" {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-gate
		}
		return d.run(s, out)
	}
	if _, err := f.h.StartDoctorScan("admin"); err != nil {
		t.Fatal(err)
	}
	<-entered
	if _, err := f.h.StartDoctorScan("admin"); errStatus(err) != 409 {
		t.Fatalf("busy: %v", err)
	}
	unlocked.Do(func() { close(gate) })
	waitDoctorOp(t, f.h)
	// The entry is written after scanMu is released.
	deadline := time.Now().Add(5 * time.Second)
	for len(auditOf(audit, "doctor.scan")) < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := auditOf(audit, "doctor.scan")
	want := []string{"disks refused ", "disks refused ", "disks refused ", "disks ok targets=4 scanned=4 failed=0 skipped=0 containers=0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("audit = %q", got)
	}
	if !f.h.scanMu.TryLock() {
		t.Error("scanMu still held")
	} else {
		f.h.scanMu.Unlock()
	}
}

// I2: a pid: host container's /proc is the host's: never read, an Info.
func TestRuntimePidHostSkipped(t *testing.T) {
	f, _ := scanFixture(t)
	f.engine.fixer.inspect["c-nas"] = docker.ContainerInfo{ID: "c-nas", PidMode: "host"}
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{container("c-nas", "portcullis-nas", "nas", "running")}
	n := 0
	f.engine.execFn = func(id string, cmd []string) (*docker.ExecResult, error) { n++; return &docker.ExecResult{}, nil }
	f.engine.mu.Unlock()
	f.h.runDoctorScan(context.Background())
	f.engine.mu.Lock()
	calls := n
	f.engine.mu.Unlock()
	if calls != 0 {
		t.Errorf("%d execs into a pid: host container", calls)
	}
	rt := f.h.scanRuntime()
	if len(rt) != 1 || rt[0].GIDs != nil || !strings.Contains(rt[0].Err, "host's processes") {
		t.Fatalf("runtime = %+v", rt)
	}
	assertSkippedInfo(t, f, "nas")
}

func assertSkippedInfo(t *testing.T, f *fixture, inst string) {
	t.Helper()
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range r.Findings {
		if x.Kind == doctor.KindGIDCollision && x.Severity == doctor.Info && strings.HasPrefix(x.Title, "Group check skipped for "+inst) {
			return
		}
	}
	t.Errorf("no 'group check skipped' Info for %s: %+v", inst, r.Findings)
}

// I4: an unreadable container (no cat, a failed exec, a failed inspect)
// is an Info finding.
func TestRuntimeUnreadableRecorded(t *testing.T) {
	f, _ := scanFixture(t)
	f.engine.fixer.inspect["c-nas"] = docker.ContainerInfo{ID: "c-nas"}
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{container("c-nas", "portcullis-nas", "nas", "running"), container("c-arr", "portcullis-arr", "arr", "running")}
	f.engine.execFn = func(id string, cmd []string) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte("exec: not found"), ExitCode: 127}, nil
	}
	f.engine.mu.Unlock()
	f.h.runDoctorScan(context.Background())
	rt := f.h.scanRuntime()
	if len(rt) != 2 {
		t.Fatalf("runtime = %+v", rt)
	}
	for _, r := range rt {
		switch r.Instance {
		case "nas":
			if !strings.Contains(r.Err, "no process status readable") {
				t.Errorf("nas: %+v", r)
			}
		case "arr": // not inspectable
			if !strings.Contains(r.Err, "inspect") {
				t.Errorf("arr: %+v", r)
			}
		}
	}
	assertSkippedInfo(t, f, "nas")
	assertSkippedInfo(t, f, "arr")
}

// M8: a container whose previous gid exec timed out and still runs is
// skipped (and said) until it ended.
func TestHungGIDExecSkipped(t *testing.T) {
	f, _ := scanFixture(t)
	f.engine.fixer.inspect["c-nas"] = docker.ContainerInfo{ID: "c-nas"}
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{container("c-nas", "portcullis-nas", "nas", "running")}
	n := 0
	f.engine.execFn = func(id string, cmd []string) (*docker.ExecResult, error) {
		n++
		return &docker.ExecResult{ExitCode: -1, TimedOut: true, ExecID: "e-" + cmd[0]}, nil
	}
	f.engine.mu.Unlock()
	f.h.runDoctorScan(context.Background())
	if rt := f.h.scanRuntime(); len(rt) != 1 || !strings.Contains(rt[0].Err, "timed out") {
		t.Fatalf("first run: %+v", rt)
	}
	f.engine.setExecRunning("e-cat", true)
	f.engine.mu.Lock()
	n0 := n
	f.engine.mu.Unlock()
	f.h.runDoctorScan(context.Background())
	f.engine.mu.Lock()
	n1 := n
	f.engine.mu.Unlock()
	if n1 != n0 {
		t.Errorf("exec'd again while the previous one runs (%d → %d)", n0, n1)
	}
	if rt := f.h.scanRuntime(); len(rt) != 1 || !strings.Contains(rt[0].Err, "still running") {
		t.Fatalf("second run: %+v", rt)
	}
	// Once it ended, the container is read again.
	f.engine.setExecRunning("e-cat", false)
	f.h.runDoctorScan(context.Background())
	f.engine.mu.Lock()
	n2 := n
	f.engine.mu.Unlock()
	if n2 == n1 {
		t.Error("not read again after the hung exec ended")
	}
}

// I3: the apply's verify scan judges the folder's uses as the apply
// leaves them, and the cache keeps them.
func TestVerifyScanCarriesPrincipals(t *testing.T) {
	f, d, _ := assignFixture(t)
	enable(t, f, "nas")
	if _, rec := assign(t, f, "media", AssignRequest{Uses: []FolderUse{{Instance: "nas", Key: "data"}}}); !rec.OK {
		t.Fatalf("assign: %+v", rec)
	}
	if p, _ := argValue(d.Argv("scan"), "principal"); p != "nas:3000:3000,60001:w" {
		t.Errorf("verify scan principal %q (%v)", p, d.Argv("scan"))
	}
	e := f.h.scanCache()["/srv/media"]
	if len(e.Principals) != 1 || e.Principals[0].Name != "nas" || !e.Principals[0].Write {
		t.Errorf("cached principals = %+v", e.Principals)
	}
}

// M6: a cached scan of a folder whose root is now another directory
// (deleted and re-created with the same id and path) is not judged.
func TestCacheMatchesFolderDevIno(t *testing.T) {
	f, _ := scanFixture(t)
	f.h.runDoctorScan(context.Background())
	f.h.mu.Lock()
	m := f.h.st.Folders["media"]
	m.Ino++
	f.h.st.Folders["media"] = m
	f.h.mu.Unlock()
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Scans {
		if s.Target == "/srv/media" {
			t.Errorf("stale scan judged: %+v", s)
		}
	}
	for _, v := range f.h.Folders() {
		if v.ID == "media" && v.LastCheck != nil {
			t.Errorf("last_check of another directory: %+v", v.LastCheck)
		}
	}
}
