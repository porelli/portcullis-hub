package hub

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/state"
)

// Task 8: previewed folder assignment (contract §14.3), snapshots and
// undo (§14.4), recovery.

// folderApp is a header-auth multi template named name (router id) with
// options (indented YAML list items) and services (the router's service
// first).
func folderApp(name, id, options, svc, extraServices string) [2]string {
	m := "name: " + name + "\ncategory: media\ninstances: multi\nauth:\n  method: header-auth\n  group_access: true\n" +
		"  access_group: users_" + id + "\n  admin_group: admin_" + id + "\nurls:\n  - label: Web\n    url: \"https://{{HOST_" + strings.ToUpper(id) + "}}\"\n" +
		"settings:\n  options:\n" + options
	c := "services:\n" + svc +
		"    labels:\n" +
		"      traefik.enable: \"true\"\n" +
		"      traefik.http.routers." + id + ".rule: Host(`${PORTCULLIS_HOST_" + strings.ToUpper(id) + ":-" + id + ".portcullis.local}`)\n" +
		"      traefik.http.routers." + id + ".entrypoints: websecure\n" +
		"      traefik.http.routers." + id + ".middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
		"      traefik.http.services." + id + ".loadbalancer.server.port: \"8080\"\n" + extraServices
	return [2]string{m, c}
}

var assignTemplates = map[string][2]string{
	"immich": folderApp("Immich", "immich", `    - key: library
      label: Library
      type: path
      target: {service: server, mount: /library}
      folder: {access: read, runs_as: {uid: 0, gid: 0}}
      applies: restart
    - key: extra
      label: Extra
      type: path
      target: {service: server, mount: /extra}
      applies: restart
    - key: workers
      label: Workers
      type: int
      default: 2
      delivery: [{env: WORKERS}]
`, "  server:\n    image: immich\n    environment:\n      WORKERS: ${WORKERS}\n", ""),
	"samba": folderApp("Samba", "samba", `    - key: share
      label: Share
      type: path
      target: {service: samba, mount: /share}
      folder: {access: write, runs_as: {uid: 2000, gid: 2000}, must_own: true}
      applies: restart
`, "  samba:\n    image: samba\n    user: \"2000:2000\"\n", ""),
	"nas": folderApp("NAS", "nas", `    - key: data
      label: Data
      type: path
      target: {service: nas, mount: /data}
      folder: {access: write, runs_as: {uid: 3000, gid: 3000}, must_own: true}
      applies: restart
`, "  nas:\n    image: nas\n    user: \"3000:3000\"\n", ""),
	"arr": folderApp("Arr", "arr", `    - key: puid
      label: User id
      type: int
      default: 1000
      delivery: [{env: PUID}]
    - key: pgid
      label: Group id
      type: int
      default: 1000
      delivery: [{env: PGID}]
    - key: downloads
      label: Downloads
      type: path
      target: {service: arr, mount: /downloads}
      folder: {access: write, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}
      applies: restart
    - key: media
      label: Media
      type: path
      target: {service: arr, mount: /media}
      folder: {access: write, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}
      applies: restart
`, "  arr:\n    image: arr\n    user: \"${PUID:-1000}:${PGID:-1000}\"\n", ""),
}

// assignDisk extends fakeDisk with snapshot, apply and restore runs and
// plans on target scans. events records every fixer run's mode and the
// compose ups and downs, in order.
type assignDisk struct {
	*fakeDisk
	amu       sync.Mutex
	events    []string
	last      string
	acl       bool
	lose      int64
	verifyBad int64
	applyExit int
	restore   folderfix.Report
	// restored: a (non dry-run) restore ran; leftAfter is what a dry run
	// still finds to rewrite after it (R56 verify).
	restored  bool
	leftAfter int64
	// races: per run ("scan", "verify", "snapshot", "apply", "restore",
	// "restore-dry") the races the report carries.
	races map[string]int64
	// snapHeader, if set, rewrites a snapshot header's gid, files, owner.
	snapHeader func(gid, files, owner string) (string, string, string)
	// applyGate, if set, blocks the apply until closed; applyEntered
	// receives once it started.
	applyGate    chan struct{}
	applyEntered chan struct{}
	// argv of the last run of each mode.
	argv map[string][]string
}

func (d *assignDisk) log(e string) {
	d.amu.Lock()
	defer d.amu.Unlock()
	d.events = append(d.events, e)
}

func (d *assignDisk) Events() []string {
	d.amu.Lock()
	defer d.amu.Unlock()
	return slices.Clone(d.events)
}

func (d *assignDisk) Argv(mode string) []string {
	d.amu.Lock()
	defer d.amu.Unlock()
	return d.argv[mode]
}

func (d *assignDisk) entry(src string) *diskPath {
	d.fakeDisk.mu.Lock()
	defer d.fakeDisk.mu.Unlock()
	return d.paths[src]
}

func (d *assignDisk) plan(e *diskPath) *folderfix.PlanCounts {
	n := e.files + e.dirs + 1
	return &folderfix.PlanCounts{Changes: n, Digest: strings.Repeat("ab", 32), ChangeGroup: folderfix.Count{N: n},
		AddSetgid: folderfix.Count{N: e.dirs + 1}, AddDefaultACL: folderfix.Count{N: e.dirs + 1},
		KeepGroup: map[int]int64{1000: n}, KeepUser: map[int]int64{}, LoseAccess: folderfix.Count{N: d.lose}}
}

func (d *assignDisk) racesOf(run string) folderfix.Count {
	d.amu.Lock()
	defer d.amu.Unlock()
	if n := d.races[run]; n > 0 {
		return folderfix.Count{N: n, Sample: []string{run + "/x"}}
	}
	return folderfix.Count{}
}

func reply(rep any, exit int) (*docker.RunResult, error) {
	b, _ := json.Marshal(rep)
	return &docker.RunResult{ExitCode: exit, Stdout: append(b, '\n')}, nil
}

func (d *assignDisk) run(s docker.RunSpec, out func(io.Reader) error) (*docker.RunResult, error) {
	mode := fixerMode(s.Cmd)
	ev := mode
	if _, dry := argValue(s.Cmd, "dry-run"); dry {
		ev = "restore-dry"
	}
	d.amu.Lock()
	d.events = append(d.events, ev)
	last := d.last
	d.last = mode
	if d.argv == nil {
		d.argv = map[string][]string{}
	}
	d.argv[mode] = s.Cmd
	d.amu.Unlock()
	src := s.Binds[0].Source
	switch mode {
	case "probe":
		return d.fakeDisk.run(s, out)
	case "scan":
		res, err := d.fakeDisk.run(s, out)
		if err != nil || res.ExitCode != 0 {
			return res, err
		}
		var rep folderfix.Report
		json.Unmarshal(bytes.TrimSpace(res.Stdout), &rep)
		rep.ACL = d.acl
		rep.Races = d.racesOf("scan")
		if _, ok := argValue(s.Cmd, "gid"); ok {
			if last == "apply" {
				rep.Races = d.racesOf("verify")
				rep.Plan = &folderfix.PlanCounts{}
				rep.Expected = &folderfix.Conformance{Group: folderfix.Count{N: d.verifyBad}}
			} else {
				rep.Plan = d.plan(d.entry(src))
				rep.Expected = &folderfix.Conformance{Group: folderfix.Count{N: rep.Plan.Changes}}
			}
		}
		return reply(rep, 0)
	case "snapshot":
		e := d.entry(src)
		kind, _ := argValue(s.Cmd, "kind")
		if kind == "" {
			kind = "apply"
		}
		gid, _ := argValue(s.Cmd, "gid")
		files, _ := argValue(s.Cmd, "files")
		owner := "null"
		if o, ok := argValue(s.Cmd, "owner"); ok {
			owner = o
		}
		plan := d.plan(e)
		d.amu.Lock()
		if d.snapHeader != nil {
			gid, files, owner = d.snapHeader(gid, files, owner)
		}
		d.amu.Unlock()
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		fmt.Fprintf(zw, `{"version":1,"kind":%q,"rules":1,"root_dev":%d,"root_ino":%d,"gid":%s,"files":%q,"owner_uid":%s,"created_at":"x","entries":%d}`+"\n",
			kind, e.dev, e.ino, gid, files, owner, plan.Changes)
		zw.Close()
		var tb bytes.Buffer
		tw := tar.NewWriter(&tb)
		tw.WriteHeader(&tar.Header{Name: "out/", Typeflag: tar.TypeDir, Mode: 0o700})
		tw.WriteHeader(&tar.Header{Name: "out/" + folderfix.SnapshotName, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(gz.Len())})
		tw.Write(gz.Bytes())
		tw.Close()
		if out != nil {
			if err := out(&tb); err != nil {
				return nil, err
			}
		}
		return reply(folderfix.Report{Version: 1, Mode: "snapshot", Dev: e.dev, Ino: e.ino, Plan: plan, Entries: plan.Changes, Races: d.racesOf("snapshot")}, 0)
	case "apply":
		if d.applyEntered != nil {
			d.applyEntered <- struct{}{}
		}
		if d.applyGate != nil {
			<-d.applyGate
		}
		e := d.entry(src)
		for _, a := range s.Cmd {
			if m, ok := strings.CutPrefix(a, "--mkdir="); ok {
				d.add(path.Join(src, m), "ext4")
			}
		}
		rep := folderfix.Report{Version: 1, Mode: "apply", Dev: e.dev, Ino: e.ino, Changed: e.files + e.dirs + 1, Plan: d.plan(e)}
		switch d.applyExit {
		case 2:
			rep.Errors = []string{"the folder changed since the preview: nothing changed"}
		case 1:
			rep.Errors = []string{"3 entries couldn't be changed"}
		}
		return reply(rep, d.applyExit)
	case "restore":
		rep := d.restore
		rep.Version, rep.Mode = 1, "restore"
		d.amu.Lock()
		restored := d.restored
		d.amu.Unlock()
		if _, dry := argValue(s.Cmd, "dry-run"); dry {
			rep.ToRestore, rep.Changed = rep.Changed, 0
			if restored {
				rep.ToRestore = d.leftAfter
			}
			return reply(rep, 0)
		}
		d.amu.Lock()
		d.restored = true
		d.amu.Unlock()
		return reply(rep, 0)
	}
	return nil, fmt.Errorf("unexpected fixer mode %q", mode)
}

// assignFixture: the assign templates, /srv/media (folder media, "Family
// media", gid 60001, 12,410 files and 312 folders owned 1000:1000) and
// /srv/docs (folder docs, gid 60002), compose simulated (an up runs one
// container, a down removes it), every compose up and down logged.
func assignFixture(t *testing.T) (*fixture, *assignDisk, *fakeAudit) {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, assignTemplates)
	for id := range assignTemplates {
		if f.h.Template(id) == nil {
			t.Fatalf("template %s not loaded (see the log)", id)
		}
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	fx := f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	d := &assignDisk{fakeDisk: &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}, acl: true}
	fx.run = d.run
	addFolder(t, f, d.fakeDisk, "media", "Family media", "/srv/media", 60001)
	addFolder(t, f, d.fakeDisk, "docs", "Docs", "/srv/docs", 60002)
	simulateCompose(f, 0)
	up, down := f.runner.upHook, f.runner.onDown
	f.runner.upHook = func(p string) { d.log("up:" + strings.TrimPrefix(p, ProjectPrefix)); up(p) }
	f.runner.onDown = func(p string) { d.log("down:" + strings.TrimPrefix(p, ProjectPrefix)); down(p) }
	return f, d, audit
}

func enable(t *testing.T, f *fixture, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := f.h.Enable(id); err != nil {
			t.Fatalf("enable %s: %v", id, err)
		}
	}
}

// waitFolderOp waits for folder id's op record to finish.
func waitFolderOp(t *testing.T, f *fixture, id string) *OpRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r := f.h.LastOp(opKeyFolder(id)); r != nil && !r.Running {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("folder %s: op still running", id)
	return nil
}

// assign previews req and applies it, waiting for the outcome.
func assign(t *testing.T, f *fixture, id string, req AssignRequest) (*AssignPlan, *OpRecord) {
	t.Helper()
	plan, err := f.h.PreviewAssign(context.Background(), id, req)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if _, err := f.h.StartAssign(id, req, plan.Hash, "admin"); err != nil {
		t.Fatalf("start: %v", err)
	}
	return plan, waitFolderOp(t, f, id)
}

func stateDump(t *testing.T, f *fixture) string {
	t.Helper()
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	b, err := yaml.Marshal(struct {
		S any
		F any
	}{f.h.st.Settings, f.h.st.Folders})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func value(f *fixture, inst, key string) any {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	return f.h.st.Settings[inst].Values[key]
}

func fixerRuns(d *assignDisk) []string {
	var out []string
	for _, e := range d.Events() {
		if !strings.Contains(e, ":") {
			out = append(out, e)
		}
	}
	return out
}

func auditOf(a *fakeAudit, action string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.entries {
		if e.Action == action {
			out = append(out, e.Target+" "+e.Result+" "+e.Detail)
		}
	}
	return out
}

var spec = AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}, {Instance: "samba", Key: "share"}}}

func TestPreviewAssignText(t *testing.T) {
	f, d, _ := assignFixture(t)
	enable(t, f, "immich", "samba")
	before := stateDump(t, f)
	plan, err := f.h.PreviewAssign(context.Background(), "media", spec)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(plan.Lines, "\n")
	for _, want := range []string{
		"gid 60001 is allocated for this folder (shown as *Family media*).",
		"12,410 files and 312 folders change group 1000 → 60001.",
		"Group 1000 keeps the access it has now through an ACL on 12,723 entries.",
		"313 folders get setgid and a default ACL",
		"Immich mounts it read-only (Library).",
		"Samba mounts it read/write and owns it (Share).",
		"Immich and Samba are stopped for under a minute, then started.",
		"A permissions snapshot is saved first.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("lines lack %q:\n%s", want, text)
		}
	}
	if plan.Disk == nil || plan.Disk.Files != "rw" || plan.Disk.OwnerUID == nil || *plan.Disk.OwnerUID != 2000 || plan.Disk.Entries != 12723 {
		t.Errorf("disk = %+v", plan.Disk)
	}
	if !reflect.DeepEqual(plan.Restarts, []string{"immich", "samba"}) || len(plan.Hash) != 64 {
		t.Errorf("restarts %v hash %q", plan.Restarts, plan.Hash)
	}
	for _, u := range plan.Uses {
		if u.Change != "add" || u.Env["PORTCULLIS_FOLDER_GID_"+strings.ToUpper(u.Key)] != "60001" {
			t.Errorf("use %+v", u)
		}
	}
	// Nothing changed: no snapshot or apply, state and values as before.
	if runs := fixerRuns(d); slices.Contains(runs, "apply") || slices.Contains(runs, "snapshot") {
		t.Errorf("runs = %v", runs)
	}
	if after := stateDump(t, f); after != before {
		t.Errorf("state changed:\n%s\n---\n%s", before, after)
	}
	if v := value(f, "immich", "library"); v != nil {
		t.Errorf("library = %v", v)
	}
	// The downtime estimate (5,000 entries a second, three runs).
	for n, want := range map[int64]string{12723: "under a minute", 100000: "about 1 minute", 200000: "about 2 minutes", 2000000: "about 20 minutes"} {
		if got := downtimeText(n, 3); got != want {
			t.Errorf("downtime(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPreviewRefusals(t *testing.T) {
	f, d, _ := assignFixture(t)
	ctx := context.Background()
	refuse := func(name, id string, req AssignRequest, status int, want string) {
		t.Helper()
		_, err := f.h.PreviewAssign(ctx, id, req)
		if statusOf(err) != status || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (%d), want %d %q", name, err, statusOf(err), status, want)
		}
	}
	use := func(uses ...FolderUse) AssignRequest { return AssignRequest{Uses: uses} }
	// Call 23 (T2 carry): two gid_env options of one service, two folders.
	setStored(f, "arr", "media", "folder:docs")
	refuse("gid_env", "media", use(FolderUse{Instance: "arr", Key: "downloads"}), 409, "point both settings at the same shared folder")
	// The same option already on another folder.
	refuse("other folder", "media", use(FolderUse{Instance: "arr", Key: "media"}), 409, "unassign it from Docs first")
	setStored(f, "arr", "media", nil)
	// Both on this folder: fine.
	if _, err := f.h.PreviewAssign(ctx, "media", use(FolderUse{Instance: "arr", Key: "downloads"}, FolderUse{Instance: "arr", Key: "media", Subpath: "tv"})); err != nil {
		t.Errorf("both gid_env options on one folder: %v", err)
	}
	refuse("must_own twice", "media", use(FolderUse{Instance: "samba", Key: "share"}, FolderUse{Instance: "nas", Key: "data"}), 409, "only one use may own it")
	refuse("unknown instance", "media", use(FolderUse{Instance: "nope", Key: "x"}), 400, "unknown app instance")
	refuse("unknown key", "media", use(FolderUse{Instance: "immich", Key: "nope"}), 400, "no setting")
	refuse("not a path", "media", use(FolderUse{Instance: "immich", Key: "workers"}), 400, "only path settings")
	refuse("bad subpath", "media", use(FolderUse{Instance: "immich", Key: "library", Subpath: "../x"}), 400, "library")
	refuse("write on a block", "media", use(FolderUse{Instance: "immich", Key: "library", Write: true}), 400, "folder block")
	refuse("unknown folder", "nope", use(), 404, "not found")
	// No ACL support: a change that would cut access is explain-only.
	d.acl, d.lose = false, 7
	refuse("no ACLs", "media", use(FolderUse{Instance: "immich", Key: "library"}), 409, "explain-only")
	// must_own without ACLs with previous owners: no owner change, the
	// group part still applies.
	d.lose = 0
	plan, err := f.h.PreviewAssign(ctx, "media", use(FolderUse{Instance: "samba", Key: "share"}))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Disk.OwnerUID != nil || !slices.Contains(plan.Warnings, "uid 1000 would lose access: ownership stays; the group part still applies") {
		t.Errorf("disk %+v warnings %v", plan.Disk, plan.Warnings)
	}
	if _, has := argValue(d.Argv("scan"), "owner"); has {
		t.Errorf("last scan still with an owner: %v", d.Argv("scan"))
	}
	// A rendering refusal (a custom override no longer valid) is a 409
	// before anything stops.
	d.acl = true
	writeFile(t, f.h.userOverridePath("immich"), "services:\n  server:\n    privileged: true\n")
	refuse("custom override", "media", use(FolderUse{Instance: "immich", Key: "library"}), 409, "custom compose override")
}

func TestApplyHashMismatch(t *testing.T) {
	f, d, _ := assignFixture(t)
	enable(t, f, "immich")
	req := AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}}
	plan, err := f.h.PreviewAssign(context.Background(), "media", req)
	if err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	s := f.h.st.Settings["immich"].Clone()
	if s.Values == nil {
		s.Values = map[string]any{}
	}
	s.Values["workers"] = int64(5)
	f.h.st.Settings["immich"] = s
	f.h.mu.Unlock()
	_, err = f.h.StartAssign("media", req, plan.Hash, "admin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "the setup changed since the preview") {
		t.Fatalf("apply = %v", err)
	}
	if f.h.LastOp(opKeyFolder("media")) != nil || slices.Contains(fixerRuns(d), "snapshot") {
		t.Error("an op started")
	}
	// A port change as well (the brief's case).
	plan, _ = f.h.PreviewAssign(context.Background(), "media", req)
	f.h.mu.Lock()
	s = f.h.st.Settings["immich"].Clone()
	if s.Ports == nil {
		s.Ports = map[string]string{}
	}
	s.Ports["X_BIND"] = "127.0.0.1"
	f.h.st.Settings["immich"] = s
	f.h.mu.Unlock()
	if _, err := f.h.StartAssign("media", req, plan.Hash, "admin"); statusOf(err) != 409 {
		t.Fatalf("port change: %v", err)
	}
	if _, err := f.h.StartAssign("media", req, "", "admin"); statusOf(err) != 409 {
		t.Fatalf("no hash: %v", err)
	}
}

func TestApplySequence(t *testing.T) {
	f, d, audit := assignFixture(t)
	enable(t, f, "immich")
	var atUp []string
	up := f.runner.upHook
	f.runner.upHook = func(p string) {
		up(p)
		f.h.mu.RLock()
		atUp = append(atUp, fmt.Sprint(f.h.st.Settings["immich"].Values["library"]))
		f.h.mu.RUnlock()
		ov, _ := os.ReadFile(f.h.overridePath("immich"))
		atUp = append(atUp, fmt.Sprint(strings.Contains(string(ov), "/srv/media/movies")))
	}
	n0 := len(d.Events())
	req := AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library", Subpath: "movies"}}}
	plan, rec := assign(t, f, "media", req)
	if !rec.OK {
		t.Fatalf("op = %+v", rec)
	}
	if !reflect.DeepEqual(plan.Disk.Mkdir, []string{"movies"}) {
		t.Errorf("mkdir = %v", plan.Disk.Mkdir)
	}
	// After the apply's own preview recomputation: stop, snapshot, apply,
	// verify, start (probes around the up).
	var seq []string
	for _, e := range d.Events()[n0:] {
		switch e {
		case "down:immich", "snapshot", "apply", "up:immich":
			seq = append(seq, e)
		case "scan":
			if slices.Contains(seq, "apply") {
				seq = append(seq, "verify")
			}
		}
	}
	if want := []string{"down:immich", "snapshot", "apply", "verify", "up:immich"}; !reflect.DeepEqual(seq, want) {
		t.Errorf("sequence = %v (%v)", seq, d.Events()[n0:])
	}
	if exp, _ := argValue(d.Argv("apply"), "expect"); exp != "12723" {
		t.Errorf("--expect = %q", exp)
	}
	if m, _ := argValue(d.Argv("apply"), "mkdir"); m != "movies" {
		t.Errorf("--mkdir = %q", m)
	}
	for _, flag := range []string{"expect-digest", "expect-mount-root", "expect-dev", "expect-ino"} {
		for _, mode := range []string{"apply", "snapshot"} {
			if v, ok := argValue(d.Argv(mode), flag); !ok || v == "" {
				if !(mode == "snapshot" && flag == "expect-digest") {
					t.Errorf("%s without --%s", mode, flag)
				}
			}
		}
	}
	// The state save and the override came before the start.
	if len(atUp) < 2 || atUp[0] != "folder:media/movies" || atUp[1] != "true" {
		t.Errorf("at the up: %v", atUp)
	}
	if v := value(f, "immich", "library"); v != "folder:media/movies" {
		t.Errorf("value = %v", v)
	}
	fo, _ := storedFolder(f, "media")
	if fo.LastApply == nil || fo.LastApply.Snapshot == "" || fo.LastApply.Files != "r" || rec.Result["snapshot"] != fo.LastApply.Snapshot {
		t.Errorf("last apply %+v result %v", fo.LastApply, rec.Result)
	}
	for _, v := range f.h.Folders() {
		if v.ID == "media" && (v.LastApply == nil || v.LastApply.Snapshot != fo.LastApply.Snapshot) {
			t.Errorf("the folder view lacks the last apply: %+v", v)
		}
	}
	ts := snapshotTS(fo.LastApply.Snapshot)
	if got := auditOf(audit, "folder.assign"); len(got) != 1 || got[0] != "media ok add=1 remove=0 entries=12723 snapshot="+ts {
		t.Errorf("folder.assign = %v", got)
	}
	if got := auditOf(audit, "folder.apply"); len(got) != 1 || got[0] != "media ok entries=12723 snapshot="+ts {
		t.Errorf("folder.apply = %v", got)
	}
	if got := auditOf(audit, "settings.change"); len(got) != 1 || got[0] != "immich/library ok scope=instance: unset -> folder:media/movies" {
		t.Errorf("settings.change = %v", got)
	}
	if _, err := os.Stat(f.h.markerPath("media")); !errors.Is(err, os.ErrNotExist) {
		t.Error("marker left behind")
	}
	// Nothing is still marked applying.
	if err := f.h.pending("immich"); err != nil {
		t.Errorf("pending after the op: %v", err)
	}
}

func TestApplyVerifyFails(t *testing.T) {
	f, d, audit := assignFixture(t)
	enable(t, f, "immich")
	d.verifyBad = 3
	ups0 := ups(f, "immich")
	_, rec := assign(t, f, "media", AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}})
	if rec.OK || !strings.Contains(rec.Error, "verify scan found entries not as planned (group 3") {
		t.Fatalf("op = %+v", rec)
	}
	fo, _ := storedFolder(f, "media")
	if fo.LastApply == nil || !strings.Contains(rec.Error, "permissions snapshot "+fo.LastApply.Snapshot+" can undo them") {
		t.Errorf("snapshot not named / not recorded: %+v %q", fo.LastApply, rec.Error)
	}
	if v := value(f, "immich", "library"); v != nil {
		t.Errorf("value = %v", v)
	}
	if ups(f, "immich") != ups0+1 || !strings.Contains(rec.Error, "Immich started again with the old configuration") {
		t.Errorf("not started again: ups %d → %d, %q", ups0, ups(f, "immich"), rec.Error)
	}
	if ov, _ := os.ReadFile(f.h.overridePath("immich")); strings.Contains(string(ov), "/srv/media") {
		t.Error("started with the new mount")
	}
	// I4: the disk may have changed: folder.apply audited with the snapshot.
	if got := auditOf(audit, "folder.apply"); len(got) != 1 || !strings.HasPrefix(got[0], "media error entries=12723 snapshot="+snapshotTS(fo.LastApply.Snapshot)) {
		t.Errorf("folder.apply = %v", got)
	}
	// An apply that refuses (exit 2) changed nothing: no undo offered.
	d.verifyBad, d.applyExit = 0, 2
	f.h.mu.Lock()
	fo = f.h.st.Folders["media"]
	fo.LastApply = nil
	f.h.st.Folders["media"] = fo
	f.h.mu.Unlock()
	_, rec = assign(t, f, "media", AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}})
	if rec.OK || rec.Status != 409 || !strings.Contains(rec.Error, "nothing on disk changed") {
		t.Errorf("refused apply: %+v", rec)
	}
	if fo, _ := storedFolder(f, "media"); fo.LastApply != nil {
		t.Errorf("last apply after a refusal: %+v", fo.LastApply)
	}
}

func TestAssignHoldsLocks(t *testing.T) {
	f, d, _ := assignFixture(t)
	enable(t, f, "immich")
	d.applyGate, d.applyEntered = make(chan struct{}), make(chan struct{}, 1)
	req := AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}}
	plan, err := f.h.PreviewAssign(context.Background(), "media", req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.StartAssign("media", req, plan.Hash, "admin"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.applyEntered:
	case <-time.After(10 * time.Second):
		t.Fatalf("the apply never started: %+v", f.h.LastOp(opKeyFolder("media")))
	}
	busy := func(name string, err error) {
		t.Helper()
		if errStatus(err) != 409 {
			t.Errorf("%s during the apply: %v", name, err)
		}
	}
	busy("Enable", f.h.Enable("immich"))
	busy("RestartApp", f.h.RestartApp("immich"))
	_, err = f.h.SaveSettings("immich", SettingsUpdate{Values: map[string]json.RawMessage{"workers": json.RawMessage("4")}}, "admin")
	busy("SaveSettings", err)
	if err == nil || !strings.Contains(err.Error(), "shared folder Family media is being applied") {
		t.Errorf("SaveSettings: %v", err)
	}
	_, err = f.h.PreviewSettings(context.Background(), "immich", SettingsUpdate{Values: map[string]json.RawMessage{"workers": json.RawMessage("4")}})
	busy("PreviewSettings", err)
	_, err = f.h.StartBackup("immich", "admin")
	busy("StartBackup", err)
	_, err = f.h.StartAssign("media", req, plan.Hash, "admin")
	busy("second StartAssign", err)
	_, err = f.h.StartUndo("media", "x", "admin")
	busy("StartUndo", err)
	close(d.applyGate)
	if rec := waitFolderOp(t, f, "media"); !rec.OK {
		t.Fatalf("op = %+v", rec)
	}
	if _, err := f.h.SaveSettings("immich", SettingsUpdate{Values: map[string]json.RawMessage{"workers": json.RawMessage("4")}}, "admin"); err != nil {
		t.Errorf("save after the apply: %v", err)
	}
}

// T7 carry: a save that passed its checks outside mu before an
// assignment committed is refused by the second folderSaveCheck under mu
// (the applying mark is gone by then).
func TestSaveRacesAssignment(t *testing.T) {
	f, _, _ := assignFixture(t)
	setStored(f, "immich", "extra", "/srv/old")
	req := AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "extra", Write: true}}}
	f.h.testHookSave = func() {
		f.h.testHookSave = nil
		_, rec := assign(t, f, "media", req)
		if !rec.OK {
			t.Errorf("assign = %+v", rec)
		}
	}
	_, err := f.h.SaveSettings("immich", SettingsUpdate{Values: map[string]json.RawMessage{"extra": json.RawMessage(`"/srv/new"`)}}, "admin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "uses shared folder media") {
		t.Fatalf("racing save = %v", err)
	}
	if v := value(f, "immich", "extra"); v != "folder:media" {
		t.Errorf("value = %v", v)
	}
	if fo, _ := storedFolder(f, "media"); !fo.WriteConfirmed["immich/extra"] {
		t.Errorf("write confirmation lost: %+v", fo.WriteConfirmed)
	}
}

func TestUnassignNoDisk(t *testing.T) {
	f, d, audit := assignFixture(t)
	setStored(f, "immich", "library", "folder:media")
	enable(t, f, "immich")
	n0, ups0 := len(fixerRuns(d)), ups(f, "immich")
	plan, rec := assign(t, f, "media", AssignRequest{Uses: []FolderUse{}})
	if !rec.OK {
		t.Fatalf("op = %+v", rec)
	}
	if plan.Disk != nil || len(plan.Uses) != 1 || plan.Uses[0].Change != "remove" || !reflect.DeepEqual(plan.Restarts, []string{"immich"}) {
		t.Errorf("plan = %+v", plan)
	}
	if !strings.Contains(strings.Join(plan.Lines, "\n"), "Nothing changes on disk.") {
		t.Errorf("lines = %v", plan.Lines)
	}
	for _, r := range fixerRuns(d)[n0:] {
		if r != "probe" {
			t.Errorf("fixer run %s", r)
		}
	}
	if ups(f, "immich") != ups0+1 {
		t.Error("not restarted")
	}
	if v := value(f, "immich", "library"); v != nil {
		t.Errorf("value = %v", v)
	}
	if got := auditOf(audit, "folder.assign"); len(got) != 1 || got[0] != "media ok add=0 remove=1" {
		t.Errorf("audit = %v", got)
	}
	if got := auditOf(audit, "folder.apply"); len(got) != 0 {
		t.Errorf("folder.apply = %v", got)
	}
}

func TestSnapshotRetention(t *testing.T) {
	f, _, _ := assignFixture(t)
	for _, sub := range []string{"a", "b", "c", "d"} {
		if _, rec := assign(t, f, "media", AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library", Subpath: sub}}}); !rec.OK {
			t.Fatalf("apply %s: %+v", sub, rec)
		}
	}
	snaps := f.h.listSnapshots("media")
	if len(snaps) != 3 {
		t.Fatalf("snapshots = %v", snaps)
	}
	fo, _ := storedFolder(f, "media")
	if snaps[2] != fo.LastApply.Snapshot {
		t.Errorf("newest %s, last apply %s", snaps[2], fo.LastApply.Snapshot)
	}
	dir := filepath.Join(f.data, "folder-snapshots")
	for _, s := range snaps {
		if fh, _, err := f.h.openSnapshot(s); err != nil {
			t.Errorf("open %s: %v", s, err)
		} else {
			fh.Close()
		}
		fi, err := os.Stat(filepath.Join(dir, s))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", s, fi.Mode(), err)
		}
		if fi, err := os.Stat(filepath.Join(dir, s+".sha256")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s.sha256: %v", s, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "media")); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", fi.Mode())
	}
	// Tampered: one byte changed → refused.
	p := filepath.Join(dir, snaps[0])
	b, _ := os.ReadFile(p)
	b[len(b)-1] ^= 0xff
	os.WriteFile(p, b, 0o600)
	if _, _, err := f.h.openSnapshot(snaps[0]); statusOf(err) != 409 || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("tampered: %v", err)
	}
	if _, _, err := f.h.openSnapshot("media/../../state.yaml"); err == nil {
		t.Error("traversal accepted")
	}
	// last_apply's snapshot is never pruned, even behind three newer ones
	// (undo snapshots).
	for range 3 {
		if _, err := f.h.saveSnapshot("media", strings.NewReader("undo")); err != nil {
			t.Fatal(err)
		}
	}
	if snaps := f.h.listSnapshots("media"); len(snaps) != 4 || snaps[0] != fo.LastApply.Snapshot {
		t.Errorf("after undo snapshots: %v (last apply %s)", snaps, fo.LastApply.Snapshot)
	}
}

func TestUndo(t *testing.T) {
	f, d, audit := assignFixture(t)
	ctx := context.Background()
	if _, err := f.h.PreviewUndo(ctx, "media"); statusOf(err) != 404 {
		t.Fatalf("no apply yet: %v", err)
	}
	enable(t, f, "immich")
	_, rec := assign(t, f, "media", AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}})
	if !rec.OK {
		t.Fatal(rec)
	}
	fo, _ := storedFolder(f, "media")
	applySnap := fo.LastApply.Snapshot
	applyData := readSnap(t, f, applySnap)
	d.restore = folderfix.Report{Changed: 12720, ChangedSince: folderfix.Count{N: 3}}
	plan, err := f.h.PreviewUndo(ctx, "media")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(plan.Lines, "\n")
	// R56: the counts come from a restore dry run.
	if !strings.Contains(text, "12,720 entries go back to the owner, group, mode and ACLs they had before the fix; 3 changed since the fix and are left alone.") {
		t.Errorf("no dry-run counts:\n%s", text)
	}
	if runs := fixerRuns(d); slices.Contains(runs, "restore") || slices.Contains(runs, "snapshot") && len(f.h.listSnapshots("media")) != 1 {
		t.Errorf("the preview restored: %v", runs)
	}
	at := fo.LastApply.At.UTC().Format("2006-01-02 15:04 UTC")
	if !strings.Contains(text, "fix of "+at+": snapshot "+snapshotTS(applySnap)+" recorded 12,723 entries") ||
		!strings.Contains(text, "Immich (Library) may lose access") || !strings.Contains(text, "Immich is stopped for") {
		t.Errorf("lines:\n%s", text)
	}
	n0 := len(d.Events())
	if _, err := f.h.StartUndo("media", plan.Hash, "admin"); err != nil {
		t.Fatal(err)
	}
	rec = waitFolderOp(t, f, "media")
	if !rec.OK || rec.Op != OpFolderUndo || rec.Result["changed_since"] != "3" {
		t.Fatalf("undo = %+v", rec)
	}
	// stop → undo snapshot → restore → start.
	var seq []string
	for _, e := range d.Events()[n0:] {
		if e == "down:immich" || e == "snapshot" || e == "restore" || e == "restore-dry" || e == "up:immich" {
			seq = append(seq, e)
		}
	}
	// The recomputed plan's dry run, then stop → undo snapshot → restore →
	// verify (a dry run, R56) → start.
	if want := []string{"restore-dry", "down:immich", "snapshot", "restore", "restore-dry", "up:immich"}; !reflect.DeepEqual(seq, want) {
		t.Errorf("sequence %v", seq)
	}
	if k, _ := argValue(d.Argv("snapshot"), "kind"); k != "undo" {
		t.Errorf("undo snapshot kind %q", k)
	}
	// The restore got the apply snapshot at /in, with --gid and the root
	// checks.
	specs := f.engine.fx().Specs()
	var restoreIn []byte
	for i, s := range specs {
		if fixerMode(s.Cmd) == "restore" {
			restoreIn = f.engine.fx().inputs[i]
			if s.InPath != "/in" {
				t.Errorf("restore in path %q", s.InPath)
			}
		}
	}
	if !bytes.Contains(restoreIn, applyData) {
		t.Error("restore didn't get the apply snapshot")
	}
	for _, flag := range []string{"gid", "expect-mount-root", "expect-dev", "expect-ino", "in"} {
		if _, ok := argValue(d.Argv("restore"), flag); !ok {
			t.Errorf("restore without --%s", flag)
		}
	}
	if v := value(f, "immich", "library"); v != "folder:media" {
		t.Errorf("value changed: %v", v)
	}
	fo, _ = storedFolder(f, "media")
	if fo.LastApply != nil {
		t.Errorf("last apply kept: %+v", fo.LastApply)
	}
	if got := auditOf(audit, "folder.apply"); len(got) != 2 || !strings.HasPrefix(got[1], "media ok undo snapshot="+snapshotTS(applySnap)+" ") {
		t.Errorf("audit = %v", got)
	}
	// R42: an undo can't be undone.
	if _, err := f.h.PreviewUndo(ctx, "media"); statusOf(err) != 404 {
		t.Errorf("undo of an undo: %v", err)
	}
	if len(f.h.listSnapshots("media")) != 2 {
		t.Errorf("snapshots %v", f.h.listSnapshots("media"))
	}
}

// readSnap is snapshot rel's bytes (checksum checked).
func readSnap(t *testing.T, f *fixture, rel string) []byte {
	t.Helper()
	fh, _, err := f.h.openSnapshot(rel)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	b, err := io.ReadAll(fh)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// reopen starts a new Hub on f's data directory (a Hub restart).
func reopen(t *testing.T, f *fixture) *Hub {
	t.Helper()
	h, err := New(Config{ProjectDir: f.project, ProjectHostDir: "/host/project", DataDir: f.data, Domain: "example.org"}, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h.lockPoll = 5 * time.Millisecond
	h.mountinfo = f.h.mountinfo
	h.SetAudit(&fakeAudit{})
	return h
}

func TestInterruptedApplyRestartsApps(t *testing.T) {
	f, d, _ := assignFixture(t)
	enable(t, f, "immich")
	// An apply that stopped the app, saved a snapshot and was cut short
	// (phase disk): marker + a running op record.
	stopped := f.h.Template("immich")
	if err := f.h.composeDown(stopped); err != nil {
		t.Fatal(err)
	}
	snap, err := f.h.saveSnapshot("media", strings.NewReader("snapshot bytes"))
	if err != nil {
		t.Fatal(err)
	}
	m := &applyMarker{Kind: "apply", Folder: "media", Instances: []string{"immich"}, Phase: "disk", Snapshot: snap, Files: "r",
		Values: []mvalue{{"immich", "library", "folder:media"}}, At: time.Now().UTC()}
	if err := f.h.writeMarker("media", m); err != nil {
		t.Fatal(err)
	}
	f.h.recordOp(opKeyFolder("media"), OpRecord{Op: OpFolderAssign, OpID: "abc", At: time.Now().UTC(), Running: true})
	f.h.Wait()
	ups0 := ups(f, "immich")
	runs0 := len(fixerRuns(d))

	h := reopen(t, f)
	h.Init()
	h.Wait()
	if ups(f, "immich") != ups0+1 {
		t.Errorf("immich not started: %v", f.runner.Calls())
	}
	for _, r := range fixerRuns(d)[runs0:] {
		if r != "probe" {
			t.Errorf("the fixer ran %s at recovery", r)
		}
	}
	rec := h.LastOp(opKeyFolder("media"))
	if rec == nil || rec.Running || rec.OK || rec.OpID != "abc" || !strings.Contains(rec.Error, "interrupted") ||
		!strings.Contains(rec.Error, "permissions snapshot "+snap+" can undo them") || !strings.Contains(rec.Error, "settings are unchanged") {
		t.Fatalf("record = %+v", rec)
	}
	h.mu.RLock()
	v := h.st.Settings["immich"].Values["library"]
	la := h.st.Folders["media"].LastApply
	h.mu.RUnlock()
	if v != nil {
		t.Errorf("value = %v", v)
	}
	if la == nil || la.Snapshot != snap {
		t.Errorf("undo not offered: %+v", la)
	}
	if _, err := os.Stat(h.markerPath("media")); !errors.Is(err, os.ErrNotExist) {
		t.Error("marker kept")
	}
	if _, failed := h.FailedOps()[opKeyFolder("media")]; failed {
		t.Error("folder record listed as a failed app")
	}

	// Phase state with the values saved: started with the new config.
	setStoredOn(h, "immich", "library", "folder:media")
	h.composeDown(h.Template("immich"))
	m.Phase = "state"
	h.writeMarker("media", m)
	h2 := reopen(t, f)
	h2.Init()
	h2.Wait()
	rec = h2.LastOp(opKeyFolder("media"))
	if rec == nil || !strings.Contains(rec.Error, "the new settings had been saved") {
		t.Errorf("record = %+v", rec)
	}
	if ov, _ := os.ReadFile(h2.overridePath("immich")); !strings.Contains(string(ov), "/srv/media") {
		t.Error("not started with the new configuration")
	}
}

func setStoredOn(h *Hub, id string, kv ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.st.Settings[id].Clone()
	if s.Values == nil {
		s.Values = map[string]any{}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		s.Values[kv[i].(string)] = kv[i+1]
	}
	h.st.Settings[id] = s
	h.st.Save(h.statePath())
}

// Ruling 20: folder and doctor records survive loadOps; FailedOps skips
// them.
func TestLoadOpsKeepsFolderRecords(t *testing.T) {
	f, _, _ := assignFixture(t)
	for _, k := range []string{opKeyFolder("media"), opKeyDoctor} {
		f.h.recordOp(k, OpRecord{Op: OpFolderAssign, At: time.Now().UTC(), Error: "x"})
	}
	writeFile(t, filepath.Join(f.data, "ops", "_folder.BAD.json"), `{"op":"x"}`)
	h := reopen(t, f)
	for _, k := range []string{opKeyFolder("media"), opKeyDoctor} {
		if h.LastOp(k) == nil {
			t.Errorf("%s dropped", k)
		}
	}
	if h.LastOp("_folder.BAD") != nil {
		t.Error("bad key kept")
	}
	for k := range h.FailedOps() {
		if strings.HasPrefix(k, "_") {
			t.Errorf("FailedOps lists %s", k)
		}
	}
	_ = state.Folder{}
}

// ── fix round 1 ──────────────────────────────────────────

var libraryReq = AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}}

// C1: a folder deleted while its preview runs: 404, state untouched (the
// dry run never writes a zero folder back), state.yaml still loads.
func TestPreviewRacesFolderDelete(t *testing.T) {
	f, d, _ := assignFixture(t)
	d.onScan = func(string) {
		if err := f.h.DeleteFolder("media", "admin"); err != nil {
			t.Errorf("delete: %v", err)
		}
	}
	if _, err := f.h.PreviewAssign(context.Background(), "media", libraryReq); statusOf(err) != 404 {
		t.Fatalf("preview = %v", err)
	}
	if _, ok := storedFolder(f, "media"); ok {
		t.Fatal("the deleted folder came back")
	}
	f.h.mu.Lock()
	err := f.h.saveStateLocked()
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Load(filepath.Join(f.data, "state.yaml")); err != nil {
		t.Fatalf("state.yaml after the race: %v", err)
	}
}

// I3: the dry run records nothing: the panel's env problems stay what
// the real configuration gives.
func TestDryRunRecordsNothing(t *testing.T) {
	f, _, _ := assignFixture(t)
	setStored(f, "arr", "pgid", int64(60005))
	f.h.mu.RLock()
	_, err := f.h.optionEnvLocked(f.h.findLocked("arr"), nil)
	f.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	problems := func() []string {
		f.h.envProblemsMu.Lock()
		defer f.h.envProblemsMu.Unlock()
		return slices.Clone(f.h.envProblems["arr"])
	}
	before := problems()
	if len(before) == 0 {
		t.Fatal("no env problem to keep")
	}
	if _, err := f.h.PreviewAssign(context.Background(), "media", AssignRequest{Uses: []FolderUse{{Instance: "arr", Key: "downloads"}}}); err != nil {
		t.Fatal(err)
	}
	if after := problems(); !slices.Equal(after, before) {
		t.Errorf("env problems %v → %v", before, after)
	}
}

// I1 + I4: a marker write that fails before the disk changes is a
// failure with nothing changed; the phase-state write failing after the
// apply offers the undo and audits folder.apply with the snapshot.
func TestMarkerWriteFailures(t *testing.T) {
	f, d, audit := assignFixture(t)
	enable(t, f, "immich")
	t.Cleanup(func() { testMarkerWrite = nil })
	testMarkerWrite = func(m *applyMarker) error {
		if m.Snapshot != "" && m.Phase == "disk" {
			return errors.New("disk full")
		}
		return nil
	}
	ups0 := ups(f, "immich")
	_, rec := assign(t, f, "media", libraryReq)
	if rec.OK || !strings.Contains(rec.Error, "recording the permissions snapshot") || !strings.Contains(rec.Error, "nothing on disk changed") {
		t.Fatalf("snapshot record: %+v", rec)
	}
	if slices.Contains(fixerRuns(d), "apply") {
		t.Error("applied without the snapshot recorded")
	}
	if fo, _ := storedFolder(f, "media"); fo.LastApply != nil {
		t.Errorf("last apply %+v", fo.LastApply)
	}
	if ups(f, "immich") != ups0+1 {
		t.Error("not started again")
	}
	if len(f.h.listSnapshots("media")) != 0 {
		t.Errorf("unrecorded snapshot kept: %v", f.h.listSnapshots("media"))
	}
	// Phase state.
	testMarkerWrite = func(m *applyMarker) error {
		if m.Phase == "state" {
			return errors.New("disk full")
		}
		return nil
	}
	_, rec = assign(t, f, "media", libraryReq)
	fo, _ := storedFolder(f, "media")
	if rec.OK || fo.LastApply == nil || !strings.Contains(rec.Error, "can undo them") || value(f, "immich", "library") != nil {
		t.Fatalf("phase state: %+v last apply %+v", rec, fo.LastApply)
	}
	got := auditOf(audit, "folder.apply")
	if len(got) != 1 || !strings.HasPrefix(got[0], "media error entries=12723 snapshot="+snapshotTS(fo.LastApply.Snapshot)) {
		t.Errorf("folder.apply = %v", got)
	}
	// The undo marker (the safety copy recorded) fails: nothing restored.
	testMarkerWrite = func(m *applyMarker) error {
		if m.Kind == "undo" && m.Undo != "" {
			return errors.New("disk full")
		}
		return nil
	}
	plan, err := f.h.PreviewUndo(context.Background(), "media")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.StartUndo("media", plan.Hash, "admin"); err != nil {
		t.Fatal(err)
	}
	rec = waitFolderOp(t, f, "media")
	if rec.OK || !strings.Contains(rec.Error, "nothing on disk changed") || d.restored {
		t.Fatalf("undo marker: %+v restored %v", rec, d.restored)
	}
}

// I2: an instance whose compose down failed is started again too.
func TestStopFailureStartsItAgain(t *testing.T) {
	f, _, _ := assignFixture(t)
	enable(t, f, "immich")
	f.runner.downErr = errors.New("down failed")
	ups0 := ups(f, "immich")
	_, rec := assign(t, f, "media", libraryReq)
	if rec.OK || !strings.Contains(rec.Error, "stopping immich failed") || !strings.Contains(rec.Error, "Immich started again") {
		t.Fatalf("op = %+v", rec)
	}
	if ups(f, "immich") != ups0+1 {
		t.Errorf("not started again (ups %d → %d)", ups0, ups(f, "immich"))
	}
}

// M1: a template source change between the preview and the apply.
func TestApplyTemplateChanged(t *testing.T) {
	f, _, _ := assignFixture(t)
	plan, err := f.h.PreviewAssign(context.Background(), "media", libraryReq)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.src, "immich", "notes.txt"), "changed\n")
	if _, err := f.h.StartAssign("media", libraryReq, plan.Hash, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "setup changed") {
		t.Fatalf("apply = %v", err)
	}
}

// M2: a saved snapshot whose header isn't the apply's: nothing applied.
func TestSnapshotHeaderChecked(t *testing.T) {
	f, d, _ := assignFixture(t)
	d.snapHeader = func(gid, files, owner string) (string, string, string) { return "60002", files, owner }
	_, rec := assign(t, f, "media", libraryReq)
	if rec.OK || !strings.Contains(rec.Error, "doesn't match the apply") || !strings.Contains(rec.Error, "nothing on disk changed") {
		t.Fatalf("op = %+v", rec)
	}
	if slices.Contains(fixerRuns(d), "apply") || len(f.h.listSnapshots("media")) != 0 {
		t.Errorf("runs %v snapshots %v", fixerRuns(d), f.h.listSnapshots("media"))
	}
}

// M3: an undo whose snapshot target differs from last_apply's: 409.
func TestUndoTargetMismatch(t *testing.T) {
	f, _, _ := assignFixture(t)
	if _, rec := assign(t, f, "media", libraryReq); !rec.OK {
		t.Fatal(rec)
	}
	f.h.mu.Lock()
	fo := f.h.st.Folders["media"]
	la := *fo.LastApply
	la.Files = "rw" // the snapshot says r
	fo.LastApply = &la
	f.h.st.Folders["media"] = fo
	f.h.mu.Unlock()
	if _, err := f.h.PreviewUndo(context.Background(), "media"); statusOf(err) != 409 || !strings.Contains(err.Error(), "another target") {
		t.Fatalf("preview undo = %v", err)
	}
}

// R56: the undo's verify is a restore dry run that must find nothing left.
func TestUndoVerifyFindsLeftovers(t *testing.T) {
	f, d, _ := assignFixture(t)
	if _, rec := assign(t, f, "media", libraryReq); !rec.OK {
		t.Fatal(rec)
	}
	d.restore = folderfix.Report{Changed: 10}
	d.leftAfter = 4
	plan, err := f.h.PreviewUndo(context.Background(), "media")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.StartUndo("media", plan.Hash, "admin"); err != nil {
		t.Fatal(err)
	}
	rec := waitFolderOp(t, f, "media")
	if rec.OK || !strings.Contains(rec.Error, "verify found 4 entries") || !strings.Contains(rec.Error, "Undo last fix can run again") {
		t.Fatalf("op = %+v", rec)
	}
	if fo, _ := storedFolder(f, "media"); fo.LastApply == nil {
		t.Error("last apply cleared after a failed verify")
	}
}

// M5: a failure's error carries the stopped instances' redaction sets.
func TestFailureKeepsRedaction(t *testing.T) {
	f, _, _ := assignFixture(t)
	enable(t, f, "immich")
	f.h.mu.Lock()
	err := setEnvVars(f.h.envPath("immich"), map[string]string{"API_TOKEN": "s3cr3t-token-value"}, false)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fb := &failCtx{id: "media", actor: "admin", m: &applyMarker{}, secrets: f.h.opSecrets([]string{"immich"})}
	got := f.h.failBeforeState(fb, errors.New("boom"), "", false)
	if !slices.Contains(secretsOf(got), "s3cr3t-token-value") {
		t.Errorf("redaction set lost: %v", secretsOf(got))
	}
}

// H3: folder audits are redacted like op records (the error's own
// redaction set and the affected instances' secrets), then clipped.
func TestFolderAuditRedacted(t *testing.T) {
	f, _, audit := assignFixture(t)
	enable(t, f, "immich")
	f.h.mu.Lock()
	err := setEnvVars(f.h.envPath("immich"), map[string]string{"API_TOKEN": "s3cr3t-token-value"}, false)
	f.h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Through the error's redaction set (a disk-changed failure).
	fb := &failCtx{id: "media", actor: "admin", m: &applyMarker{}, secrets: f.h.opSecrets([]string{"immich"})}
	f.h.failBeforeState(fb, errors.New("compose up: API_TOKEN=s3cr3t-token-value rejected"), "", true)
	e := audit.last()
	if e.Action != "folder.apply" || e.Error == "" || strings.Contains(e.Error, "s3cr3t-token-value") || !strings.Contains(e.Error, "[redacted]") {
		t.Errorf("folder.apply audit = %+v", e)
	}
	// Through the affected instances, the error carrying no set.
	f.h.auditFolder("admin", "folder.assign", "media", "", errors.New("start immich: s3cr3t-token-value"), "immich")
	if e := audit.last(); strings.Contains(e.Error, "s3cr3t-token-value") || !strings.Contains(e.Error, "[redacted]") {
		t.Errorf("folder.assign audit = %+v", e)
	}
	// Clipped.
	f.h.auditFolder("admin", "folder.assign", "media", "", errors.New(strings.Repeat("x", 5000)))
	if e := audit.last(); len([]rune(e.Error)) > 601 {
		t.Errorf("unclipped audit error: %d runes", len([]rune(e.Error)))
	}
}

// H4: a preview is refused while a service the folder's gid reaches also
// mounts a path at or above the folder (a setting or the custom
// override): through it the gid would reach every folder directory.
func TestPreviewRefusesMountAboveFolder(t *testing.T) {
	f, _, _ := assignFixture(t)
	ctx := context.Background()
	use := func(uses ...FolderUse) AssignRequest { return AssignRequest{Uses: uses} }
	lib := FolderUse{Instance: "immich", Key: "library"}
	// A hand-typed setting of the target service above the folder.
	setStored(f, "immich", "extra", "/srv")
	_, err := f.h.PreviewAssign(ctx, "media", use(lib))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "`/srv`") || !strings.Contains(err.Error(), "Family media") {
		t.Fatalf("setting above: %v", err)
	}
	// At the folder's path itself.
	setStored(f, "immich", "extra", "/srv/media")
	if _, err := f.h.PreviewAssign(ctx, "media", use(lib)); statusOf(err) != 409 {
		t.Fatalf("setting at: %v", err)
	}
	// Elsewhere, or below the folder: fine.
	setStored(f, "immich", "extra", "/srv/docs")
	if _, err := f.h.PreviewAssign(ctx, "media", use(lib)); err != nil {
		t.Fatalf("elsewhere: %v", err)
	}
	// Another service the gid reaches (immich, already assigned) is
	// judged when samba is added.
	setStored(f, "immich", "extra", "/srv", "library", "folder:media")
	if _, err := f.h.PreviewAssign(ctx, "media", use(lib, FolderUse{Instance: "samba", Key: "share"})); statusOf(err) != 409 || !strings.Contains(err.Error(), "immich") {
		t.Fatalf("existing user: %v", err)
	}
	setStored(f, "immich", "extra", nil, "library", nil)
	// The custom override's bind of the target service.
	writeFile(t, f.h.userOverridePath("samba"), "services:\n  samba:\n    volumes:\n      - /srv:/all\n")
	if _, err := f.h.PreviewAssign(ctx, "media", use(FolderUse{Instance: "samba", Key: "share"})); statusOf(err) != 409 || !strings.Contains(err.Error(), "custom override") {
		t.Fatalf("custom override above: %v", err)
	}
}

// H2: a folder whose identity changed (a reboot on btrfs/LVM changes the
// device number) says so, and "Re-check identity" previews old → new and
// stores the new identity once confirmed.
func TestRecheckFolderIdentity(t *testing.T) {
	f, d, audit := assignFixture(t)
	ctx := context.Background()
	lib := AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}}
	recheck := "the folder's identity changed (e.g. after a reboot on btrfs/LVM): re-check it in Shared folders"
	d.mu.Lock()
	d.paths["/srv/media"].dev = 2050
	d.mu.Unlock()
	if _, err := f.h.PreviewAssign(ctx, "media", lib); statusOf(err) != 409 || !strings.Contains(err.Error(), recheck) {
		t.Fatalf("assign preview: %v", err)
	}
	setStored(f, "immich", "library", "folder:media")
	if err := f.h.Enable("immich"); statusOf(err) != 409 || !strings.Contains(err.Error(), recheck) {
		t.Fatalf("enable: %v", err)
	}
	chk, err := f.h.PreviewRecheck(ctx, "media")
	if err != nil {
		t.Fatal(err)
	}
	if !chk.Changed || chk.Old.Dev != 2049 || chk.New.Dev != 2050 || chk.Old.Ino != chk.New.Ino || chk.New.MountRoot != "/srv/media" || len(chk.Hash) != 64 ||
		!strings.Contains(strings.Join(chk.Lines, "\n"), "Only the device number changed") {
		t.Fatalf("preview = %+v", chk)
	}
	if fo, _ := storedFolder(f, "media"); fo.Dev != 2049 {
		t.Fatal("the preview stored the identity")
	}
	if _, err := f.h.ApplyRecheck(ctx, "media", strings.Repeat("0", 64), "admin"); statusOf(err) != 409 {
		t.Errorf("stale hash = %v", err)
	}
	// Busy: the folder's lock, or a user's app lock.
	unlock, _ := f.h.folderLock("media")
	if _, err := f.h.ApplyRecheck(ctx, "media", chk.Hash, "admin"); statusOf(err) != 409 {
		t.Errorf("folder busy = %v", err)
	}
	unlock()
	unlockApp, _ := f.h.lockApp("immich")
	if _, err := f.h.ApplyRecheck(ctx, "media", chk.Hash, "admin"); statusOf(err) != 409 {
		t.Errorf("app busy = %v", err)
	}
	unlockApp()
	v, err := f.h.ApplyRecheck(ctx, "media", chk.Hash, "admin")
	if err != nil || v == nil || v.ID != "media" {
		t.Fatalf("apply = %+v %v", v, err)
	}
	if fo, _ := storedFolder(f, "media"); fo.Dev != 2050 || fo.Ino != chk.New.Ino || fo.MountRoot != "/srv/media" {
		t.Errorf("stored = %+v", fo)
	}
	if a := auditOf(audit, "folder.update"); len(a) == 0 || !strings.Contains(a[len(a)-1], "media ok recheck device 2049→2050") {
		t.Errorf("audit = %q", a)
	}
	if err := f.h.Enable("immich"); err != nil {
		t.Errorf("enable after the re-check: %v", err)
	}
	// Unchanged: said so; changed again after the preview: 409.
	chk, err = f.h.PreviewRecheck(ctx, "media")
	if err != nil || chk.Changed || !strings.Contains(strings.Join(chk.Lines, "\n"), "as stored") {
		t.Fatalf("unchanged preview = %+v %v", chk, err)
	}
	d.mu.Lock()
	d.paths["/srv/media"].dev = 2051
	d.mu.Unlock()
	if _, err := f.h.ApplyRecheck(ctx, "media", chk.Hash, "admin"); statusOf(err) != 409 {
		t.Errorf("changed since the preview = %v", err)
	}
	if _, err := f.h.PreviewRecheck(ctx, "nope"); statusOf(err) != 404 {
		t.Errorf("unknown folder = %v", err)
	}
}

// M6: every run's races reach the op's warnings.
func TestEveryRunsWarnings(t *testing.T) {
	f, d, _ := assignFixture(t)
	d.races = map[string]int64{"snapshot": 2, "verify": 3}
	_, rec := assign(t, f, "media", libraryReq)
	if !rec.OK {
		t.Fatal(rec)
	}
	w := strings.Join(rec.Warnings, "\n")
	for _, want := range []string{"snapshot: 2 entries changed while the fixer ran", "verify: 3 entries changed while the fixer ran"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
}

// M7: while an unrecovered marker exists, a new apply or undo is 409;
// a recovery that can't take its locks records a failed op and keeps
// the marker.
func TestUnrecoveredMarker(t *testing.T) {
	f, _, _ := assignFixture(t)
	if _, rec := assign(t, f, "media", libraryReq); !rec.OK {
		t.Fatal(rec)
	}
	plan, err := f.h.PreviewUndo(context.Background(), "media")
	if err != nil {
		t.Fatal(err)
	}
	m := &applyMarker{Kind: "apply", Folder: "media", Instances: []string{"immich"}, Phase: "disk", At: time.Now().UTC()}
	if err := f.h.writeMarker("media", m); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.StartAssign("media", libraryReq, "x", "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "hasn't been recovered") {
		t.Errorf("assign = %v", err)
	}
	if _, err := f.h.StartUndo("media", plan.Hash, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "hasn't been recovered") {
		t.Errorf("undo = %v", err)
	}
	unlock, err := f.h.lockApp("immich")
	if err != nil {
		t.Fatal(err)
	}
	f.h.restartWait = 20 * time.Millisecond
	f.h.recoverFolderApply("media")
	unlock()
	rec := f.h.LastOp(opKeyFolder("media"))
	if rec == nil || rec.OK || !strings.Contains(rec.Error, "not recovered yet") {
		t.Fatalf("record = %+v", rec)
	}
	if _, err := os.Stat(f.h.markerPath("media")); err != nil {
		t.Errorf("marker removed: %v", err)
	}
}

// M8: removing the must_own use changes the other users' env (their
// PORTCULLIS_FOLDER_UID_<KEY>): they are restarted too, though only
// samba's values change and nothing changes on disk.
func TestRenderChangeRestartsOthers(t *testing.T) {
	f, _, _ := assignFixture(t)
	if _, rec := assign(t, f, "media", spec); !rec.OK {
		t.Fatal(rec)
	}
	enable(t, f, "immich", "samba")
	if env := optionEnv(t, f, "immich"); env["PORTCULLIS_FOLDER_UID_LIBRARY"] != "2000" {
		t.Fatalf("env before = %v", env["PORTCULLIS_FOLDER_UID_LIBRARY"])
	}
	ups0 := ups(f, "immich")
	plan, rec := assign(t, f, "media", libraryReq)
	if !rec.OK {
		t.Fatal(rec)
	}
	if plan.Disk != nil || !reflect.DeepEqual(plan.Restarts, []string{"immich", "samba"}) {
		t.Errorf("disk %+v restarts %v", plan.Disk, plan.Restarts)
	}
	if ups(f, "immich") != ups0+1 {
		t.Error("immich not restarted")
	}
	if env := optionEnv(t, f, "immich"); env["PORTCULLIS_FOLDER_UID_LIBRARY"] != "" {
		t.Errorf("env after = %q", env["PORTCULLIS_FOLDER_UID_LIBRARY"])
	}
}
