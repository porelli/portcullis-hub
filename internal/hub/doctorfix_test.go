package hub

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/state"
)

// Task 12: the doctor's one-click fixes (contract §14.6).

// ── rebind_port ─────────────────────────────────────────

// rebindFixture: samba enabled (compose simulated), its main domain
// resolving to 192.168.1.20 (a local address the rebind must refuse).
func rebindFixture(t *testing.T) (*fixture, *fakeAudit) {
	t.Helper()
	f, audit := sambaFixture(t)
	f.h.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.1.20")}, nil
	}
	simulateCompose(f, 0)
	enable(t, f, "samba")
	return f, audit
}

var smbFP = doctor.Fingerprint(doctor.KindLANOnlyExposed, "samba", "SAMBA_SMB", "tcp")

func countCalls(f *fixture, call string) int {
	n := 0
	for _, c := range f.runner.Calls() {
		if c == call {
			n++
		}
	}
	return n
}

func waitInstanceOp(t *testing.T, f *fixture, id, opID string) *OpRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if r := f.h.LastOp(id); r != nil && r.OpID == opID && !r.Running {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: op %s still running", id, opID)
	return nil
}

func storedPorts(f *fixture, id string) map[string]string {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	return f.h.st.Settings[id].Ports
}

func TestRebindPreviewText(t *testing.T) {
	f, _ := rebindFixture(t)
	ctx := context.Background()
	before, calls := stateDump(t, f), len(f.runner.Calls())
	ov, _ := os.ReadFile(f.h.overridePath("samba"))
	plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != doctor.FixRebindPort || plan.FP != smbFP || len(plan.Hash) != 64 || plan.Assign != nil {
		t.Errorf("plan = %+v", plan)
	}
	if len(plan.Lines) == 0 || plan.Lines[0] != "SAMBA_SMB bind 0.0.0.0 → 192.168.1.10, Samba restarts" {
		t.Errorf("lines = %q", plan.Lines)
	}
	// The preview changes nothing.
	ov2, _ := os.ReadFile(f.h.overridePath("samba"))
	if stateDump(t, f) != before || len(f.runner.Calls()) != calls || string(ov) != string(ov2) {
		t.Error("the preview changed something")
	}
	// The same address previews the same hash; another address another.
	again, _ := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	other, _ := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "10.0.0.5"})
	if again == nil || other == nil || again.Hash != plan.Hash || other.Hash == plan.Hash {
		t.Errorf("hashes %v %v", again, other)
	}
	for _, bad := range []string{"0.0.0.0", "::", "8.8.8.8", "not-an-ip", "", "192.168.1.20", "fe80::1%eth0"} {
		if _, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": bad}); statusOf(err) != 400 {
			t.Errorf("address %q: %v", bad, err)
		}
		if _, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": bad}, plan.Hash, "admin"); statusOf(err) != 400 {
			t.Errorf("apply address %q: %v", bad, err)
		}
	}
	if _, err := f.h.PreviewFix(ctx, "0123456789abcdef", nil); statusOf(err) != 404 {
		t.Errorf("unknown fp: %v", err)
	}
	if _, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10", "fix": "manage_as_folder"}); statusOf(err) != 400 {
		t.Errorf("a fix the finding doesn't offer: %v", err)
	}
}

func TestRebindApply(t *testing.T) {
	f, audit := rebindFixture(t)
	ctx := context.Background()
	plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	ups := countCalls(f, "up:"+projectName("samba"))
	op, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if op.Op != OpRebind || op.Instance != "samba" {
		t.Errorf("op = %+v", op)
	}
	rec := waitInstanceOp(t, f, "samba", op.OpID)
	if !rec.OK || rec.RolledBack {
		t.Fatalf("rebind = %+v", rec)
	}
	if p := storedPorts(f, "samba"); p["SAMBA_SMB_BIND"] != "192.168.1.10" {
		t.Errorf("ports = %v", p)
	}
	ov, _ := os.ReadFile(f.h.overridePath("samba"))
	if !strings.Contains(string(ov), `"192.168.1.10:445:445/tcp"`) {
		t.Errorf("override:\n%s", ov)
	}
	if n := countCalls(f, "up:"+projectName("samba")); n != ups+1 {
		t.Errorf("ups %d → %d: restarted once inline", ups, n)
	}
	time.Sleep(50 * time.Millisecond)
	if n := countCalls(f, "up:"+projectName("samba")); n != ups+1 {
		t.Errorf("a second restart followed (%d ups)", n-ups)
	}
	if got := auditOf(audit, "settings.change"); !slices.Contains(got, "samba/SAMBA_SMB_BIND ok scope=port: default -> 192.168.1.10") {
		t.Errorf("settings.change = %v", got)
	}
	// The finding is gone; a stale apply is 404.
	if _, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, "admin"); statusOf(err) != 404 {
		t.Errorf("second apply: %v", err)
	}
}

func TestRebindRollback(t *testing.T) {
	f, audit := rebindFixture(t)
	ctx := context.Background()
	plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	ovBefore, _ := os.ReadFile(f.h.overridePath("samba"))
	project := projectName("samba")
	ups := countCalls(f, "up:"+project)
	// The first up (the restart with the new bind) fails, the next works.
	hook, n := f.runner.upHook, 0
	f.runner.upHook = func(p string) {
		hook(p)
		n++
		if n == 1 {
			f.runner.upErr = &compose.Error{Command: "up", Err: errors.New("exit status 1"),
				Output: "Error response from daemon: failed to bind host port 192.168.1.10:445/tcp: cannot assign requested address"}
		} else {
			f.runner.upErr = nil
		}
	}
	op, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	rec := waitInstanceOp(t, f, "samba", op.OpID)
	if rec.OK || !rec.RolledBack || rec.Op != OpRebind || !strings.Contains(rec.Output, "cannot assign requested address") ||
		!strings.Contains(rec.Error, "the old bind 0.0.0.0 was put back") {
		t.Fatalf("rebind = %+v", rec)
	}
	if p := storedPorts(f, "samba"); p["SAMBA_SMB_BIND"] != "" {
		t.Errorf("ports = %v: the old bind isn't back", p)
	}
	ovAfter, _ := os.ReadFile(f.h.overridePath("samba"))
	if string(ovAfter) != string(ovBefore) || strings.Contains(string(ovAfter), "192.168.1.10") {
		t.Errorf("override not put back:\n%s", ovAfter)
	}
	if got := countCalls(f, "up:"+project) - ups; got != 2 {
		t.Errorf("%d ups: the failed restart and the start again", got)
	}
	f.engine.mu.Lock()
	running := false
	for _, c := range f.engine.containers {
		running = running || c.Project() == project
	}
	f.engine.mu.Unlock()
	if !running {
		t.Error("samba was left down")
	}
	if got := auditOf(audit, "settings.change"); len(got) == 0 || !strings.Contains(got[len(got)-1], "error") {
		t.Errorf("settings.change = %v", got)
	}
}

// ── manage_as_folder ────────────────────────────────────

var manageTemplates = map[string][2]string{
	"jellyfin": folderApp("Jellyfin", "jellyfin", `    - key: media
      label: Media
      type: path
      target: {service: jellyfin, mount: /media}
      folder: {access: read, runs_as: {uid: 1000, gid: 1000}}
      applies: restart
`, "  jellyfin:\n    image: jellyfin\n    user: \"1000:1000\"\n", ""),
	"writer": folderApp("Writer", "writer", `    - key: data
      label: Data
      type: path
      target: {service: writer, mount: /data}
      applies: restart
`, "  writer:\n    image: writer\n    user: \"1001:1001\"\n", ""),
}

// manageFixture: jellyfin (declared reader) and writer (no folder block,
// mounted rw) both on the hand-typed /srv/media, enabled; no folders.
func manageFixture(t *testing.T) (*fixture, *assignDisk, *fakeAudit) {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, manageTemplates)
	for id := range manageTemplates {
		if f.h.Template(id) == nil {
			t.Fatalf("template %s not loaded (see the log)", id)
		}
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	f.h.SetPeople(newFakePeople("erin"))
	fx := f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	d := &assignDisk{fakeDisk: &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}, acl: true}
	fx.run = d.run
	d.add("/srv/media", "ext4")
	d.add("/srv/other", "ext4")
	simulateCompose(f, 0)
	up, down := f.runner.upHook, f.runner.onDown
	f.runner.upHook = func(p string) { d.log("up:" + strings.TrimPrefix(p, ProjectPrefix)); up(p) }
	f.runner.onDown = func(p string) { d.log("down:" + strings.TrimPrefix(p, ProjectPrefix)); down(p) }
	setStored(f, "jellyfin", "media", "/srv/media")
	setStored(f, "writer", "data", "/srv/media")
	enable(t, f, "jellyfin", "writer")
	return f, d, audit
}

var mediaFP = doctor.Fingerprint(doctor.KindSharedPath, "/srv/media")

func foldersOf(f *fixture) (map[string]state.Folder, []int) {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	out := map[string]state.Folder{}
	for k, v := range f.h.st.Folders {
		out[k] = v
	}
	return out, slices.Clone(f.h.st.FolderGIDs)
}

func TestManageAsFolder(t *testing.T) {
	f, d, audit := manageFixture(t)
	ctx := context.Background()
	r, err := f.h.Doctor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fd *doctor.Finding
	for i := range r.Findings {
		if r.Findings[i].FP == mediaFP {
			fd = &r.Findings[i]
		}
	}
	if fd == nil || fd.FixKind != doctor.FixManageAsFolder {
		t.Fatalf("findings = %+v", r.Findings)
	}
	before := stateDump(t, f)
	plan, err := f.h.PreviewFix(ctx, mediaFP, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(plan.Lines, "\n")
	for _, want := range []string{
		"Shared folder *media* (id media) is defined at /srv/media.",
		"gid 60000 is allocated for this folder (shown as *media*).",
		"Jellyfin's Media: /srv/media → folder:media.",
		"Writer's Data: /srv/media → folder:media.",
		"Jellyfin mounts it read-only (Media).",
		"Writer mounts it read/write (Data).",
		"A permissions snapshot is saved first.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("lines lack %q:\n%s", want, text)
		}
	}
	if plan.Kind != doctor.FixManageAsFolder || plan.Assign == nil || plan.Assign.Folder != "media" || plan.Assign.GID != 60000 ||
		plan.Assign.Disk == nil || plan.Assign.Disk.Files != "rw" || len(plan.Assign.Uses) != 2 || len(plan.Hash) != 64 {
		t.Fatalf("plan = %+v assign %+v", plan, plan.Assign)
	}
	if runs := fixerRuns(d); slices.Contains(runs, "apply") || slices.Contains(runs, "snapshot") {
		t.Errorf("the preview ran %v", runs)
	}
	if stateDump(t, f) != before {
		t.Error("the preview changed state")
	}
	// Params: another name and id.
	named, err := f.h.PreviewFix(ctx, mediaFP, map[string]string{"name": "Family media", "id": "family"})
	if err != nil || named.Assign.Folder != "family" || !strings.Contains(strings.Join(named.Lines, "\n"), "Shared folder *Family media* (id family)") || named.Hash == plan.Hash {
		t.Errorf("named = %+v, %v", named, err)
	}
	for _, bad := range []map[string]string{{"id": "Bad id"}, {"name": strings.Repeat("x", 65)}, {"name": "a\nb"}, {"bogus": "x"}} {
		if _, err := f.h.PreviewFix(ctx, mediaFP, bad); statusOf(err) != 400 {
			t.Errorf("params %v: %v", bad, err)
		}
	}

	op, err := f.h.ApplyFix(ctx, mediaFP, nil, plan.Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if op.Instance != opKeyFolder("media") || op.Op != OpFolderAssign {
		t.Errorf("op = %+v", op)
	}
	rec := waitFolderOp(t, f, "media")
	if !rec.OK {
		t.Fatalf("assign = %+v", rec)
	}
	fs, _ := foldersOf(f)
	if fo, ok := fs["media"]; !ok || fo.GID != 60000 || fo.Path != "/srv/media" || fo.Name != "media" || fo.LastApply == nil {
		t.Errorf("folder = %+v", fs)
	}
	if v := value(f, "jellyfin", "media"); v != "folder:media" {
		t.Errorf("jellyfin media = %v", v)
	}
	if v := value(f, "writer", "data"); v != "folder:media" {
		t.Errorf("writer data = %v", v)
	}
	if runs := fixerRuns(d); !slices.Contains(runs, "snapshot") || !slices.Contains(runs, "apply") {
		t.Errorf("runs = %v", runs)
	}
	if got := auditOf(audit, "folder.create"); len(got) != 1 || !strings.HasPrefix(got[0], "media ok gid=60000 path=/srv/media") {
		t.Errorf("folder.create = %v", got)
	}
	if got := auditOf(audit, "folder.assign"); len(got) != 1 || !strings.Contains(got[0], "ok add=2") {
		t.Errorf("folder.assign = %v", got)
	}
}

// Ruling 34: the gid is predicted, and a change since the preview is a
// 409 before anything is defined.
func TestFixHashMismatch(t *testing.T) {
	ctx := context.Background()
	t.Run("rebind", func(t *testing.T) {
		f, audit := rebindFixture(t)
		plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
		if err != nil {
			t.Fatal(err)
		}
		ups := countCalls(f, "up:"+projectName("samba"))
		f.h.mu.Lock()
		s := f.h.st.Settings["samba"].Clone()
		s.Ports = map[string]string{"SAMBA_WEB": "8081"}
		f.h.st.Settings["samba"] = s
		f.h.mu.Unlock()
		_, err = f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, "admin")
		if statusOf(err) != 409 || !strings.Contains(err.Error(), "changed since the preview") {
			t.Fatalf("apply after a port change: %v", err)
		}
		if p := storedPorts(f, "samba"); p["SAMBA_SMB_BIND"] != "" || countCalls(f, "up:"+projectName("samba")) != ups {
			t.Errorf("changed: %v", p)
		}
		if _, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "10.0.0.5"}, plan.Hash, "admin"); statusOf(err) != 409 {
			t.Errorf("another address: %v", err)
		}
		if _, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, "", "admin"); statusOf(err) != 409 {
			t.Errorf("no hash: %v", err)
		}
		if got := auditOf(audit, "doctor.fix"); len(got) != 3 || !strings.HasPrefix(got[0], smbFP+" refused") {
			t.Errorf("doctor.fix = %v", got)
		}
	})
	t.Run("manage_as_folder", func(t *testing.T) {
		f, d, _ := manageFixture(t)
		plan, err := f.h.PreviewFix(ctx, mediaFP, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Another folder takes the predicted gid.
		if _, _, err := f.h.CreateFolder(ctx, FolderInput{ID: "other", Name: "Other", Path: "/srv/other"}, "admin"); err != nil {
			t.Fatal(err)
		}
		_, err = f.h.ApplyFix(ctx, mediaFP, nil, plan.Hash, "admin")
		if statusOf(err) != 409 || !strings.Contains(err.Error(), "changed since the preview") {
			t.Fatalf("apply: %v", err)
		}
		fs, gids := foldersOf(f)
		if _, ok := fs["media"]; ok || !slices.Equal(gids, []int{60000}) {
			t.Errorf("folders %v gids %v", fs, gids)
		}
		if runs := fixerRuns(d); slices.Contains(runs, "apply") {
			t.Errorf("runs %v", runs)
		}
		if v := value(f, "jellyfin", "media"); v != "/srv/media" {
			t.Errorf("value %v", v)
		}
		// Previewed again, it predicts the next gid.
		plan, err = f.h.PreviewFix(ctx, mediaFP, nil)
		if err != nil || plan.Assign.GID != 60001 {
			t.Fatalf("plan %+v %v", plan, err)
		}
	})
}

// Ruling 34: a refusal after the definition exists (the assignment's
// recomputation under the locks differs) deletes the definition, and its
// gid stays used.
func TestManageAsFolderRefusalDeletesDefinition(t *testing.T) {
	f, _, audit := manageFixture(t)
	ctx := context.Background()
	plan, err := f.h.PreviewFix(ctx, mediaFP, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Between the create and the assignment's validation (M5: an injected
	// hook, not the scan order), writer's ports change: the assignment's
	// recomputation under the locks differs.
	f.h.testHookManageDefined = func() {
		f.h.mu.Lock()
		s := f.h.st.Settings["writer"].Clone()
		s.Ports = map[string]string{}
		f.h.st.Settings["writer"] = s
		f.h.mu.Unlock()
	}
	_, err = f.h.ApplyFix(ctx, mediaFP, nil, plan.Hash, "admin")
	if statusOf(err) != 409 {
		t.Fatalf("apply: %v", err)
	}
	fs, gids := foldersOf(f)
	if _, ok := fs["media"]; ok || !slices.Equal(gids, []int{60000}) {
		t.Errorf("folders %v gids %v: the definition stays, or its gid was given back", fs, gids)
	}
	if v := value(f, "writer", "data"); v != "/srv/media" {
		t.Errorf("value %v", v)
	}
	if got := auditOf(audit, "folder.create"); len(got) != 1 || !strings.Contains(got[0], "ok gid=60000") {
		t.Errorf("folder.create = %v", got)
	}
	if got := auditOf(audit, "folder.delete"); len(got) != 1 || !strings.Contains(got[0], "media ok") {
		t.Errorf("folder.delete = %v", got)
	}
	if got := auditOf(audit, "doctor.fix"); len(got) != 1 || !strings.HasPrefix(got[0], mediaFP+" refused") {
		t.Errorf("doctor.fix = %v", got)
	}
	// The folder lock was released.
	unlock, err := f.h.folderLock("media")
	if err != nil {
		t.Fatalf("folder lock still held: %v", err)
	}
	unlock()
}

// ── explain-only and link findings ──────────────────────

func TestExplainOnlyHasNoPreview(t *testing.T) {
	f, _, audit := manageFixture(t)
	ctx := context.Background()
	writeFile(t, f.h.userOverridePath("jellyfin"), "services:\n  jellyfin:\n    volumes:\n      - /srv/media:/extra:ro\n")
	r, err := f.h.Doctor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fd *doctor.Finding
	for i := range r.Findings {
		if r.Findings[i].Kind == doctor.KindCustomOverrideMount {
			fd = &r.Findings[i]
		}
	}
	if fd == nil || fd.Class != doctor.FixExplain || len(fd.Steps) == 0 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	_, err = f.h.PreviewFix(ctx, fd.FP, nil)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "explain-only") || !strings.Contains(err.Error(), fd.Steps[0]) {
		t.Errorf("preview: %v", err)
	}
	if _, err := f.h.ApplyFix(ctx, fd.FP, nil, "x", "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "explain-only") {
		t.Errorf("apply: %v", err)
	}
	// The shared path with a custom-override use is explain-only too now.
	if _, err := f.h.PreviewFix(ctx, mediaFP, nil); statusOf(err) != 409 {
		t.Errorf("shared path: %v", err)
	}
	if got := auditOf(audit, "doctor.fix"); len(got) != 1 || !strings.Contains(got[0], "refused") {
		t.Errorf("doctor.fix = %v", got)
	}
}

// ── audit ───────────────────────────────────────────────

func TestFixAudited(t *testing.T) {
	f, audit := rebindFixture(t)
	ctx := context.Background()
	plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, ""); statusOf(err) != 401 {
		t.Errorf("no actor: %v", err)
	}
	op, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	waitInstanceOp(t, f, "samba", op.OpID)
	audit.mu.Lock()
	var fix []string
	for _, e := range audit.entries {
		if e.Action == "doctor.fix" {
			fix = append(fix, e.Actor+" "+e.Target+" "+e.Result+" "+e.Detail)
		}
	}
	audit.mu.Unlock()
	if len(fix) != 2 || fix[1] != "admin "+smbFP+" ok fix=rebind_port samba/SAMBA_SMB op="+op.OpID ||
		!strings.Contains(fix[0], "refused") {
		t.Errorf("doctor.fix = %q", fix)
	}
}

// ── reapply_folder and undo_folder ──────────────────────

func TestReapplyAndUndoFixes(t *testing.T) {
	f, d, audit := assignFixture(t)
	f.h.SetPeople(newFakePeople("erin"))
	ctx := context.Background()
	enable(t, f, "immich")
	if _, rec := assign(t, f, "media", AssignRequest{Uses: []FolderUse{{Instance: "immich", Key: "library"}}}); !rec.OK {
		t.Fatal(rec)
	}
	// The folder drifted since (a cached scan says so).
	fo, _ := storedFolder(f, "media")
	f.h.storeScan("media", &folderfix.Report{Version: 1, Mode: "scan", FSType: "ext4", ACL: true, Entries: 10, Dev: fo.Dev, Ino: fo.Ino,
		Expected: &folderfix.Conformance{Group: folderfix.Count{N: 4}}}, nil)
	fp := doctor.Fingerprint(doctor.KindFolderOwner, "folder:media")
	r, err := f.h.Doctor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fd *doctor.Finding
	for i := range r.Findings {
		if r.Findings[i].FP == fp {
			fd = &r.Findings[i]
		}
	}
	if fd == nil || fd.FixKind != doctor.FixReapplyFolder || !slices.Equal(fd.MoreFixes, []string{doctor.FixUndoFolder}) {
		t.Fatalf("findings = %+v", r.Findings)
	}

	// reapply_folder: the folder's current uses, kept, with a disk plan.
	plan, err := f.h.PreviewFix(ctx, fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != doctor.FixReapplyFolder || plan.Assign == nil || plan.Assign.Disk == nil || len(plan.Assign.Uses) != 1 ||
		plan.Assign.Uses[0].Change != "keep" || !strings.Contains(strings.Join(plan.Lines, "\n"), "A permissions snapshot is saved first.") {
		t.Fatalf("reapply plan = %+v / %+v", plan, plan.Assign)
	}
	snaps := len(f.h.listSnapshots("media"))
	if _, err := f.h.ApplyFix(ctx, fp, nil, plan.Hash, "admin"); err != nil {
		t.Fatal(err)
	}
	if rec := waitFolderOp(t, f, "media"); !rec.OK || rec.Op != OpFolderAssign {
		t.Fatalf("reapply = %+v", rec)
	}
	if n := len(f.h.listSnapshots("media")); n != snaps+1 {
		t.Errorf("snapshots %d → %d", snaps, n)
	}
	if v := value(f, "immich", "library"); v != "folder:media" {
		t.Errorf("library = %v", v)
	}

	// undo_folder: the undo of that last fix.
	f.h.storeScan("media", &folderfix.Report{Version: 1, Mode: "scan", FSType: "ext4", ACL: true, Entries: 10, Dev: fo.Dev, Ino: fo.Ino,
		Expected: &folderfix.Conformance{Group: folderfix.Count{N: 4}}}, nil)
	d.restore = folderfix.Report{Changed: 12720}
	undo, err := f.h.PreviewFix(ctx, fp, map[string]string{"fix": doctor.FixUndoFolder})
	if err != nil {
		t.Fatal(err)
	}
	if undo.Kind != doctor.FixUndoFolder || undo.Assign == nil || !strings.Contains(strings.Join(undo.Lines, "\n"), "12,720 entries go back") {
		t.Fatalf("undo plan = %+v", undo)
	}
	if _, err := f.h.ApplyFix(ctx, fp, map[string]string{"fix": doctor.FixUndoFolder}, plan.Hash, "admin"); statusOf(err) != 409 {
		t.Errorf("the reapply's hash on the undo: %v", err)
	}
	if _, err := f.h.ApplyFix(ctx, fp, map[string]string{"fix": doctor.FixUndoFolder}, undo.Hash, "admin"); err != nil {
		t.Fatal(err)
	}
	if rec := waitFolderOp(t, f, "media"); !rec.OK || rec.Op != OpFolderUndo {
		t.Fatalf("undo = %+v", rec)
	}
	if fo, _ := storedFolder(f, "media"); fo.LastApply != nil {
		t.Errorf("last apply kept: %+v", fo.LastApply)
	}
	got := auditOf(audit, "doctor.fix")
	if len(got) != 3 || !strings.Contains(got[0], "ok fix=reapply_folder media") || !strings.Contains(got[2], "ok fix=undo_folder media") {
		t.Errorf("doctor.fix = %v", got)
	}
}

// ── fix round 1 ─────────────────────────────────────────

// I1: compose publishes nothing for a host-network port, so <KEY>_BIND
// can't move it: no rebind_port, explain-only.
func TestRebindRefusedOnHostNetwork(t *testing.T) {
	f, _ := rebindFixture(t)
	ctx := context.Background()
	fp := doctor.Fingerprint(doctor.KindLANOnlyExposed, "samba", "SAMBA_WSDD", "udp")
	_, err := f.h.PreviewFix(ctx, fp, map[string]string{"address": "192.168.1.10"})
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "explain-only") || !strings.Contains(err.Error(), "firewall") {
		t.Fatalf("preview: %v", err)
	}
	// Even a finding claiming one-click finds no port to rebind.
	f.h.mu.RLock()
	_, ok := f.h.rebindPortLocked(doctor.Finding{FP: fp})
	f.h.mu.RUnlock()
	if ok {
		t.Error("a host-network port is rebindable")
	}
}

// failFirstUps makes the next n compose ups fail with a bind error.
func failFirstUps(f *fixture, n int) {
	hook, calls := f.runner.upHook, 0
	f.runner.upHook = func(p string) {
		hook(p)
		calls++
		if calls <= n {
			f.runner.upErr = &compose.Error{Command: "up", Err: errors.New("exit status 1"),
				Output: "Error response from daemon: failed to bind host port 192.168.1.10:445/tcp: cannot assign requested address"}
		} else {
			f.runner.upErr = nil
		}
	}
}

func applyRebind(t *testing.T, f *fixture, addr string) *OpRecord {
	t.Helper()
	ctx := context.Background()
	plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": addr})
	if err != nil {
		t.Fatal(err)
	}
	op, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": addr}, plan.Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return waitInstanceOp(t, f, "samba", op.OpID)
}

// I2: the rollback puts back only <KEY>_BIND, and only while it still is
// the rebind's address: a save committed during the restart is kept.
func TestRebindRollbackKeepsConcurrentSave(t *testing.T) {
	for _, tc := range []struct {
		name, bind string
		want       map[string]string
	}{
		{"other port", "192.168.1.10", map[string]string{"SAMBA_WEB": "8099"}},
		{"bind changed", "10.0.0.5", map[string]string{"SAMBA_WEB": "8099", "SAMBA_SMB_BIND": "10.0.0.5"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := rebindFixture(t)
			hook, calls := f.runner.upHook, 0
			saved := make(chan error, 1)
			f.runner.upHook = func(p string) {
				hook(p)
				calls++
				f.runner.upErr = nil
				if calls == 1 {
					// A settings save while the restart runs (it doesn't
					// take the instance lock).
					_, err := f.h.SaveSettings("samba", SettingsUpdate{Ports: map[string]string{"SAMBA_SMB_BIND": tc.bind, "SAMBA_WEB": "8099"}}, "bob")
					saved <- err
					f.runner.upErr = &compose.Error{Command: "up", Err: errors.New("exit status 1"), Output: "cannot assign requested address"}
				}
			}
			rec := applyRebind(t, f, "192.168.1.10")
			if err := <-saved; err != nil {
				t.Fatalf("save: %v", err)
			}
			if rec.OK {
				t.Fatalf("rebind = %+v", rec)
			}
			if p := storedPorts(f, "samba"); !maps.Equal(p, tc.want) {
				t.Errorf("ports = %v, want %v", p, tc.want)
			}
			ov, _ := os.ReadFile(f.h.overridePath("samba"))
			if !strings.Contains(string(ov), ":8099:80/tcp") {
				t.Errorf("override not regenerated from the current state:\n%s", ov)
			}
			if tc.bind != "192.168.1.10" && !strings.Contains(rec.Error, "changed since") {
				t.Errorf("error = %q", rec.Error)
			}
			waitIdle(t, f, "samba")
		})
	}
}

// waitIdle waits until no operation holds id's lock (a queued restart
// the save owed has run).
func waitIdle(t *testing.T, f *fixture, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if !f.h.appBusy(id) {
			return
		}
	}
}

// M1: rolled_back only when the start with the old bind worked.
func TestRebindRollbackStartFails(t *testing.T) {
	f, _ := rebindFixture(t)
	failFirstUps(f, 2)
	rec := applyRebind(t, f, "192.168.1.10")
	if rec.OK || rec.RolledBack || !strings.Contains(rec.Error, "starting Samba again failed") {
		t.Fatalf("rebind = %+v", rec)
	}
	if p := storedPorts(f, "samba"); p["SAMBA_SMB_BIND"] != "" {
		t.Errorf("ports = %v", p)
	}
}

// M2: a restart refused before anything stopped is rolled back without a
// start; a failed down alone (the up with the new bind worked) is no
// failed rebind.
func TestRebindRefusedBeforeStop(t *testing.T) {
	f, _ := rebindFixture(t)
	ctx := context.Background()
	plan, err := f.h.PreviewFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}
	// The custom override no longer fits: restartLocked refuses first.
	writeFile(t, f.h.userOverridePath("samba"), "services:\n  worker:\n    image: x\n")
	calls := len(f.runner.Calls())
	op, err := f.h.ApplyFix(ctx, smbFP, map[string]string{"address": "192.168.1.10"}, plan.Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	rec := waitInstanceOp(t, f, "samba", op.OpID)
	if rec.OK || !rec.RolledBack || !strings.Contains(rec.Error, "nothing was stopped") {
		t.Fatalf("rebind = %+v", rec)
	}
	if got := f.runner.Calls()[calls:]; len(got) != 0 {
		t.Errorf("compose ran: %v", got)
	}
	if p := storedPorts(f, "samba"); p["SAMBA_SMB_BIND"] != "" {
		t.Errorf("ports = %v", p)
	}
}

func TestRebindDownOnlyFailure(t *testing.T) {
	f, _ := rebindFixture(t)
	f.runner.downErr = errors.New("down: exit status 1")
	rec := applyRebind(t, f, "192.168.1.10")
	if !rec.OK || rec.RolledBack || len(rec.Warnings) == 0 || !strings.Contains(strings.Join(rec.Warnings, "\n"), "compose down failed") {
		t.Fatalf("rebind = %+v", rec)
	}
	if p := storedPorts(f, "samba"); p["SAMBA_SMB_BIND"] != "192.168.1.10" {
		t.Errorf("ports = %v", p)
	}
}

// M3: an accepted assignment that fails keeps the new definition, and
// its op record says so.
func TestManageAsFolderFailedOpNamesDefinition(t *testing.T) {
	f, d, _ := manageFixture(t)
	ctx := context.Background()
	plan, err := f.h.PreviewFix(ctx, mediaFP, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.applyExit = 1
	if _, err := f.h.ApplyFix(ctx, mediaFP, nil, plan.Hash, "admin"); err != nil {
		t.Fatal(err)
	}
	rec := waitFolderOp(t, f, "media")
	if rec.OK || !strings.Contains(rec.Error, "shared folder media was defined (gid 60000) and is kept: assign it again or delete it") {
		t.Fatalf("op = %+v", rec)
	}
	if fs, _ := foldersOf(f); fs["media"].GID != 60000 {
		t.Errorf("folders = %v", fs)
	}
}
