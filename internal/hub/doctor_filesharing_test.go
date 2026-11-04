package hub

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Plan 3 Task 11: the doctor's file-sharing checks and fixes (contract
// §14.5–14.6): the credential canary and revoke_leaver, per-person trees
// (former_account_folder, person_tree_owner and its childfix fix, F33),
// the hook report's findings, local_networks_empty (F35),
// unverifiable_account (F31), served_to_nobody (T10 carry), gid_from
// options refusing shared folders (F34). Fixture: credSvcFixture
// (smbfixture enabled; alice, bob and root have access) with its homes
// tree at /srv/homes on a fake disk.

func findingsOf(t *testing.T, f *fixture, kind string) []doctor.Finding {
	t.Helper()
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []doctor.Finding
	for _, fd := range r.Findings {
		if fd.Kind == kind {
			out = append(out, fd)
		}
	}
	return out
}

func TestCanaryFindsUnrevokedHolder(t *testing.T) {
	c := credSvcFixture(t)
	f := c.f
	c.create(t, "bob")
	c.create(t, "alice")
	if got := findingsOf(t, f, doctor.KindCredentialWithoutAccess); len(got) != 0 {
		t.Fatalf("canary with everyone in: %+v", got)
	}
	// bob leaves; the holder check doesn't run (stubbed): the canary sees it.
	c.people.removeMember("users_"+smbID, "bob")
	got := findingsOf(t, f, doctor.KindCredentialWithoutAccess)
	if len(got) != 1 {
		t.Fatalf("canary = %+v", got)
	}
	fd := got[0]
	if fd.Severity != doctor.Problem || fd.FP != doctor.CredentialFP(smbID, smbKey, "bob") || !slices.Equal(fd.Instances, []string{smbID}) ||
		!strings.Contains(fd.Title, "bob") || fd.FixKind != doctor.FixRevokeLeaver {
		t.Fatalf("canary = %+v", fd)
	}
	plan, err := f.h.PreviewFix(context.Background(), fd.FP, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Lines, []string{"revoke bob's file-share password for SMB Fixture"}) || plan.Hash == "" {
		t.Fatalf("preview = %+v", plan)
	}
	if _, err := f.h.ApplyFix(context.Background(), fd.FP, nil, strings.Repeat("0", 64), "admin"); errStatus(err) != 409 {
		t.Fatalf("wrong hash: %v, want 409", err)
	}
	op, err := f.h.ApplyFix(context.Background(), fd.FP, nil, plan.Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if r := waitInstanceOp(t, f, smbID, op.OpID); !r.OK {
		t.Fatalf("op = %+v", r)
	}
	f.h.mu.RLock()
	cr := f.h.st.Credentials[smbID][smbKey]["bob"]
	alice := f.h.st.Credentials[smbID][smbKey]["alice"]
	f.h.mu.RUnlock()
	if cr.Active() || cr.Reason != state.CredentialReasonAdmin || cr.RevokedBy != "admin" || !alice.Active() {
		t.Errorf("bob = %+v (alice active %v), want revoked by the admin", cr, alice.Active())
	}
	if _, ok := c.hashFile("bob"); ok {
		t.Error("bob's hash file is still there")
	}
	if a := credAudits(c.audit, "credential.revoke"); len(a) != 1 || !strings.HasPrefix(a[0], "admin ") {
		t.Errorf("credential.revoke audits = %q", a)
	}
	if a := credAudits(c.audit, "doctor.fix"); len(a) != 2 || !strings.Contains(a[1], "fix=revoke_leaver "+smbID) || !strings.Contains(a[1], " ok") {
		t.Errorf("doctor.fix audits = %q", a)
	}
	if got := findingsOf(t, f, doctor.KindCredentialWithoutAccess); len(got) != 0 {
		t.Errorf("canary after the fix: %+v", got)
	}
}

// treeEnv is credSvcFixture with the fixer's own image, a fake disk and
// smbfixture's homes tree at /srv/homes (alice's directory 0700 with
// group 100, a former account's "dave" (uid 20777), a file).
type treeEnv struct {
	*credSvc
	d     *fakeDisk
	alice int
}

func treeFixture(t *testing.T) *treeEnv {
	t.Helper()
	c := credSvcFixture(t)
	f := c.f
	fx := f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	d := &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}
	fx.run = d.run
	alice := mustPersonID(t, f.h, "alice")
	tree := d.add("/srv/homes", "ext4")
	d.add("/srv/homes/alice", "ext4")
	tree.children = []folderfix.ChildOwner{
		{Name: "alice", UID: alice, GID: 100, Mode: 0o700, Dir: true},
		{Name: "dave", UID: 20777, GID: 20777, Mode: 0o700, Dir: true},
		{Name: "readme.txt", UID: 0, GID: 0, Mode: 0o644},
	}
	if err := f.h.save(smbID, SettingsUpdate{Values: vals("homes", "/srv/homes")}); err != nil {
		t.Fatal(err)
	}
	settle(f)
	return &treeEnv{credSvc: c, d: d, alice: alice}
}

func (e *treeEnv) scan(t *testing.T) {
	t.Helper()
	if _, err := e.f.h.StartDoctorScan("admin"); err != nil {
		t.Fatal(err)
	}
	if r := waitDoctorOp(t, e.f.h); !r.OK {
		t.Fatalf("scan op = %+v", r)
	}
}

func TestPersonTreeOwnerFix(t *testing.T) {
	e := treeFixture(t)
	f := e.f
	e.scan(t)
	// The tree's scan: its first level only, no principals (F33).
	var scans []docker.RunSpec
	for _, s := range f.engine.fx().Specs() {
		if fixerMode(s.Cmd) == "scan" && s.Binds[0].Source == "/srv/homes" {
			scans = append(scans, s)
		}
	}
	if len(scans) != 1 {
		t.Fatalf("tree scans = %d", len(scans))
	}
	if _, ok := argValue(scans[0].Cmd, "top-only"); !ok || len(argValues(scans[0].Cmd, "principal")) != 0 {
		t.Errorf("tree scan argv = %q", scans[0].Cmd)
	}
	// F8: the owners it lists are never handed out.
	f.h.mu.RLock()
	seen := f.h.st.PersonIDs[templates.PoolPOSIXUID].Seen
	f.h.mu.RUnlock()
	if !slices.ContainsFunc(seen, func(o state.SeenOwner) bool { return o.ID == 20777 }) {
		t.Errorf("seen owners = %+v, want 20777", seen)
	}

	got := findingsOf(t, f, doctor.KindPersonTreeOwner)
	var fd *doctor.Finding
	infos := 0
	for i := range got {
		switch got[i].Severity {
		case doctor.Warning:
			fd = &got[i]
		case doctor.Info:
			infos++
		}
	}
	if fd == nil || fd.FP != doctor.TreeFP(doctor.KindPersonTreeOwner, smbID, "homes", "alice") || infos != 1 {
		t.Fatalf("person_tree_owner = %+v", got)
	}
	// dave isn't a current person: only the Info lists him (no former
	// account finding without a person of that name).
	if fa := findingsOf(t, f, doctor.KindFormerAccountFolder); len(fa) != 0 {
		t.Errorf("former_account_folder = %+v", fa)
	}
	plan, err := f.h.PreviewFix(context.Background(), fd.FP, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "chown " + strconv.Itoa(e.alice) + ":" + strconv.Itoa(e.alice) + " + chmod 0700 /srv/homes/alice (not recursive)"
	if !slices.Equal(plan.Lines, []string{want}) {
		t.Fatalf("preview lines = %q, want exactly %q", plan.Lines, want)
	}
	// The preview is a read-only probe of the child; nothing changes.
	last := f.engine.fx().Specs()
	if s := last[len(last)-1]; fixerMode(s.Cmd) != "probe" || !s.Binds[0].ReadOnly {
		t.Errorf("preview ran %q (read-only %v)", s.Cmd, s.Binds[0].ReadOnly)
	}

	// Another inode since the preview: 409, nothing run.
	e.d.mu.Lock()
	e.d.paths["/srv/homes/alice"].ino++
	e.d.mu.Unlock()
	if _, err := f.h.ApplyFix(context.Background(), fd.FP, nil, plan.Hash, "admin"); errStatus(err) != 409 {
		t.Fatalf("moved child: %v, want 409", err)
	}
	e.d.mu.Lock()
	e.d.paths["/srv/homes/alice"].ino--
	e.d.mu.Unlock()

	op, err := f.h.ApplyFix(context.Background(), fd.FP, nil, plan.Hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if r := waitInstanceOp(t, f, smbID, op.OpID); !r.OK {
		t.Fatalf("op = %+v", r)
	}
	var fix *docker.RunSpec
	for _, s := range f.engine.fx().Specs() {
		if fixerMode(s.Cmd) == "childfix" {
			s := s
			fix = &s
		}
	}
	if fix == nil {
		t.Fatal("no childfix run")
	}
	alice := e.d.paths["/srv/homes/alice"]
	for flag, v := range map[string]string{"root": "/broot", "rel": "homes", "child": "alice:" + strconv.Itoa(e.alice),
		"expect-dev": strconv.FormatUint(alice.dev, 10), "expect-ino": strconv.FormatUint(alice.ino, 10), "expect-mount-root": "/srv/homes/alice"} {
		if got, _ := argValue(fix.Cmd, flag); got != v {
			t.Errorf("childfix --%s = %q, want %q (%q)", flag, got, v, fix.Cmd)
		}
	}
	if b := fix.Binds[0]; b.Source != "/srv" || b.Target != "/broot" || b.ReadOnly || !slices.Equal(fix.CapAdd, []string{"CHOWN", "FOWNER"}) {
		t.Errorf("childfix bind %+v caps %v", b, fix.CapAdd)
	}
	if a := credAudits(e.audit, "doctor.fix"); len(a) != 2 || !strings.Contains(a[0], " refused ") || !strings.Contains(a[1], "fix=person_tree_owner "+smbID+" /srv/homes/alice") || !strings.Contains(a[1], " ok") {
		t.Errorf("doctor.fix audits = %q", a)
	}
	// The tree was checked again: alice's directory is fine now.
	for _, fd := range findingsOf(t, f, doctor.KindPersonTreeOwner) {
		if fd.Severity == doctor.Warning {
			t.Errorf("after the fix: %+v", fd)
		}
	}
}

func TestFormerAccountFinding(t *testing.T) {
	e := treeFixture(t)
	f := e.f
	// The hook report alone (no scan yet): alice's folder is a former
	// account's.
	writeReport(t, f, settings.HookReport{Version: 1, Findings: []settings.HookFinding{
		{Code: "former_account", Severity: "warning", Subject: "alice", Message: "alice's folder is owned by uid 20023", Option: "homes", UID: ptr64(20023)},
	}})
	got := findingsOf(t, f, doctor.KindFormerAccountFolder)
	if len(got) != 1 || got[0].Title != "alice's SMB Fixture folder belongs to a former account (uid 20023)." || got[0].Class != doctor.FixExplain {
		t.Fatalf("from the report = %+v", got)
	}
	fp := got[0].FP
	if _, err := f.h.PreviewFix(context.Background(), fp, nil); errStatus(err) != 409 || !strings.Contains(err.Error(), "explain-only") {
		t.Errorf("preview: %v, want 409 explain-only", err)
	}
	// The scan (newer) says the same: the same fingerprint.
	e.d.mu.Lock()
	e.d.paths["/srv/homes"].children[0].UID = 20023
	e.d.mu.Unlock()
	time.Sleep(10 * time.Millisecond)
	e.scan(t)
	got = findingsOf(t, f, doctor.KindFormerAccountFolder)
	if len(got) != 1 || got[0].FP != fp || got[0].Title != "alice's SMB Fixture folder belongs to a former account (uid 20023)." {
		t.Errorf("from the scan = %+v, want fp %s", got, fp)
	}
}

func ptr64(n int64) *int64 { return &n }

// writeReport stores rep as smbfixture's last hook report.
func writeReport(t *testing.T, f *fixture, rep settings.HookReport) {
	t.Helper()
	b, err := json.Marshal(StoredHookReport{Hook: "sync", ReceivedAt: time.Now().UTC(), Report: rep})
	if err != nil {
		t.Fatal(err)
	}
	p := f.h.hookReportPath(smbID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHookReportFindingsInDoctor(t *testing.T) {
	c := credSvcFixture(t)
	writeReport(t, c.f, settings.HookReport{Version: 1, Findings: []settings.HookFinding{
		{Code: "name_refused", Severity: "info", Subject: "Family", Message: "share name <b>homes</b> is reserved"},
		{Code: "owner_unwritable", Severity: "problem", Subject: "alice", Message: "can't write alice's folder", Option: "homes"},
	}})
	nr := findingsOf(t, c.f, doctor.KindNameRefused)
	if len(nr) != 1 || nr[0].Severity != doctor.Info || !strings.Contains(nr[0].Title, "share name <b>homes</b> is reserved") || !slices.Equal(nr[0].Instances, []string{smbID}) {
		t.Errorf("name_refused = %+v", nr)
	}
	if ou := findingsOf(t, c.f, doctor.KindOwnerUnwritable); len(ou) != 1 || ou[0].Severity != doctor.Problem {
		t.Errorf("owner_unwritable = %+v", ou)
	}
}

func TestLocalNetworksEmptyProblem(t *testing.T) {
	c := credSvcFixture(t)
	if got := findingsOf(t, c.f, doctor.KindLocalNetworksEmpty); len(got) != 0 {
		t.Fatalf("with the defaults: %+v", got)
	}
	if err := c.f.h.SetLocalNetworks([]string{}, "admin"); err != nil {
		t.Fatal(err)
	}
	settle(c.f)
	got := findingsOf(t, c.f, doctor.KindLocalNetworksEmpty)
	if len(got) != 1 || got[0].Severity != doctor.Problem || got[0].Title != "Local networks is empty; file sharing is off." || !slices.Equal(got[0].Instances, []string{smbID}) {
		t.Errorf("local_networks_empty = %+v", got)
	}
}

func TestUnverifiableAccountProblem(t *testing.T) {
	c := credSvcFixture(t)
	c.create(t, "alice")
	c.people.set(func(p *fakePeople) { p.uuids = map[string]string{"alice": ""} })
	got := findingsOf(t, c.f, doctor.KindUnverifiableAccount)
	if len(got) != 1 || got[0].Severity != doctor.Problem || got[0].Title != "SMB Fixture: can't verify alice's account." {
		t.Errorf("unverifiable_account = %+v", got)
	}
}

func TestServedToNobodyWarning(t *testing.T) {
	c := credSvcFixture(t)
	setStored(c.f, smbID, "share1_folder", "/srv/share1")
	got := findingsOf(t, c.f, doctor.KindServedToNobody)
	if len(got) != 1 || got[0].Severity != doctor.Warning || got[0].Title != "Share 1 folder of SMB Fixture is served to nobody." ||
		got[0].Link == nil || got[0].Link.Instance != smbID {
		t.Fatalf("served_to_nobody = %+v", got)
	}
	setStored(c.f, smbID, "share1_writers", []any{"users_" + smbID})
	if got := findingsOf(t, c.f, doctor.KindServedToNobody); len(got) != 0 {
		t.Errorf("with writers: %+v", got)
	}
}

// TestGIDFromRefusesFolderValue (F34): a per-person tree never takes a
// shared folder (save 409, assignment preview 409), gets no
// PORTCULLIS_FOLDER_GID_<KEY>, resolves to no single owner and is never a
// shared_path subject (even used twice) nor a hand-typed scan target.
func TestGIDFromRefusesFolderValue(t *testing.T) {
	e := treeFixture(t)
	f := e.f
	addFolder(t, f, e.d, "photos", "Photos", "/srv/photos", 60001)
	_, err := f.h.SaveSettings(smbID, SettingsUpdate{Values: vals("homes", "folder:photos")}, "admin")
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "per-person tree") {
		t.Errorf("save folder:photos: %v, want 409 per-person tree", err)
	}
	_, err = f.h.PreviewAssign(context.Background(), "photos", AssignRequest{Uses: []FolderUse{{Instance: smbID, Key: "homes"}}})
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "per-person tree") {
		t.Errorf("assignment preview: %v, want 409 per-person tree", err)
	}
	var homes *PathUsage
	for _, u := range f.h.PathUsages() {
		if u.Instance == smbID && u.Key == "homes" {
			u := u
			homes = &u
		}
	}
	if homes == nil || homes.OwnerKnown || !homes.PersonTree || homes.HostPath != "/srv/homes" {
		t.Fatalf("homes usage = %+v", homes)
	}
	f.h.mu.RLock()
	env := f.h.folderEnvLocked(f.h.findLocked(smbID))
	targets := f.h.scanTargetsLocked()
	f.h.mu.RUnlock()
	if _, ok := env[templates.FolderGIDVar("homes")]; ok {
		t.Errorf("env has %s", templates.FolderGIDVar("homes"))
	}
	if _, ok := env[templates.FolderGIDVar("share1_folder")]; !ok {
		t.Errorf("env lacks %s", templates.FolderGIDVar("share1_folder"))
	}
	n := 0
	for _, tg := range targets {
		if tg.Path == "/srv/homes" {
			n++
			if !tg.Children || len(tg.Principals) != 0 || tg.Target != nil || !slices.Equal(tg.Pools, []string{templates.PoolPOSIXUID}) {
				t.Errorf("tree target = %+v", tg)
			}
		}
	}
	if n != 1 {
		t.Errorf("targets = %+v", targets)
	}
	// Two instances on the same tree: still no shared_path.
	in, err := f.h.doctorInputs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	twice := *homes
	twice.Instance = smbB
	in.Paths = append(in.Paths, pathIn(twice))
	r := doctor.Run(in, nil)
	for _, fd := range r.Findings {
		if (fd.Kind == doctor.KindSharedPath || fd.Kind == doctor.KindFolderOwner) && slices.Contains(fd.Paths, "/srv/homes") {
			t.Errorf("a per-person tree as a %s subject: %+v", fd.Kind, fd)
		}
	}
}
