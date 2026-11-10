package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// rewriteMember replaces one member of an archive and its MANIFEST sum
// (an archive that verifies but carries other content).
func rewriteMember(t *testing.T, p, name string, content []byte) {
	t.Helper()
	names, data, _ := readArchive(t, p)
	var m BackupManifest
	if err := json.Unmarshal(data["MANIFEST.json"], &m); err != nil {
		t.Fatal(err)
	}
	data[name] = content
	sum := sha256.Sum256(content)
	m.Files[name] = hex.EncodeToString(sum[:])
	data["MANIFEST.json"], _ = json.Marshal(m)
	writeArchive(t, p, names, data)
}

// Fix round 1, Important 1: a restored configuration meets SaveSettings'
// rules; refused (409, every problem listed) before anything changes.
func TestRestoreRefusesInvalidConfig(t *testing.T) {
	f, _, groups := grafanaB(t)
	// An archive without settings (the first start's stamp dropped):
	// the test adds its own settings block.
	forgetFirstStart(f, "grafana-b")
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	p := archivePath(f, entry.Archive)
	_, data, _ := readArchive(t, p)
	bad := strings.Replace(string(data["config/instance.yaml"]), "enabled: true", "enabled: true\nsign_in: native\npublic_mode: listed\nsettings:\n  values:\n    bad key: x", 1)
	rewriteMember(t, p, "config/instance.yaml", []byte(bad))
	n, hl := len(f.runner.Calls()), len(f.engine.vol().helperLog)
	_, err = f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root"))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), `unknown setting "bad key"`) || !strings.Contains(err.Error(), "sign-in choice") || !strings.Contains(err.Error(), "public exceptions") {
		t.Fatalf("same-instance restore of a bad config = %v", err)
	}
	_, err = f.h.RestoreInstanceAs(entry.Archive, "grafana-c", directory.Human("root"))
	if statusOf(err) != 409 || !strings.Contains(err.Error(), `unknown setting "bad key"`) {
		t.Fatalf("new-id restore of a bad config = %v", err)
	}
	if len(f.runner.Calls()) != n || len(f.engine.vol().helperLog) != hl || f.h.Template("grafana-c") != nil || len(groups.Calls()) != 0 {
		t.Error("something changed")
	}
	if fi, _ := os.ReadDir(filepath.Dir(p)); len(fi) != 1 {
		t.Errorf("a pre-restore backup was taken: %v", fi)
	}
}

// Fix round 1, Important 2: a same-instance restore interrupted half-way
// (the Hub died) is recorded as "restoring" and rolled back from its
// pre-restore backup at the next start; meanwhile nothing may start or
// change the instance.
func TestInterruptedRestoreRolledBack(t *testing.T) {
	f, _, _ := grafanaB(t)
	f.h.mu.Lock()
	f.h.st.Settings["grafana-b"] = state.InstanceSettings{Ports: map[string]string{"GRAFANA_PORT": "3401"}}
	f.h.saveLocked()
	f.h.mu.Unlock()
	secret := readEnvFile(f.h.envPath("grafana-b"))["GF_SECRET"]
	// What a restore does up to its crash: the pre-restore backup, the
	// record, then half of the data replaced.
	unlock, _ := f.h.lockApp("grafana-b")
	pre, err := f.h.backupLocked("grafana-b", BackupRestore, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.markRestoring("grafana-b", pre.Archive); err != nil {
		t.Fatal(err)
	}
	putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "half", Body: "restored"})
	setEnvVar(f.h.envPath("grafana-b"), "GF_SECRET", "half")
	unlock()

	// While "restoring": listed so, and nothing starts or changes it.
	var st string
	for _, v := range f.h.Instances() {
		if v.ID == "grafana-b" {
			st = v.State
		}
	}
	if st != StateRestoring || f.h.IsEnabled("grafana-b") {
		t.Fatalf("state %q, enabled %v", st, f.h.IsEnabled("grafana-b"))
	}
	for name, err := range map[string]error{
		"enable":   f.h.Enable("grafana-b"),
		"settings": f.h.save("grafana-b", SettingsUpdate{}),
		"env":      envOverrideErr(f.h, "grafana-b", "X", "y"),
		"hosts":    f.h.SetHosts("grafana-b", map[string]string{"grafana": "g2.example.org"}, directory.Human("root")),
	} {
		if statusOf(err) != 409 {
			t.Errorf("%s while restoring = %v", name, err)
		}
	}
	if _, _, err := f.h.SaveUserOverride("grafana-b", ""); statusOf(err) != 409 {
		t.Errorf("custom override while restoring = %v", err)
	}
	if _, err := f.h.BackupInstance("grafana-b", directory.Human("root")); statusOf(err) != 409 {
		t.Errorf("backup while restoring = %v", err)
	}
	f.h.mu.Lock()
	f.h.st.SetEnabled("grafana-b", true) // as drift would see a stale enabled flag
	f.h.rebuildLocked()
	f.h.mu.Unlock()
	if err := f.h.ResolveDrift("grafana-b", ActionStart); statusOf(err) != 409 {
		t.Errorf("drift start while restoring = %v", err)
	}
	f.h.mu.Lock()
	f.h.st.SetEnabled("grafana-b", false)
	f.h.rebuildLocked()
	f.h.mu.Unlock()

	// The Hub restarts: the restore is rolled back.
	f.h.Wait()
	h2, err := New(f.h.cfg, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h2.lockPoll = 5 * time.Millisecond
	f.h = h2
	h2.Init()
	h2.Wait()
	if got := f.engine.volumeFiles("portcullis_grafana-b-grafana-data"); got["grafana.db"].Body != "v1" || got["half"].Body != "" {
		t.Errorf("volume after recovery = %+v", got)
	}
	if got := readEnvFile(h2.envPath("grafana-b"))["GF_SECRET"]; got != secret {
		t.Errorf("env after recovery = %s", got)
	}
	h2.mu.RLock()
	e, inState := h2.st.Instances["grafana-b"]
	k := h2.st.Settings["grafana-b"].Ports["GRAFANA_PORT"]
	h2.mu.RUnlock()
	if e.State != "" || e.Backup != "" || !inState || k != "3401" || !h2.IsEnabled("grafana-b") {
		t.Errorf("after recovery: entry %+v, K=%s, enabled %v", e, k, h2.IsEnabled("grafana-b"))
	}
	if lo := h2.LastOp("grafana-b"); lo == nil || lo.Op != OpRestore || lo.OK || !lo.RolledBack {
		t.Errorf("last op = %+v", lo)
	}
}

// The next RestoreInstance call rolls an interrupted restore back first,
// then restores what was asked.
func TestRestoreAfterInterruptedRestore(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "grafana.db", Mode: 0600, UID: 472, Body: "v2"})
	unlock, _ := f.h.lockApp("grafana-b")
	pre, err := f.h.backupLocked("grafana-b", BackupRestore, true)
	if err != nil {
		t.Fatal(err)
	}
	f.h.markRestoring("grafana-b", pre.Archive)
	putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "garbage", Body: "x"})
	unlock()
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	files := f.engine.volumeFiles("portcullis_grafana-b-grafana-data")
	if files["grafana.db"].Body != "v1" || files["garbage"].Body != "" {
		t.Errorf("volume = %+v", files)
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e.State != "" || !f.h.IsEnabled("grafana-b") {
		t.Errorf("entry %+v enabled %v", e, f.h.IsEnabled("grafana-b"))
	}
}

// Fix round 1, Important 3: only groups named exactly users_<id> /
// admin_<id> are deleted; any other manifest group is kept.
func TestDeleteKeepsGroupsWithOtherNames(t *testing.T) {
	m := strings.NewReplacer("grafana", "media", "Grafana", "Media", "GRAFANA", "MEDIA").Replace(v2GrafanaManifest)
	m = strings.Replace(m, "access_group: users_media", "access_group: family", 1)
	c := strings.NewReplacer("grafana", "media", "GRAFANA", "MEDIA").Replace(v2GrafanaCompose)
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"media": {m, c}})
	groups := &fakeGroups{}
	f.h.SetGroups(groups)
	simulateCompose(f, 0)
	if f.h.Template("media") == nil {
		t.Fatal("media not loaded")
	}
	res, err := f.h.DeleteInstance("media", "media", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(groups.Calls(), ","); got != "-admin_media:root" {
		t.Errorf("groups = %s", got)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "group family was kept") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

// Minor 10: an actor the directory can't resolve fails before anything
// is deleted or created.
func TestActorResolvedFirst(t *testing.T) {
	f, _, groups := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	groups.actorErr = errors.New("not an administrator")
	if _, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("mallory")); err == nil || !strings.Contains(err.Error(), "nothing was deleted") {
		t.Fatalf("delete as an unknown actor = %v", err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", directory.Human("mallory")); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("restore as an unknown actor = %v", err)
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 1 || f.h.Template("grafana-c") != nil || !f.h.IsEnabled("grafana-b") {
		t.Errorf("something changed: backups %d", len(l))
	}
}

// Minor 1 + 8: a missing template whose snapshot lists no clients falls
// back to the derived client id (warned); no IdP is a warning.
func TestDeleteMissingTemplateClients(t *testing.T) {
	f := newInstanceFixture(t, nil)
	simulateCompose(f, 0)
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	snap := f.h.st.Published["chat-b"]
	snap.Clients = nil
	f.h.st.Published["chat-b"] = snap
	f.h.saveLocked()
	f.h.mu.Unlock()
	os.RemoveAll(filepath.Join(f.src, "chat"))
	f.h.Discover()
	if f.h.Template("chat-b") != nil {
		t.Fatal("chat-b still resolves")
	}
	res, err := f.h.DeleteInstance("chat-b", "chat-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.idp.deleted, ",") != "chat-b:chat-b" || !strings.Contains(strings.Join(res.Warnings, " "), "derived client id chat-b") {
		t.Errorf("deleted %v, warnings %v", f.idp.deleted, res.Warnings)
	}

	g := newInstanceFixture(t, nil)
	simulateCompose(g, 0)
	g.h.idp = nil
	res, err = g.h.DeleteInstance("grafana", "grafana", directory.Human("root"))
	if err != nil || !strings.Contains(strings.Join(res.Warnings, " "), "Keycloak is not configured") {
		t.Errorf("delete without an IdP = %+v %v", res, err)
	}
}

// Minor 2: a volume that appears between the plan and the fill is never
// touched (nor removed by an undo).
func TestFillVolumeRefusesForeignVolume(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.engine.addVolume("portcullis_x-data", "someone-else", "data", 0, fakeFile{Name: "theirs", Body: "keep"})
	created, err := f.h.fillVolume(t.Context(), "x", composeVolume("x", "data", "portcullis_x-data"), false, "")
	if err == nil || created || f.engine.volumeFiles("portcullis_x-data")["theirs"].Body != "keep" {
		t.Errorf("fill over a foreign volume: created %v, %v", created, err)
	}
}

// Minor 3: leftovers of an interrupted backup or restore are removed at
// startup; archives stay.
func TestSweepBackupLeftovers(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.CreateHelper(t.Context(), helperSpecFor("portcullis_grafana-b-grafana-data")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.data, "backups", "grafana-b")
	os.MkdirAll(filepath.Join(dir, ".staging-123", "volumes"), 0700)
	writeFile(t, filepath.Join(dir, "20260101T000000Z.tar.partial"), "x")
	os.MkdirAll(filepath.Join(f.data, "backups", ".staging", "restore-1"), 0700)
	f.h.SweepBackupLeftovers()
	fi, _ := os.ReadDir(dir)
	if len(fi) != 1 || fi[0].Name() != filepath.Base(entry.Archive) {
		t.Errorf("backup dir = %v", fi)
	}
	if _, err := os.Stat(filepath.Join(f.data, "backups", ".staging")); !errors.Is(err, os.ErrNotExist) {
		t.Error("restore staging left")
	}
	if len(f.engine.vol().helpers) != 0 {
		t.Error("helper container left")
	}
}

// Minor 4: too little free space refuses before anything stops.
func TestBackupRestoreNeedFreeSpace(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	old := freeSpace
	t.Cleanup(func() { freeSpace = old })
	freeSpace = func(string) (uint64, error) { return 1 << 20, nil }
	n := len(f.runner.Calls())
	if _, err := f.h.BackupInstance("grafana-b", directory.Human("root")); statusOf(err) != 507 || !strings.Contains(err.Error(), "free space") {
		t.Errorf("backup on a full disk = %v", err)
	}
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root")); statusOf(err) != 507 {
		t.Errorf("restore on a full disk = %v", err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", directory.Human("root")); statusOf(err) != 507 {
		t.Errorf("new-id restore on a full disk = %v", err)
	}
	if len(f.runner.Calls()) != n || !f.h.IsEnabled("grafana-b") {
		t.Errorf("something ran: %v", f.runner.Calls()[n:])
	}
}

// Minor 5: a same-instance restore empties the project's volumes the
// archive doesn't have (their data is in the pre-restore backup).
func TestRestoreEmptiesVolumesNotInArchive(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	f.engine.addVolume("portcullis_grafana-b-extra", "portcullis-grafana-b", "extra", 0, fakeFile{Name: "x", Body: "later"})
	res, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	files := f.engine.volumeFiles("portcullis_grafana-b-extra")
	if files == nil || files["x"].Body != "" || len(files) != 1 {
		t.Errorf("extra volume = %+v", files)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "portcullis_grafana-b-extra is not in the archive") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	_, data, _ := readArchive(t, archivePath(f, res.PreRestoreBackup))
	if innerTar(t, data["volumes/extra.tar"])["data/x"] == nil {
		t.Error("the pre-restore backup lacks the emptied volume's data")
	}
}

// Minor 6: deleting marks the instance disabled with "deleting", so a
// failure in step 3 can't leave it startable.
func TestDeletingIsDisabled(t *testing.T) {
	f, _, _ := grafanaB(t)
	// The backup's down works; the delete's own down (step 3) fails.
	f.engine.vol().copyFromErr = func(string) error {
		f.runner.downErr = errors.New("compose down failed")
		f.runner.byNameErr = errors.New("compose down failed")
		return nil
	}
	if _, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root")); err == nil {
		t.Fatal("delete with a failing down succeeded")
	}
	f.runner.downErr, f.runner.byNameErr = nil, nil
	if f.h.IsEnabled("grafana-b") {
		t.Error("still enabled while deleting")
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e.State != state.InstanceDeleting {
		t.Fatalf("entry = %+v", e)
	}
	if err := f.h.save("grafana-b", SettingsUpdate{}); statusOf(err) != 409 {
		t.Errorf("settings while deleting = %v", err)
	}
	if err := envOverrideErr(f.h, "grafana-b", "X", "y"); statusOf(err) != 409 {
		t.Errorf("env while deleting = %v", err)
	}
	if _, _, err := f.h.SaveUserOverride("grafana-b", ""); statusOf(err) != 409 {
		t.Errorf("custom override while deleting = %v", err)
	}
}

// Minor 7: host paths aren't copied by a new-id restore: warned.
func TestRestoreNewIDWarnsPathSettings(t *testing.T) {
	m := strings.NewReplacer("grafana", "media", "Grafana", "Media", "GRAFANA", "MEDIA").Replace(v2GrafanaManifest) +
		"settings:\n  options:\n    - {key: library, label: Library, type: path, target: {service: web, mount: /library}}\n"
	c := strings.NewReplacer("grafana", "media", "GRAFANA", "MEDIA").Replace(v2GrafanaCompose)
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"media": {m, c}})
	simulateCompose(f, 0)
	if f.h.Template("media") == nil {
		t.Fatal("media not loaded")
	}
	if err := f.h.CreateInstance("media", "media-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.save("media-b", SettingsUpdate{Values: vals("library", "/srv/library")}); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("media-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.h.RestoreInstanceAs(entry.Archive, "media-c", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if w := strings.Join(res.Warnings, " "); !strings.Contains(w, "library") || !strings.Contains(w, "/srv/library") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func helperSpecFor(vol string) docker.HelperSpec {
	return docker.HelperSpec{Image: HelperImage, Volumes: map[string]string{vol: "/data"}, ReadOnly: true, Instance: "grafana-b"}
}

// Re-review N1: an interrupted restore whose recorded archive isn't the
// instance's own pre-restore backup is refused; nothing is touched.
func TestRecoverRefusesForeignArchive(t *testing.T) {
	f, _, _ := grafanaB(t)
	if err := f.h.CreateInstance("grafana", "grafana-c", nil); err != nil {
		t.Fatal(err)
	}
	other, err := f.h.BackupInstance("grafana-c", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	own, err := f.h.BackupInstance("grafana-b", directory.Human("root")) // reason manual
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range []string{other.Archive, own.Archive, "../x.tar"} {
		f.h.mu.Lock()
		e := f.h.st.Instances["grafana-b"]
		e.State, e.Backup = state.InstanceRestoring, rec
		f.h.st.Instances["grafana-b"] = e
		f.h.saveLocked()
		f.h.mu.Unlock()
		putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "now", Body: "keep"})
		n, hl := len(f.runner.Calls()), len(f.engine.vol().helperLog)
		_, err := f.h.RestoreInstance("grafana-b", own.Archive, directory.Human("root"))
		if statusOf(err) != 409 {
			t.Errorf("recorded %s: %v", rec, err)
		}
		if len(f.runner.Calls()) != n || len(f.engine.vol().helperLog) != hl || f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["now"].Body != "keep" {
			t.Errorf("recorded %s: something was touched", rec)
		}
	}
}

// Re-review N2 + N4 (sign-in Task 4): a restored sign-in template pick
// is stored when it names an enabled template here (a disabled one is
// refused, never the default instead), and a never-enabled instance stays
// "created".
func TestRestoreSignInTemplateKeepsCreated(t *testing.T) {
	f := newInstanceFixture(t, nil)
	simulateCompose(f, 0)
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	p := archivePath(f, entry.Archive)
	_, data, _ := readArchive(t, p)
	cfg := string(data["config/instance.yaml"])
	if !strings.Contains(cfg, "state: created") {
		t.Fatalf("instance.yaml lacks the created state:\n%s", cfg)
	}
	rewriteMember(t, p, "config/instance.yaml", []byte(cfg+"sign_in_template: basic\n"))
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled template restored: %v", err)
	}
	rewriteMember(t, p, "config/instance.yaml", []byte(cfg+"sign_in_template: strong\n"))
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e.SignInTemplate != "strong" {
		t.Errorf("pick = %q", e.SignInTemplate)
	}
	if e.State != state.InstanceCreated {
		t.Errorf("state after restore = %q", e.State)
	}
	var st string
	for _, v := range f.h.Instances() {
		if v.ID == "grafana-b" {
			st = v.State
		}
	}
	if st != StateCreated {
		t.Errorf("view state = %s", st)
	}
}

// Re-review N2: turning on public exceptions that can't be routed is
// refused by the shared checks.
func TestConfigProblemsPublicRoutable(t *testing.T) {
	f := newInstanceFixture(t, nil)
	tmpl := *f.h.Template("grafana")
	tmpl.Manifest.Auth.PublicAccess = &templates.PublicAccess{Description: "x"}
	tmpl.Public = nil
	on := true
	if p := configProblems(&tmpl, f.h.kinds, nil, SettingsUpdate{PublicAccess: &on}, false); len(p) != 1 || !strings.Contains(p[0].Error(), "can't be routed") {
		t.Errorf("problems = %v", p)
	}
}

// Re-review N5: deleting an instance with an unfinished restore names
// the pre-restore backup in its warnings.
func TestDeleteRestoringWarns(t *testing.T) {
	f, _, _ := grafanaB(t)
	unlock, _ := f.h.lockApp("grafana-b")
	pre, err := f.h.backupLocked("grafana-b", BackupRestore, true)
	if err != nil {
		t.Fatal(err)
	}
	f.h.markRestoring("grafana-b", pre.Archive)
	unlock()
	res, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), pre.Archive) {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

// Re-review N3: a failed save when the restoring record is cleared is a
// loud warning, not a silent loss.
func TestClearRestoringSaveFailureWarns(t *testing.T) {
	f, _, _ := grafanaB(t)
	f.h.markRestoring("grafana-b", "grafana-b/20260101T000000Z.tar")
	os.Chmod(f.data, 0500)
	t.Cleanup(func() { os.Chmod(f.data, 0755) })
	err := f.h.clearRestoring("grafana-b", "")
	os.Chmod(f.data, 0755)
	if err == nil || !strings.Contains(err.Error(), "saving state.yaml failed") {
		t.Errorf("clearRestoring with a failing save = %v", err)
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e.State != "" {
		t.Errorf("in-memory state = %+v", e)
	}
}
