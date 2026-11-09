package hub

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/templates"
)

// A Nextcloud-shaped template (contract §13.18): the database is a setup
// choice, fixed after the first start, and each value starts its own
// compose profile.
const setupCloudManifest = `name: Cloud
category: storage
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
settings:
  options:
    - key: database
      label: Database
      type: enum
      scope: instance
      options:
        - {value: mysql, label: MySQL / MariaDB}
        - {value: postgres, label: PostgreSQL}
      default: mysql
      setup: true
      fixed_after_start: true
      profiles:
        mysql: [db-mysql]
        postgres: [db-postgres]
    - key: trash_days
      label: Trash days
      type: int
      scope: instance
      default: 30
`

const setupCloudCompose = "services:\n" +
	"  app:\n" +
	"    image: example.org/cloud:1\n" +
	"    environment:\n" +
	"      DB_TYPE: ${DATABASE:-mysql}\n" +
	"      TRASH_DAYS: ${TRASH_DAYS:-30}\n" +
	"    labels:\n" +
	"      traefik.http.routers.cloud.rule: Host(`${PORTCULLIS_HOST_CLOUD:-cloud.portcullis.local}`)\n" +
	"  db-mysql:\n" +
	"    image: example.org/mariadb:11\n" +
	"    profiles: [db-mysql]\n" +
	"    volumes: [mysql-data:/var/lib/mysql]\n" +
	"  db-postgres:\n" +
	"    image: example.org/postgres:17\n" +
	"    profiles: [db-postgres]\n" +
	"    volumes: [pg-data:/var/lib/postgresql/data]\n" +
	"volumes:\n" +
	"  mysql-data: {}\n" +
	"  pg-data: {}\n"

// setupCloudFixture is newInstanceFixture with the cloud template, Users &
// Groups and compose simulated (volumes made at create).
func setupCloudFixture(t *testing.T) *fixture {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"cloud": {setupCloudManifest, setupCloudCompose}})
	if f.h.Template("cloud") == nil {
		t.Fatal("cloud template refused")
	}
	f.h.SetAudit(&fakeAudit{})
	f.h.SetGroups(&fakeGroups{})
	simulateCompose(f, 999)
	return f
}

func setupOf(kv ...string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = json.RawMessage(kv[i+1])
	}
	return out
}

func createCloud(t *testing.T, f *fixture, id string, setup map[string]json.RawMessage) {
	t.Helper()
	if _, err := f.h.CreateInstanceAs(CreateRequest{Template: "cloud", ID: id, Label: "Team", Setup: setup}, root); err != nil {
		t.Fatal(err)
	}
}

func storedSetting(f *fixture, id, key string) any {
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	return f.h.st.Settings[id].Values[key]
}

func locked(t *testing.T, f *fixture, id string) bool {
	t.Helper()
	v, ok := f.h.InstanceView(id)
	if !ok {
		t.Fatalf("no view of %s", id)
	}
	return v.Setup.Locked
}

// TestCreateWithSetupChoice: postgres → profile db-postgres; only that
// DB service is pulled, rendered and written into COMPOSE_PROFILES.
func TestCreateWithSetupChoice(t *testing.T) {
	f := setupCloudFixture(t)
	// Refusals, nothing created: a non-setup option, a value the enum
	// doesn't have, an unknown key.
	for _, setup := range []map[string]json.RawMessage{
		setupOf("trash_days", "7"),
		setupOf("database", `"oracle"`),
		setupOf("nope", `"x"`),
	} {
		_, err := f.h.CreateInstanceAs(CreateRequest{Template: "cloud", ID: "cloud-bad", Label: "Bad", Setup: setup}, root)
		if statusOf(err) != 400 {
			t.Errorf("setup %v = %v, want 400", setup, err)
		}
		if _, ok := f.h.InstanceView("cloud-bad"); ok {
			t.Errorf("setup %v: created anyway", setup)
		}
	}
	if _, err := f.h.CreateInstanceAs(CreateRequest{Template: "cloud", ID: "cloud-bad", Label: "Bad", Setup: setupOf("trash_days", "7")}, root); err == nil || !strings.Contains(err.Error(), "trash_days") {
		t.Errorf("non-setup key error names it? %v", err)
	}

	createCloud(t, f, "cloud-team", setupOf("database", `"postgres"`))
	if v := storedSetting(f, "cloud-team", "database"); v != "postgres" {
		t.Fatalf("stored database = %v", v)
	}
	if locked(t, f, "cloud-team") {
		t.Error("locked before the first start")
	}
	if err := f.h.Enable("cloud-team"); err != nil {
		t.Fatal(err)
	}
	env := readFile(t, f.h.envPath("cloud-team"))
	if !strings.Contains(env, "\nCOMPOSE_PROFILES='db-postgres'\n") || !strings.Contains(env, "\nDATABASE='postgres'\n") {
		t.Errorf(".env = %s", env)
	}
	tm := f.h.Template("cloud-team")
	if got := f.h.renderedServices(context.Background(), tm); !got["app"] || !got["db-postgres"] || got["db-mysql"] || len(got) != 2 {
		t.Errorf("rendered services = %v", got)
	}
	if !locked(t, f, "cloud-team") {
		t.Error("not locked after the first start")
	}

	// An omitted choice takes its default: mysql.
	createCloud(t, f, "cloud-def", nil)
	if err := f.h.Enable("cloud-def"); err != nil {
		t.Fatal(err)
	}
	if env := readFile(t, f.h.envPath("cloud-def")); !strings.Contains(env, "\nCOMPOSE_PROFILES='db-mysql'\n") {
		t.Errorf("default .env = %s", env)
	}
}

// TestFixedAfterStartLocked: before the first start the choice changes;
// after it a save, a preview or a create over it is 409; a failed start
// never locks.
func TestFixedAfterStartLocked(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-a", nil)
	save := func(v string) error {
		_, err := f.h.SaveSettings("cloud-a", SettingsUpdate{Values: setupOf("database", v)}, root)
		return err
	}
	if err := save(`"postgres"`); err != nil {
		t.Fatalf("change before the first start = %v", err)
	}
	if err := save(`"mysql"`); err != nil {
		t.Fatalf("change back before the first start = %v", err)
	}

	// A failed start doesn't lock.
	f.runner.upErr = errors.New("boom")
	if err := f.h.Enable("cloud-a"); err == nil {
		t.Fatal("enable succeeded despite the up error")
	}
	if locked(t, f, "cloud-a") {
		t.Fatal("locked by a failed start")
	}
	if err := save(`"postgres"`); err != nil {
		t.Fatalf("change after a failed start = %v", err)
	}
	f.runner.upErr = nil
	if err := f.h.Enable("cloud-a"); err != nil {
		t.Fatal(err)
	}
	if !locked(t, f, "cloud-a") {
		t.Fatal("not locked after the first start")
	}
	f.h.mu.RLock()
	first := *f.h.st.Settings["cloud-a"].FirstStartedAt
	f.h.mu.RUnlock()

	err := save(`"mysql"`)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "Database is fixed after the first start: changing it would mean moving the data (create a new instance and restore a backup into it)") {
		t.Fatalf("change after the first start = %v", err)
	}
	if err := save("null"); statusOf(err) != 409 {
		t.Errorf("back to the default (mysql) after the first start = %v", err)
	}
	if _, err := f.h.PreviewSettings(context.Background(), "cloud-a", SettingsUpdate{Values: setupOf("database", `"mysql"`)}); statusOf(err) != 409 {
		t.Errorf("preview after the first start = %v", err)
	}
	// The unchanged value and other options still save.
	if err := save(`"postgres"`); err != nil {
		t.Errorf("unchanged value = %v", err)
	}
	if _, err := f.h.SaveSettings("cloud-a", SettingsUpdate{Values: setupOf("trash_days", "7")}, root); err != nil {
		t.Errorf("other option = %v", err)
	}
	if v := storedSetting(f, "cloud-a", "database"); v != "postgres" {
		t.Errorf("database = %v", v)
	}
	// A restart (the saves' own, then one more) keeps the first start's
	// time.
	f.h.Wait()
	if err := f.h.RestartApp("cloud-a"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	again := *f.h.st.Settings["cloud-a"].FirstStartedAt
	f.h.mu.RUnlock()
	if !again.Equal(first) {
		t.Errorf("first_started_at moved: %v -> %v", first, again)
	}
}

// TestRestoreKeepsChoiceAndLock: a same-instance restore keeps the
// archived choice and first start; the lock still holds.
func TestRestoreKeepsChoiceAndLock(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-r", setupOf("database", `"postgres"`))
	if err := f.h.Enable("cloud-r"); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("cloud-r", root)
	if err != nil {
		t.Fatal(err)
	}
	_, members, _ := readArchive(t, archivePath(f, entry.Archive))
	if inst := string(members["config/instance.yaml"]); !strings.Contains(inst, "first_started_at:") || !strings.Contains(inst, "database: postgres") {
		t.Errorf("config/instance.yaml = %s", inst)
	}
	f.h.mu.RLock()
	archived := *f.h.st.Settings["cloud-r"].FirstStartedAt
	f.h.mu.RUnlock()
	// Even an instance whose lock was lost meanwhile gets the archive's.
	f.h.mu.Lock()
	s := f.h.st.Settings["cloud-r"].Clone()
	s.FirstStartedAt = nil
	s.Values["database"] = "mysql"
	f.h.st.Settings["cloud-r"] = s
	f.h.mu.Unlock()
	if _, err := f.h.RestoreInstance("cloud-r", entry.Archive, root); err != nil {
		t.Fatal(err)
	}
	if v := storedSetting(f, "cloud-r", "database"); v != "postgres" {
		t.Errorf("restored database = %v", v)
	}
	if !locked(t, f, "cloud-r") {
		t.Error("restore lost the lock")
	}
	f.h.mu.RLock()
	got := f.h.st.Settings["cloud-r"].FirstStartedAt
	f.h.mu.RUnlock()
	if got == nil || !got.Equal(archived) {
		t.Errorf("first_started_at after the restore = %v, want the archived %v", got, archived)
	}
	if _, err := f.h.SaveSettings("cloud-r", SettingsUpdate{Values: setupOf("database", `"mysql"`)}, root); statusOf(err) != 409 {
		t.Errorf("change after the restore = %v", err)
	}
	if env := readFile(t, f.h.envPath("cloud-r")); !strings.Contains(env, "\nCOMPOSE_PROFILES='db-postgres'\n") {
		t.Errorf("restored .env = %s", env)
	}
}

// TestRestoreAsKeepsChoice: a restore into a new id takes the archive's
// choice and is locked when the archive was.
func TestRestoreAsKeepsChoice(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-s", setupOf("database", `"postgres"`))
	if err := f.h.Enable("cloud-s"); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("cloud-s", root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "cloud-copy", root); err != nil {
		t.Fatal(err)
	}
	if v := storedSetting(f, "cloud-copy", "database"); v != "postgres" {
		t.Errorf("restore-as database = %v", v)
	}
	if !locked(t, f, "cloud-copy") {
		t.Error("restore-as of a started archive is not locked")
	}
	if _, err := f.h.SaveSettings("cloud-copy", SettingsUpdate{Values: setupOf("database", `"mysql"`)}, root); statusOf(err) != 409 {
		t.Errorf("change after restore-as = %v", err)
	}
	if env := readFile(t, f.h.envPath("cloud-copy")); !strings.Contains(env, "\nCOMPOSE_PROFILES='db-postgres'\n") {
		t.Errorf("restore-as .env = %s", env)
	}

	// An archive of an instance that never started isn't locked.
	createCloud(t, f, "cloud-n", setupOf("database", `"postgres"`))
	entry, err = f.h.BackupInstance("cloud-n", root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "cloud-n2", root); err != nil {
		t.Fatal(err)
	}
	if v := storedSetting(f, "cloud-n2", "database"); v != "postgres" || locked(t, f, "cloud-n2") {
		t.Errorf("never-started archive: database %v, locked %v", v, locked(t, f, "cloud-n2"))
	}
}

// TestPullRefsFollowProfiles: the pre-pull takes the selected profile's
// images and the unprofiled ones, never another profile's.
func TestPullRefsFollowProfiles(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-p", setupOf("database", `"postgres"`))
	if err := f.h.Enable("cloud-p"); err != nil {
		t.Fatal(err)
	}
	got := f.h.pullRefs(context.Background(), f.h.Template("cloud-p"))
	if want := []string{"example.org/cloud:1", "example.org/postgres:17"}; !slices.Equal(got, want) {
		t.Errorf("pullRefs = %v, want %v", got, want)
	}
	// The safety checks' loader still reads every profile.
	proj, err := loadRendered(context.Background(), f.h.project(f.h.Template("cloud-p")), f.h.cfg.ProjectDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := proj.Services["db-mysql"]; !ok {
		t.Errorf("loadRendered hides db-mysql: %v", proj.ServiceNames())
	}
}

// TestStatusFollowsProfiles: status, drift and readiness look only at
// the selected services; a leftover of the other profile is not listed,
// an active profiled job with no container is job_missing.
func TestStatusFollowsProfiles(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-t", setupOf("database", `"postgres"`))
	if err := f.h.Enable("cloud-t"); err != nil {
		t.Fatal(err)
	}
	tm := f.h.Template("cloud-t")
	f.h.mu.RLock()
	want, err := f.h.desiredRouteLabelsLocked(f.h.findLocked("cloud-t"))
	f.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	app := container("a1", "portcullis-cloud-t", "app", "running")
	for k, v := range want["app"] {
		app.Labels[k] = v
	}
	pg := container("p1", "portcullis-cloud-t", "db-postgres", "running")
	leftover := container("m1", "portcullis-cloud-t", "db-mysql", "exited")
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{app, pg, leftover}
	f.engine.states = map[string]docker.State{
		"a1": {Running: true, Status: "running"},
		"p1": {Running: true, Status: "running"},
		"m1": {Status: "exited", ExitCode: 1},
	}
	f.engine.mu.Unlock()
	st, err := f.h.Status(context.Background(), "cloud-t")
	if err != nil {
		t.Fatal(err)
	}
	var svcs []string
	for _, c := range st {
		svcs = append(svcs, c.Service)
	}
	slices.Sort(svcs)
	if !slices.Equal(svcs, []string{"app", "db-postgres"}) {
		t.Errorf("status services = %v", svcs)
	}
	// An active service with no container gets a missing row; the
	// inactive profile's service (db-mysql) never does, container or not.
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{app, leftover}
	f.engine.mu.Unlock()
	st, err = f.h.Status(context.Background(), "cloud-t")
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, c := range st {
		rows = append(rows, c.Service+"="+c.State)
	}
	if !slices.Equal(rows, []string{"app=running", "db-postgres=missing"}) {
		t.Errorf("status rows = %v, want app running and db-postgres missing (db-mysql inactive: not listed)", rows)
	}
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{app, pg, leftover}
	f.engine.mu.Unlock()
	n, m, others, _, err := f.h.countContainers(context.Background(), tm, f.h.renderedServices(context.Background(), tm))
	if err != nil || n != 2 || m != 2 || len(others) != 0 {
		t.Errorf("readiness = %d of %d, others %v, %v", n, m, others, err)
	}
	rep := f.h.Reconcile(context.Background())
	for _, d := range rep.Items {
		if d.ID == "cloud-t" {
			t.Errorf("drift for the leftover of an unselected profile: %+v", d)
		}
	}
}

// TestProfiledJobFollowsChoice: an active profiled job without a
// container is job_missing; an inactive one isn't (§11.9).
func TestProfiledJobFollowsChoice(t *testing.T) {
	f := newFixture(t)
	writeFile(t, f.src+"/profiledapp/manifest.yaml", profiledJobManifest)
	writeFile(t, f.src+"/profiledapp/compose.yml", profiledJobCompose)
	f.h.Discover()
	if _, err := f.h.SaveSettings("profiledapp", SettingsUpdate{Values: setupOf("mode", `"extended"`)}, root); err != nil {
		t.Fatal(err)
	}
	f.h.Enable("profiledapp")
	tmpl := f.h.Template("profiledapp")
	f.h.mu.RLock()
	want, err := f.h.desiredRouteLabelsLocked(tmpl)
	f.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	web := container("w1", "portcullis-profiledapp", "web", "running")
	for k, v := range want["web"] {
		web.Labels[k] = v
	}
	f.engine.containers = []docker.Container{web}
	f.engine.states = map[string]docker.State{"w1": {Running: true, Status: "running"}}
	found := false
	for _, d := range f.h.Reconcile(context.Background()).Items {
		found = found || (d.ID == "profiledapp" && d.Kind == DriftJobMissing && strings.Contains(d.Message, "setup"))
	}
	if !found {
		t.Error("no job_missing for the active profiled job")
	}
}

// TestStoppedEnableDoesntLock: an enable stopped after its compose up
// (its undo removes what it made) never stamps the first start; one
// that commits does, at its commit.
func TestStoppedEnableDoesntLock(t *testing.T) {
	f := stopFixture(t)
	first := func() bool {
		f.h.mu.RLock()
		defer f.h.mu.RUnlock()
		return f.h.st.Settings["other"].FirstStartedAt != nil
	}
	// Blocked in the settings step: startUp has run its up and returns
	// nil after the Stop; the enable's commit then finds the Stop.
	reached, release := f.blockAt("settings")
	a, err := f.h.StartEnable("other", root)
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	if _, err := f.h.StopOp("other", root); err != nil {
		t.Fatal(err)
	}
	close(release)
	if r := waitOp(t, f.h, "other", a.OpID); !r.Stopped() {
		t.Fatalf("not stopped: %+v", r)
	}
	if first() {
		t.Fatal("a stopped enable stamped the first start")
	}
	a, err = f.h.StartEnable("other", root)
	if err != nil {
		t.Fatal(err)
	}
	if r := waitOp(t, f.h, "other", a.OpID); !r.OK {
		t.Fatalf("enable: %+v", r)
	}
	if !first() {
		t.Error("a committed enable didn't stamp the first start")
	}
}

// forgetFirstStart drops instance id's first start stamp (tests whose
// archive must hold no settings block).
func forgetFirstStart(f *fixture, id string) {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	s := f.h.st.Settings[id].Clone()
	s.FirstStartedAt = nil
	if s.IsZero() {
		delete(f.h.st.Settings, id)
	} else {
		f.h.st.Settings[id] = s
	}
}

// TestFolderAssignRefusesFixedChoice: a folder assignment that would
// change a fixed_after_start path choice of a started instance is 409
// (preview and start share the computation); before the first start it
// is planned like any other.
func TestFolderAssignRefusesFixedChoice(t *testing.T) {
	f := strongboxFixture(t)
	req := AssignRequest{Uses: []FolderUse{{Instance: "strongbox", Key: "data"}}}
	if _, err := f.h.PreviewAssign(context.Background(), "media", req); err != nil {
		t.Fatalf("before the first start: %v", err)
	}
	f.h.mu.Lock()
	f.h.stampFirstStartLocked("strongbox")
	f.h.mu.Unlock()
	_, err := f.h.PreviewAssign(context.Background(), "media", req)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "Data store is fixed after the first start") {
		t.Fatalf("after the first start: %v", err)
	}
	if _, err := f.h.StartAssign("media", req, strings.Repeat("0", 64), root); statusOf(err) != 409 || !strings.Contains(err.Error(), "fixed after the first start") {
		t.Errorf("start after the first start: %v", err)
	}
}

// TestCreateStoresSetupValues: every setup option's effective value is
// stored at create, with or without setup in the body, so a later
// template default change can't move it (§11.9 I1).
func TestCreateStoresSetupValues(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-d", nil)
	if v := storedSetting(f, "cloud-d", "database"); v != "mysql" {
		t.Fatalf("stored database = %v, want mysql", v)
	}
	if v := storedSetting(f, "cloud-d", "trash_days"); v != nil {
		t.Errorf("a non-setup option was stored: %v", v)
	}
	writeFile(t, f.src+"/cloud/manifest.yaml", strings.Replace(setupCloudManifest, "      default: mysql\n", "      default: postgres\n", 1))
	f.h.Discover()
	f.h.mu.RLock()
	tm := f.h.findLocked("cloud-d")
	o := optionByKey(tm, "database")
	v, _ := f.h.effectiveValue(tm, o, f.h.st.Settings["cloud-d"])
	def := o.Default
	f.h.mu.RUnlock()
	if def != "postgres" || v != "mysql" {
		t.Errorf("after the default change: default %v, effective %v (want mysql)", def, v)
	}
}

// TestFixedChoiceTemplateUpdate (ruling I3): a template update never
// drops a started instance's fixed choice; one that no longer fits is
// listed by SettingsIncompatibilities and refuses the start (409); a
// changed profiles entry for the stored value is listed too.
func TestFixedChoiceTemplateUpdate(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-u", setupOf("database", `"postgres"`))
	if err := f.h.Enable("cloud-u"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	s := f.h.st.Settings["cloud-u"].Clone()
	old := *f.h.findLocked("cloud-u")
	f.h.mu.RUnlock()
	if !slices.Equal(s.FixedKeys, []string{"database"}) {
		t.Fatalf("fixed keys = %v", s.FixedKeys)
	}
	// The listing: postgres refused by the new template; then a new
	// profiles entry for postgres.
	edit := func(fn func(o *templates.Option)) *templates.Template {
		nt := old
		m := *old.Manifest.Settings
		m.Options = slices.Clone(m.Options)
		for i := range m.Options {
			if m.Options[i].Key == "database" {
				fn(&m.Options[i])
			}
		}
		nt.Manifest.Settings = &m
		return &nt
	}
	gone := edit(func(o *templates.Option) {
		o.Choices = []templates.EnumOption{{Value: "mysql", Label: "MySQL"}}
		o.Profiles = map[string][]string{"mysql": {"db-mysql"}}
	})
	if got := strings.Join(SettingsIncompatibilities(&old, gone, s), "\n"); !strings.Contains(got, "setup choice database is fixed after the first start and no longer fits") || strings.Contains(got, "dropped") {
		t.Errorf("incompatibilities (value refused) = %q", got)
	}
	moved := edit(func(o *templates.Option) {
		o.Profiles = map[string][]string{"mysql": {"db-mysql"}, "postgres": {"db-postgres", "db-extra"}}
	})
	if got := strings.Join(SettingsIncompatibilities(&old, moved, s), "\n"); !strings.Contains(got, "would start compose profiles [db-extra, db-postgres] instead of [db-postgres]") {
		t.Errorf("incompatibilities (profiles) = %q", got)
	}
	if got := SettingsIncompatibilities(&old, &old, s); len(got) != 0 {
		t.Errorf("unchanged template = %v", got)
	}

	// The update itself: postgres is no longer a value. The prune keeps
	// it; the start is refused.
	m := strings.Replace(setupCloudManifest, "        - {value: postgres, label: PostgreSQL}\n", "        - {value: mariadb, label: MariaDB}\n", 1)
	m = strings.Replace(m, "        postgres: [db-postgres]\n", "        mariadb: [db-postgres]\n", 1)
	writeFile(t, f.src+"/cloud/manifest.yaml", m)
	f.h.Discover()
	if f.h.Template("cloud-u") == nil {
		t.Fatal("updated template refused")
	}
	f.h.pruneSettings()
	if v := storedSetting(f, "cloud-u", "database"); v != "postgres" {
		t.Fatalf("the prune dropped the fixed choice: %v", v)
	}
	err := f.h.RestartApp("cloud-u")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "setup choice database no longer fits the template") {
		t.Fatalf("restart = %v", err)
	}
	if err := f.h.Disable("cloud-u"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("cloud-u"); statusOf(err) != 409 || !strings.Contains(err.Error(), "setup choice database no longer fits") {
		t.Errorf("enable = %v", err)
	}
}

// TestInactiveServiceRunningDrift: on an enabled instance a RUNNING
// container of a service outside the selected profiles is drift (fail
// closed); an exited one stays hidden.
func TestInactiveServiceRunningDrift(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-v", setupOf("database", `"postgres"`))
	if err := f.h.Enable("cloud-v"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	want, err := f.h.desiredRouteLabelsLocked(f.h.findLocked("cloud-v"))
	f.h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	app := container("a1", "portcullis-cloud-v", "app", "running")
	for k, v := range want["app"] {
		app.Labels[k] = v
	}
	set := func(mysql string) {
		f.engine.mu.Lock()
		f.engine.containers = []docker.Container{app, container("p1", "portcullis-cloud-v", "db-postgres", "running"), container("m1", "portcullis-cloud-v", "db-mysql", mysql)}
		f.engine.states = map[string]docker.State{"a1": {Running: true, Status: "running"}, "p1": {Running: true, Status: "running"}, "m1": {Status: mysql}}
		f.engine.mu.Unlock()
	}
	set("running")
	var got []Drift
	for _, d := range f.h.Reconcile(context.Background()).Items {
		if d.ID == "cloud-v" {
			got = append(got, d)
		}
	}
	if len(got) != 1 || got[0].Kind != DriftInactiveRunning || got[0].Message != "service db-mysql runs although the instance's setup choices leave it off" || !slices.Contains(got[0].Actions, ActionRestart) {
		t.Fatalf("drift = %+v", got)
	}
	set("exited")
	for _, d := range f.h.Reconcile(context.Background()).Items {
		if d.ID == "cloud-v" {
			t.Errorf("exited leftover drift: %+v", d)
		}
	}
}

// TestCreateSetupCatalogChanged: the setup values are checked once
// (parseSetup) and stored only against that catalog: a source sync in
// between is a 409 "try again", nothing created; unchecked values never
// reach the store.
func TestCreateSetupCatalogChanged(t *testing.T) {
	f := setupCloudFixture(t)
	req := CreateRequest{Template: "cloud", ID: "cloud-race", Label: "Race", Setup: setupOf("database", `"postgres"`)}
	req.recheck = func() error { f.h.Discover(); return nil }
	_, err := f.h.CreateInstanceAs(req, root)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "the template changed while creating: try again") {
		t.Fatalf("create across a catalog change = %v", err)
	}
	if _, ok := f.h.InstanceView("cloud-race"); ok {
		t.Error("created anyway")
	}
	if err := f.h.createEntry(CreateRequest{Template: "cloud", ID: "cloud-raw", Setup: setupOf("database", `"postgres"`)}, "", ""); statusOf(err) != 500 {
		t.Errorf("unchecked setup = %v", err)
	}
	// Without a change in between: created with the checked value.
	createCloud(t, f, "cloud-race", setupOf("database", `"postgres"`))
	if v := storedSetting(f, "cloud-race", "database"); v != "postgres" {
		t.Errorf("database = %v", v)
	}
}

// strongboxFixture is the assignment fixture plus "strongbox", whose
// fixed setup choice is a mounted path option.
func strongboxFixture(t *testing.T) *fixture {
	t.Helper()
	tmpls := maps.Clone(assignTemplates)
	tmpls["strongbox"] = folderApp("Strongbox", "strongbox", `    - key: data
      label: Data store
      type: path
      setup: true
      fixed_after_start: true
      target: {service: box, mount: /data}
      folder: {access: read, runs_as: {uid: 0, gid: 0}}
      applies: restart
`, "  box:\n    image: box\n", "")
	f := newInstanceFixtureExtra(t, nil, nil, tmpls)
	if f.h.Template("strongbox") == nil {
		t.Fatal("strongbox not loaded (see the log)")
	}
	fx := f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	d := &assignDisk{fakeDisk: &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}, acl: true}
	fx.run = d.run
	addFolder(t, f, d.fakeDisk, "media", "Family media", "/srv/media", 60001)
	simulateCompose(f, 0)
	return f
}

// TestFixedFolderChoiceRestarts: a shared folder assigned to a fixed path
// choice before the first start is recorded as fixed at the start and
// still fits afterwards: the restart (and a disable + enable) start it
// again — the folder value is checked like a restore's (configCheck with
// the folder source), never refused by the bare kind.
func TestFixedFolderChoiceRestarts(t *testing.T) {
	f := strongboxFixture(t)
	req := AssignRequest{Uses: []FolderUse{{Instance: "strongbox", Key: "data"}}}
	if _, rec := assign(t, f, "media", req); !rec.OK {
		t.Fatalf("assign = %+v", rec)
	}
	if v := storedSetting(f, "strongbox", "data"); v != "folder:media" {
		t.Fatalf("data = %v", v)
	}
	if err := f.h.Enable("strongbox"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	s := f.h.st.Settings["strongbox"].Clone()
	f.h.mu.RUnlock()
	if s.FirstStartedAt == nil || !slices.Equal(s.FixedKeys, []string{"data"}) {
		t.Fatalf("not locked: %+v", s)
	}
	if err := f.h.RestartApp("strongbox"); err != nil {
		t.Fatalf("restart of a fixed folder choice = %v", err)
	}
	if err := f.h.Disable("strongbox"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("strongbox"); err != nil {
		t.Fatalf("enable again = %v", err)
	}
	f.h.pruneSettings()
	if v := storedSetting(f, "strongbox", "data"); v != "folder:media" {
		t.Errorf("after the prune: %v", v)
	}
	f.h.mu.RLock()
	old := *f.h.findLocked("strongbox")
	f.h.mu.RUnlock()
	if got := SettingsIncompatibilities(&old, &old, s); len(got) != 0 {
		t.Errorf("incompatibilities = %v", got)
	}
}

// TestFirstStartBackfillsFixedChoice: an instance with no stored fixed
// value (created before values were stored at create) gets its
// effective value stored and locked at its first start.
func TestFirstStartBackfillsFixedChoice(t *testing.T) {
	f := setupCloudFixture(t)
	createCloud(t, f, "cloud-b", nil)
	f.h.mu.Lock()
	s := f.h.st.Settings["cloud-b"].Clone()
	delete(s.Values, "database")
	delete(s.Types, "database")
	f.h.st.Settings["cloud-b"] = s
	f.h.mu.Unlock()
	if v := storedSetting(f, "cloud-b", "database"); v != nil {
		t.Fatalf("precondition: %v", v)
	}
	if err := f.h.Enable("cloud-b"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	s = f.h.st.Settings["cloud-b"].Clone()
	f.h.mu.RUnlock()
	if s.Values["database"] != "mysql" || s.Types["database"] != "enum" || !slices.Equal(s.FixedKeys, []string{"database"}) || s.FirstStartedAt == nil {
		t.Fatalf("after the first start: %+v", s)
	}
	if _, err := f.h.SaveSettings("cloud-b", SettingsUpdate{Values: setupOf("database", `"postgres"`)}, root); statusOf(err) != 409 {
		t.Errorf("change after the backfill = %v", err)
	}
}
