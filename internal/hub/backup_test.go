package hub

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/state"
)

// simulateCompose makes the fake runner behave like compose for backups:
// `up --no-start` creates the instance's volumes (labelled, root owned by
// uid), up runs one container, down removes it (volumes kept).
func simulateCompose(f *fixture, uid int) {
	f.runner.createHook = func(project string) {
		id := strings.TrimPrefix(project, ProjectPrefix)
		t := f.h.Template(id)
		if t == nil {
			return
		}
		have := map[string]bool{}
		for _, n := range f.engine.volumeNames() {
			have[n] = true
		}
		for k, n := range t.NamesFor(id).Volumes {
			if !have[n] {
				f.engine.addVolume(n, project, k, uid)
			}
		}
	}
	f.runner.upHook = func(project string) {
		f.engine.mu.Lock()
		defer f.engine.mu.Unlock()
		for _, c := range f.engine.containers {
			if c.Project() == project {
				return
			}
		}
		f.engine.containers = append(f.engine.containers, container(project+"-c", project, "app", "running"))
	}
	f.runner.onDown = func(project string) {
		f.engine.mu.Lock()
		defer f.engine.mu.Unlock()
		var keep []docker.Container
		for _, c := range f.engine.containers {
			if c.Project() != project {
				keep = append(keep, c)
			}
		}
		f.engine.containers = keep
	}
}

// putFiles replaces volume name's files (root kept).
func putFiles(f *fixture, name string, files ...fakeFile) {
	v := f.engine.vol()
	v.vmu.Lock()
	defer v.vmu.Unlock()
	fv := v.volumes[name]
	root := fv.files[""]
	fv.files = map[string]fakeFile{"": root}
	for _, x := range files {
		fv.files[x.Name] = x
	}
}

// readArchive returns an archive's member names in order and contents.
func readArchive(t *testing.T, p string) ([]string, map[string][]byte, map[string]*tar.Header) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(b))
	var names []string
	data := map[string][]byte{}
	hdrs := map[string]*tar.Header{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		c, _ := io.ReadAll(tr)
		names = append(names, h.Name)
		data[h.Name] = c
		hdrs[h.Name] = h
	}
	return names, data, hdrs
}

// writeArchive writes members in order (a hand-made / tampered archive).
func writeArchive(t *testing.T, p string, names []string, data map[string][]byte) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(data[n])), Typeflag: tar.TypeReg})
		tw.Write(data[n])
	}
	tw.Close()
	if err := os.WriteFile(p, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func innerTar(t *testing.T, b []byte) map[string]*tar.Header {
	t.Helper()
	out := map[string]*tar.Header{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = h
	}
}

// grafanaB is an enabled grafana-b whose volume holds a database owned by
// uid 472.
func grafanaB(t *testing.T) (*fixture, *fakeAudit, *fakeGroups) {
	t.Helper()
	f := newInstanceFixture(t, nil)
	audit := &fakeAudit{}
	groups := &fakeGroups{}
	f.h.SetAudit(audit)
	f.h.SetGroups(groups)
	simulateCompose(f, 472)
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	putFiles(f, "portcullis_grafana-b-grafana-data",
		fakeFile{Name: "grafana.db", Mode: 0640, UID: 472, GID: 0, Body: "v1"},
		fakeFile{Name: "plugins", Dir: true, Mode: 0750, UID: 472, GID: 472})
	return f, audit, groups
}

func archivePath(f *fixture, archive string) string {
	return filepath.Join(f.data, "backups", filepath.FromSlash(archive))
}

func TestBackupArchiveLayout(t *testing.T) {
	f, audit, _ := grafanaB(t)
	n := len(f.runner.Calls())
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^grafana-b/[0-9]{8}T[0-9]{6}Z\.tar$`).MatchString(entry.Archive) || entry.Reason != BackupManual || entry.Size == 0 {
		t.Fatalf("entry = %+v", entry)
	}
	// Stopped while copied, started again.
	if got := strings.Join(f.runner.Calls()[n:], " "); got != "down:portcullis-grafana-b up:portcullis-grafana-b" {
		t.Errorf("calls = %s", got)
	}
	p := archivePath(f, entry.Archive)
	for path, want := range map[string]os.FileMode{p: 0600, filepath.Dir(p): 0700, filepath.Dir(filepath.Dir(p)): 0700} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v %v", path, fi.Mode().Perm(), err)
		}
	}
	names, data, _ := readArchive(t, p)
	if got := strings.Join(names, ","); got != "MANIFEST.json,config/env,config/instance.yaml,config/override.yml,volumes/grafana-data.tar" {
		t.Fatalf("members = %s", got)
	}
	var m BackupManifest
	if err := json.Unmarshal(data["MANIFEST.json"], &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != 1 || m.Instance != "grafana-b" || m.Template != "grafana" || m.Reason != "manual" || m.CreatedAt.IsZero() ||
		m.Volumes["grafana-data"] != "portcullis_grafana-b-grafana-data" || len(m.Volumes) != 1 || len(m.Files) != len(names)-1 {
		t.Fatalf("manifest = %+v", m)
	}
	for _, name := range names[1:] {
		sum := sha256.Sum256(data[name])
		if m.Files[name] != hex.EncodeToString(sum[:]) {
			t.Errorf("sha256 of %s = %s, manifest %s", name, hex.EncodeToString(sum[:]), m.Files[name])
		}
	}
	if !strings.Contains(string(data["config/env"]), "GF_SECRET=") {
		t.Errorf("env = %s", data["config/env"])
	}
	var cfg instanceConfig
	if err := yaml.Unmarshal(data["config/instance.yaml"], &cfg); err != nil || cfg.ID != "grafana-b" || cfg.Hosts["grafana"] != "grafana-b.example.org" || !cfg.Enabled {
		t.Errorf("instance.yaml = %+v %v", cfg, err)
	}
	// Owners, modes and the volume root survive.
	inner := innerTar(t, data["volumes/grafana-data.tar"])
	if h := inner["data/grafana.db"]; h == nil || h.Uid != 472 || h.Mode != 0640 {
		t.Errorf("grafana.db = %+v", h)
	}
	if h := inner["data/"]; h == nil || h.Uid != 472 || h.Typeflag != tar.TypeDir {
		t.Errorf("volume root = %+v", h)
	}
	// The helper: pinned image, read-only, only that volume, removed.
	ve := f.engine.vol()
	if len(ve.helperLog) != 1 || ve.helperLog[0].Image != HelperImage || !ve.helperLog[0].ReadOnly ||
		len(ve.helperLog[0].Volumes) != 1 || ve.helperLog[0].Volumes["portcullis_grafana-b-grafana-data"] != "/data" || len(ve.helpers) != 0 {
		t.Errorf("helpers = %+v (left: %d)", ve.helperLog, len(ve.helpers))
	}
	if a := audit.last(); a.Action != "instance.backup" || a.Result != "ok" || a.Detail != "archive="+entry.Archive || a.Actor != "root" {
		t.Errorf("audit = %+v", a)
	}
	list, err := f.h.ListBackups("")
	if err != nil || len(list) != 1 || list[0].Archive != entry.Archive || !list[0].InstanceExists || list[0].Size != entry.Size {
		t.Errorf("list = %+v %v", list, err)
	}
	if l, _ := f.h.ListBackups("grafana"); len(l) != 0 {
		t.Errorf("list(grafana) = %+v", l)
	}
	if fi, _ := os.ReadDir(filepath.Dir(p)); len(fi) != 1 {
		t.Errorf("leftovers in the backup dir: %v", fi)
	}
}

func TestHelperImagePinned(t *testing.T) {
	if !regexp.MustCompile(`^[a-z0-9./-]+:[0-9][a-z0-9.-]*@sha256:[0-9a-f]{64}$`).MatchString(HelperImage) {
		t.Fatalf("HelperImage %q is not pinned name:tag@sha256", HelperImage)
	}
	// Same image as core's CLI helpers (one pin to keep current).
	core := os.Getenv("PORTCULLIS_CORE_DIR")
	if core == "" {
		core = filepath.Join("..", "..", "..", "portcullis")
	}
	b, err := os.ReadFile(filepath.Join(core, "scripts", "lib", "common.sh"))
	if err != nil {
		t.Skip("no core checkout")
	}
	if !strings.Contains(string(b), `PORTCULLIS_HELPER_IMAGE="`+HelperImage+`"`) {
		t.Errorf("HelperImage %s differs from core's PORTCULLIS_HELPER_IMAGE", HelperImage)
	}
}

func TestDeleteBackupFirst(t *testing.T) {
	f, audit, groups := grafanaB(t)
	if _, err := f.h.DeleteInstance("grafana-b", "grafana", directory.Human("root")); statusOf(err) != 400 {
		t.Fatalf("wrong confirm = %v", err)
	}
	// The backup fails: nothing is removed, the instance runs again.
	ve := f.engine.vol()
	ve.copyFromErr = func(string) error { return errors.New("disk full") }
	n := len(f.runner.Calls())
	if _, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root")); err == nil || !strings.Contains(err.Error(), "nothing was deleted") {
		t.Fatalf("delete with a failing backup = %v", err)
	}
	ve.copyFromErr = nil
	if got := strings.Join(f.runner.Calls()[n:], " "); got != "down:portcullis-grafana-b up:portcullis-grafana-b" {
		t.Errorf("calls = %s", got)
	}
	if !f.h.IsEnabled("grafana-b") || f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["grafana.db"].Body != "v1" ||
		f.h.Template("grafana-b") == nil || len(groups.Calls()) != 0 || len(f.idp.callbacks) != 0 {
		t.Fatal("a failed backup removed something")
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 0 {
		t.Errorf("archives after a failed backup: %+v", l)
	}
	if fi, _ := os.ReadDir(filepath.Join(f.data, "backups", "grafana-b")); len(fi) != 0 {
		t.Errorf("leftovers: %v", fi)
	}
	if a := audit.last(); a.Action != "instance.delete" || a.Result != "error" {
		t.Errorf("audit = %+v", a)
	}

	// Fails after the backup (the groups step): partially deleted,
	// retryable.
	groups.delErr = errors.New("lldap down")
	_, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root"))
	var oe *OpError
	if !errors.As(err, &oe) || !strings.Contains(err.Error(), "deleting") {
		t.Fatalf("delete with Keycloak down = %v", err)
	}
	list, _ := f.h.ListBackups("grafana-b")
	if len(list) != 1 || list[0].Reason != BackupDelete || list[0].InstanceExists {
		t.Fatalf("backups = %+v", list)
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["grafana-b"]
	f.h.mu.RUnlock()
	if e.State != state.InstanceDeleting || e.Backup != list[0].Archive {
		t.Fatalf("state entry = %+v", e)
	}
	if st, _ := state.Load(filepath.Join(f.data, "state.yaml")); st.Instances["grafana-b"].State != state.InstanceDeleting {
		t.Error("deleting not persisted")
	}
	var view *InstanceView
	for _, v := range f.h.Instances() {
		if v.ID == "grafana-b" {
			view = &v
		}
	}
	if view == nil || view.State != StateDeleting {
		t.Errorf("instance view = %+v", view)
	}
	if err := f.h.Enable("grafana-b"); statusOf(err) != 409 {
		t.Errorf("enable while deleting = %v", err)
	}
	if _, err := f.h.BackupInstance("grafana-b", directory.Human("root")); statusOf(err) != 409 {
		t.Errorf("backup while deleting = %v", err)
	}
	if f.h.IsEnabled("grafana-b") || len(f.engine.volumeNames()) != 0 {
		t.Errorf("after step 3: enabled=%v volumes=%v", f.h.IsEnabled("grafana-b"), f.engine.volumeNames())
	}

	// The retry finishes with the first backup (no new one).
	groups.delErr = nil
	res, err := f.h.DeleteInstance("grafana-b", "grafana-b", directory.Human("root"))
	if err != nil || res.Backup != list[0].Archive {
		t.Fatalf("retry = %+v %v", res, err)
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 1 {
		t.Errorf("backups after retry = %+v", l)
	}
	if a := audit.last(); a.Action != "instance.delete" || a.Result != "ok" || a.Detail != "backup="+list[0].Archive {
		t.Errorf("audit = %+v", a)
	}
}

func TestDeleteRemovesEverything(t *testing.T) {
	kc := kctest.New(t)
	idp := keycloak.New(kc.HTTP.URL, "admin", "admin")
	f := newInstanceFixtureWith(t, nil, idp)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	audit, groups := &fakeAudit{}, &fakeGroups{}
	f.h.SetAudit(audit)
	f.h.SetGroups(groups)
	simulateCompose(f, 0)
	// The instance's callback (as an instance behind forward-auth gets).
	fa := kc.AddClient(keycloak.ForwardAuthClient, nil)
	kc.SetClientURIs(fa, []string{"https://auth.example.org/oauth2/callback", "https://chat.team-b.example.org/oauth2/callback"}, nil)
	kc.AddClient("chat", map[string]string{keycloak.OwnerAttr: "chat"})

	if err := f.h.CreateInstance("chat", "chat-b", map[string]string{"chat": "chat.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	if kc.ClientByClientID("chat-b") == nil || kc.ClientByClientID("chat-b-chat-admin") == nil {
		t.Fatal("enable did not set up Keycloak")
	}
	f.engine.addVolume("portcullis_chat-b-data", "portcullis-chat-b", "data", 0, fakeFile{Name: "x", Body: "x"})
	f.engine.addVolume("portcullis_other", "portcullis-other", "data", 0)
	f.engine.addVolume("unlabelled", "", "", 0)
	f.h.mu.Lock()
	f.h.st.Settings["chat-b"] = state.InstanceSettings{Ports: map[string]string{"K": "v"}}
	f.h.st.PublicTokens["chat-b"] = []string{"tok"}
	f.h.mu.Unlock()
	for _, p := range []string{f.h.userOverridePath("chat-b")} {
		writeFile(t, p, "services: {}\n")
	}

	res, err := f.h.DeleteInstance("chat-b", "chat-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Backup == "" {
		t.Error("no backup")
	}
	// Project and volumes.
	if !strings.Contains(strings.Join(f.runner.Calls(), " "), "down:portcullis-chat-b") {
		t.Errorf("calls = %v", f.runner.Calls())
	}
	if got := strings.Join(f.engine.volumeNames(), ","); got != "portcullis_other,unlabelled" {
		t.Errorf("volumes = %s", got)
	}
	// Keycloak: its clients and callback gone, others untouched.
	if kc.ClientByClientID("chat-b") != nil || kc.ClientByClientID("chat-b-chat-admin") != nil || kc.ClientByClientID("chat") == nil {
		t.Error("Keycloak clients not (only) the instance's deleted")
	}
	if got := strings.Join(kc.ClientByClientID(keycloak.ForwardAuthClient).RedirectURIs, ","); got != "https://auth.example.org/oauth2/callback" {
		t.Errorf("forward-auth callbacks = %s", got)
	}
	// Groups through the guardrails, as the actor.
	if got := strings.Join(groups.Calls(), ","); got != "-users_chat-b:root" {
		t.Errorf("groups = %s", got)
	}
	// Files (generated secrets included), ops record, state.
	for _, p := range []string{f.h.envPath("chat-b"), f.h.overridePath("chat-b"), f.h.userOverridePath("chat-b")} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still there", p)
		}
	}
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	_, a := st.Instances["chat-b"]
	_, b := st.Settings["chat-b"]
	_, c := st.PublicTokens["chat-b"]
	_, d := st.Published["chat-b"]
	if a || b || c || d || st.IsEnabled("chat-b") {
		t.Errorf("state left: %+v", st)
	}
	// The delete's own record is kept (contract §11.7: a deleted
	// instance's record outlives it; DeleteInstance runs the operation).
	if r := f.h.LastOp("chat-b"); r == nil || r.Op != OpDelete || !r.OK || r.Running {
		t.Errorf("op record = %+v", r)
	}
	for _, v := range f.h.Instances() {
		if v.ID == "chat-b" {
			t.Errorf("still listed: %+v", v)
		}
	}
	if strings.Contains(readFile(t, filepath.Join(f.data, "group-gate-policy.json")), "chat.team-b.example.org") {
		t.Error("policy still names the instance's host")
	}
	// The backup outlives it; the id may be used again.
	if l, _ := f.h.ListBackups(""); len(l) != 1 || l[0].InstanceExists || l[0].Reason != BackupDelete {
		t.Errorf("backups = %+v", l)
	}
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Errorf("id reuse after delete: %v", err)
	}
}

// TestDeleteDefaultInstanceKeepsSharedGroup: deleting a template's default
// instance removes its groups unless another template shares them.
func TestDeleteDefaultInstanceKeepsSharedGroup(t *testing.T) {
	shared := strings.NewReplacer("grafana", "dash", "Grafana", "Dash", "GRAFANA", "DASH").Replace(v2GrafanaManifest)
	shared = strings.Replace(shared, "access_group: users_dash", "access_group: users_grafana", 1)
	dashCompose := strings.NewReplacer("grafana-data", "dash-data", "grafana", "dash", "GRAFANA", "DASH").Replace(v2GrafanaCompose)
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"dash": {shared, dashCompose}})
	groups := &fakeGroups{}
	f.h.SetGroups(groups)
	simulateCompose(f, 0)
	if f.h.Template("dash") == nil {
		t.Fatal("dash not loaded")
	}
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	res, err := f.h.DeleteInstance("grafana", "grafana", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(groups.Calls(), ","); got != "-admin_grafana:root" {
		t.Errorf("groups = %s", got)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "users_grafana") || !strings.Contains(res.Warnings[0], "dash") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	// The template stays; enabling it again is a fresh default instance.
	if f.h.Template("grafana") == nil || f.h.IsEnabled("grafana") {
		t.Fatal("default instance view gone or still enabled")
	}
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreSameInstance(t *testing.T) {
	f, audit, _ := grafanaB(t)
	f.h.mu.Lock()
	f.h.st.Settings["grafana-b"] = state.InstanceSettings{Ports: map[string]string{"GRAFANA_PORT": "3401"}}
	f.h.saveLocked()
	f.h.mu.Unlock()
	writeFile(t, f.h.userOverridePath("grafana-b"), "services: {}\n")
	secret := readEnvFile(f.h.envPath("grafana-b"))["GF_SECRET"]
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}

	// Everything changes afterwards, hostnames too.
	putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "grafana.db", Mode: 0600, UID: 1, Body: "v2"}, fakeFile{Name: "junk", Body: "j"})
	setEnvVar(f.h.envPath("grafana-b"), "GF_SECRET", "changed")
	os.Remove(f.h.userOverridePath("grafana-b"))
	f.h.mu.Lock()
	f.h.st.Settings["grafana-b"] = state.InstanceSettings{Ports: map[string]string{"GRAFANA_PORT": "3402"}}
	f.h.mu.Unlock()
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "grafana-x.example.org"}, directory.Human("root")); err != nil {
		t.Fatal(err)
	}

	n := len(f.runner.Calls())
	res, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if res.PreRestoreBackup == "" || res.PreRestoreBackup == entry.Archive {
		t.Errorf("pre-restore backup = %q", res.PreRestoreBackup)
	}
	files := f.engine.volumeFiles("portcullis_grafana-b-grafana-data")
	if files["grafana.db"].Body != "v1" || files["grafana.db"].UID != 472 || files["grafana.db"].Mode != 0640 || files[""].UID != 472 {
		t.Errorf("volume = %+v", files)
	}
	if _, junk := files["junk"]; junk {
		t.Error("the volume was merged, not replaced")
	}
	env := readEnvFile(f.h.envPath("grafana-b"))
	if env["GF_SECRET"] != secret || env["PORTCULLIS_HOST_GRAFANA"] != "grafana-x.example.org" {
		t.Errorf("env = %v", env)
	}
	if _, err := os.Stat(f.h.userOverridePath("grafana-b")); err != nil {
		t.Error("custom override not restored")
	}
	if v := f.h.Template("grafana-b"); v == nil || v.Hosts["grafana"] != "grafana-x.example.org" || !v.Enabled {
		t.Errorf("view = %+v", v)
	}
	f.h.mu.RLock()
	k := f.h.st.Settings["grafana-b"].Ports["GRAFANA_PORT"]
	f.h.mu.RUnlock()
	if k != "3401" {
		t.Errorf("setting = %s", k)
	}
	calls := strings.Join(f.runner.Calls()[n:], " ")
	if !strings.HasPrefix(calls, "down:portcullis-grafana-b") || !strings.HasSuffix(calls, "up:portcullis-grafana-b") {
		t.Errorf("calls = %s", calls)
	}
	ve := f.engine.vol()
	last := ve.helperLog[len(ve.helperLog)-1]
	if last.ReadOnly || last.Image != HelperImage || len(last.Volumes) != 1 || len(ve.helpers) != 0 {
		t.Errorf("restore helper = %+v (left %d)", last, len(ve.helpers))
	}
	if a := audit.last(); a.Action != "instance.restore" || a.Result != "ok" || !strings.Contains(a.Detail, entry.Archive) {
		t.Errorf("audit = %+v", a)
	}
	if lo := f.h.LastOp("grafana-b"); lo == nil || lo.Op != OpRestore || !lo.OK {
		t.Errorf("last op = %+v", lo)
	}
	if _, err := f.h.RestoreInstance("grafana-c", entry.Archive, directory.Human("root")); statusOf(err) != 400 {
		t.Errorf("another instance's archive = %v", err)
	}
}

func TestRestoreFailureKeepsData(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	putFiles(f, "portcullis_grafana-b-grafana-data", fakeFile{Name: "grafana.db", Mode: 0600, UID: 472, Body: "current"})
	setEnvVar(f.h.envPath("grafana-b"), "GF_SECRET", "current")
	// The first extract fails (the archive's), the second (the
	// pre-restore backup's) works.
	var calls int32
	f.engine.vol().copyToErr = func(string) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			return errors.New("no space left on device")
		}
		return nil
	}
	_, err = f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root"))
	var oe *OpError
	if !errors.As(err, &oe) || !oe.Record.RolledBack || !strings.Contains(err.Error(), "previous data was put back") {
		t.Fatalf("failed restore = %v", err)
	}
	if got := f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["grafana.db"]; got.Body != "current" || got.UID != 472 {
		t.Errorf("volume after a failed restore = %+v", got)
	}
	if got := readEnvFile(f.h.envPath("grafana-b"))["GF_SECRET"]; got != "current" {
		t.Errorf("env after a failed restore = %s", got)
	}
	if !f.h.IsEnabled("grafana-b") {
		t.Error("left disabled")
	}
	if l, _ := f.h.ListBackups("grafana-b"); len(l) != 2 {
		t.Errorf("backups = %+v", l)
	}
}

func TestRestoreChecksumMismatchRefused(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	p := archivePath(f, entry.Archive)
	names, data, _ := readArchive(t, p)
	orig := map[string][]byte{}
	for k, v := range data {
		orig[k] = v
	}
	try := func(label string, names []string, data map[string][]byte, want int) {
		t.Helper()
		writeArchive(t, p, names, data)
		n, h := len(f.runner.Calls()), len(f.engine.vol().helperLog)
		_, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root"))
		if statusOf(err) != want {
			t.Errorf("%s: %v (want %d)", label, err, want)
		}
		if len(f.runner.Calls()) != n || len(f.engine.vol().helperLog) != h {
			t.Errorf("%s: something ran: %v", label, f.runner.Calls()[n:])
		}
		if fi, _ := os.ReadDir(filepath.Dir(p)); len(fi) != 1 {
			t.Errorf("%s: a pre-restore backup was taken", label)
		}
	}
	tampered := map[string][]byte{}
	for k, v := range orig {
		tampered[k] = v
	}
	tampered["config/env"] = append([]byte("EVIL=1\n"), orig["config/env"]...)
	try("changed member", names, tampered, 409)
	try("unlisted member", append(append([]string{}, names...), "config/extra"), map[string][]byte{"config/extra": []byte("x"), "MANIFEST.json": orig["MANIFEST.json"], "config/env": orig["config/env"], "config/instance.yaml": orig["config/instance.yaml"], "config/override.yml": orig["config/override.yml"], "volumes/grafana-data.tar": orig["volumes/grafana-data.tar"]}, 409)
	try("missing member", names[:len(names)-1], orig, 409)
	reordered := append([]string{}, names[1:]...)
	sort.Strings(reordered)
	try("manifest not first", append(reordered, "MANIFEST.json"), orig, 409)
	// A volume archive escaping the volume.
	var evil bytes.Buffer
	tw := tar.NewWriter(&evil)
	tw.WriteHeader(&tar.Header{Name: "data/../etc/passwd", Mode: 0644, Typeflag: tar.TypeReg})
	tw.Close()
	bad := map[string][]byte{}
	for k, v := range orig {
		bad[k] = v
	}
	bad["volumes/grafana-data.tar"] = evil.Bytes()
	var m BackupManifest
	json.Unmarshal(orig["MANIFEST.json"], &m)
	sum := sha256.Sum256(evil.Bytes())
	m.Files["volumes/grafana-data.tar"] = hex.EncodeToString(sum[:])
	bad["MANIFEST.json"], _ = json.Marshal(m)
	try("volume entry outside the volume", names, bad, 409)
	writeArchive(t, p, names, orig)
	for _, a := range []string{"../x.tar", "grafana-b/latest.tar", "grafana-b/20261102T153000Z.tar.partial"} {
		if _, err := f.h.RestoreInstance("grafana-b", a, directory.Human("root")); statusOf(err) != 400 {
			t.Errorf("archive %q = %v", a, err)
		}
	}
	if _, err := f.h.RestoreInstance("grafana-b", "grafana-b/20000101T000000Z.tar", directory.Human("root")); statusOf(err) != 404 {
		t.Errorf("missing archive = %v", err)
	}
	if files := f.engine.volumeFiles("portcullis_grafana-b-grafana-data"); files["grafana.db"].Body != "v1" {
		t.Errorf("volume changed: %+v", files)
	}
	// The intact archive still restores.
	if _, err := f.h.RestoreInstance("grafana-b", entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreIntoNewID(t *testing.T) {
	f, audit, groups := grafanaB(t)
	secret := readEnvFile(f.h.envPath("grafana-b"))["GF_SECRET"]
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	// Collisions are refused before anything is created.
	for id, want := range map[string]int{"grafana-b": 409, "grafana": 409, "Bad": 400} {
		if _, err := f.h.RestoreInstanceAs(entry.Archive, id, directory.Human("root")); statusOf(err) != want {
			t.Errorf("restore as %s = %v (want %d)", id, err, want)
		}
	}
	f.engine.addVolume("portcullis_grafana-d-grafana-data", "", "", 0) // a leftover
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-d", directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("restore over a leftover volume = %v", err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	v := f.h.Template("grafana-c")
	if v == nil || v.Hosts["grafana"] != "grafana-c.example.org" || v.Enabled {
		t.Fatalf("grafana-c = %+v", v)
	}
	var st string
	for _, iv := range f.h.Instances() {
		if iv.ID == "grafana-c" {
			st = iv.State
		}
	}
	if st != StateCreated {
		t.Errorf("state = %s", st)
	}
	files := f.engine.volumeFiles("portcullis_grafana-c-grafana-data")
	if files["grafana.db"].Body != "v1" || files["grafana.db"].UID != 472 || files[""].UID != 472 {
		t.Errorf("new volume = %+v", files)
	}
	vols, _ := f.engine.ListVolumes(nil, docker.Filters{"label": {docker.LabelProject + "=portcullis-grafana-c"}})
	if len(vols) != 1 || vols[0].Labels[docker.LabelVolume] != "grafana-data" {
		t.Errorf("volume labels = %+v", vols)
	}
	env := readEnvFile(f.h.envPath("grafana-c"))
	if env["GF_SECRET"] != secret || env["PORTCULLIS_INSTANCE"] != "grafana-c" || env["PORTCULLIS_HOST_GRAFANA"] != "grafana-c.example.org" {
		t.Errorf("env = %v", env)
	}
	if got := strings.Join(groups.Calls(), ","); got != "+users_grafana-c:root,+admin_grafana-c:root" {
		t.Errorf("groups = %s", got)
	}
	if a := audit.last(); a.Action != "instance.restore" || a.Target != "grafana-c" || a.Result != "ok" {
		t.Errorf("audit = %+v", a)
	}
	// It runs like any instance (the same host port as the original: one
	// at a time); the original is untouched.
	if err := f.h.Disable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-c"); err != nil {
		t.Fatal(err)
	}
	if f.engine.volumeFiles("portcullis_grafana-b-grafana-data")["grafana.db"].Body != "v1" {
		t.Error("the original changed")
	}
}

// TestRestoreIntoNewIDClients: a new id gets new Keycloak clients with
// regenerated client secrets.
func TestRestoreIntoNewIDClients(t *testing.T) {
	f := newInstanceFixture(t, nil)
	simulateCompose(f, 0)
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	old := readEnvFile(f.h.envPath("chat-b"))["CHAT_SECRET"]
	entry, err := f.h.BackupInstance("chat-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "chat-c", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if s := readEnvFile(f.h.envPath("chat-c"))["CHAT_SECRET"]; s == "" || s == old {
		t.Errorf("client secret not regenerated: %q", s)
	}
	if err := f.h.Enable("chat-c"); err != nil {
		t.Fatal(err)
	}
	reg := strings.Join(f.idp.registered, " ")
	if !strings.Contains(reg, "chat-c:chat-c:") || !strings.Contains(reg, "chat-c-chat-admin:chat-c:") {
		t.Errorf("registered = %s", reg)
	}
}

// TestRestoreNewIDImmutableHosts: a template that binds its data to a
// hostname can't be restored into a new id (its default would differ).
func TestRestoreNewIDImmutableHosts(t *testing.T) {
	m := strings.Replace(v2ChatManifest, "name: Chat", "name: Talk", 1)
	m = strings.Replace(m, "access_group: users_chat", "access_group: users_talk", 1)
	m = strings.NewReplacer("client_id: chat-admin", "client_id: talk-admin", "client_id: chat", "client_id: talk", "HOST_CHAT", "HOST_TALK", "CHAT_SECRET", "TALK_SECRET").Replace(m) + "hosts:\n  immutable: [talk]\n"
	c := strings.NewReplacer("chat", "talk", "CHAT", "TALK").Replace(v2ChatCompose)
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"talk": {m, c}})
	simulateCompose(f, 0)
	if f.h.Template("talk") == nil {
		t.Fatal("talk not loaded")
	}
	if err := f.h.CreateInstance("talk", "talk-b", nil); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("talk-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	// The archive's hostname is still talk-b's: refused, nothing created.
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "talk-c", directory.Human("root")); statusOf(err) != 409 || !strings.Contains(err.Error(), "talk-b") {
		t.Errorf("restore as a new id = %v", err)
	}
	if f.h.Template("talk-c") != nil {
		t.Error("talk-c was created")
	}
	// Another hostname for the immutable router: refused.
	if _, err := f.h.RestoreInstanceAsWith(entry.Archive, "talk-c", directory.Human("root"), map[string]string{"talk": "talk-c.example.org"}); statusOf(err) != 409 || !strings.Contains(err.Error(), "data is bound") {
		t.Errorf("restore as a new id with another immutable host = %v", err)
	}
	if _, err := f.h.RestoreInstance("talk-b", entry.Archive, directory.Human("root")); err != nil {
		t.Errorf("same-id restore: %v", err)
	}
	// Once talk-b is deleted, its hostname is free: a new id gets the
	// archive's hostname (final review I3).
	host := f.h.Template("talk-b").Hosts["talk"]
	if _, err := f.h.DeleteInstance("talk-b", "talk-b", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "talk-c", directory.Human("root")); err != nil {
		t.Fatalf("restore as a new id after the delete: %v", err)
	}
	v := f.h.Template("talk-c")
	if v == nil || v.Hosts["talk"] != host {
		t.Fatalf("talk-c hosts = %v, want %s", v, host)
	}
	f.h.mu.RLock()
	e := f.h.st.Instances["talk-c"]
	f.h.mu.RUnlock()
	if e.State != state.InstanceCreated || e.RestoreAs != "" {
		t.Errorf("talk-c entry after the restore = %+v", e)
	}
}

// TestRestoreAsHostsGiven: restore-as takes optional hostnames, validated
// like CreateInstance.
func TestRestoreAsHostsGiven(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAsWith(entry.Archive, "grafana-c", directory.Human("root"), map[string]string{"grafana": "grafana-b.example.org"}); statusOf(err) != 409 {
		t.Errorf("taken hostname = %v", err)
	}
	if _, err := f.h.RestoreInstanceAsWith(entry.Archive, "grafana-c", directory.Human("root"), map[string]string{"nope": "x.example.org"}); statusOf(err) != 400 {
		t.Errorf("unknown router = %v", err)
	}
	if _, err := f.h.RestoreInstanceAsWith(entry.Archive, "grafana-c", directory.Human("root"), map[string]string{"grafana": "Dash.Example.org."}); err != nil {
		t.Fatal(err)
	}
	if v := f.h.Template("grafana-c"); v == nil || v.Hosts["grafana"] != "dash.example.org" {
		t.Fatalf("grafana-c = %v", v)
	}
}

// TestCreateInstanceRefusesExistingVolume: a new instance never adopts a
// volume that already exists (a deleted instance's leftover or anything
// else).
func TestCreateInstanceRefusesExistingVolume(t *testing.T) {
	f := newInstanceFixture(t, nil)
	f.engine.addVolume("portcullis_grafana-b-grafana-data", "", "", 0)
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); statusOf(err) != 409 || !strings.Contains(err.Error(), "portcullis_grafana-b-grafana-data") {
		t.Errorf("create over a leftover volume = %v", err)
	}
	f.engine.addVolume("odd-name", "portcullis-grafana-c", "x", 0)
	if err := f.h.CreateInstance("grafana", "grafana-c", nil); statusOf(err) != 409 {
		t.Errorf("create over a volume of the same project = %v", err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-e", nil); err != nil {
		t.Error(err)
	}
}

// TestDisableRemovesCallbacks: disabling an instance drops its
// extra-domain sign-in callbacks (enable adds them back).
func TestDisableRemovesCallbacks(t *testing.T) {
	f := newInstanceFixture(t, nil)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "grafana.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Disable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.idp.callbacks, " | "); got != "+https://grafana.team-b.example.org/oauth2/callback - | + -https://grafana.team-b.example.org/oauth2/callback" {
		t.Errorf("callbacks = %s", got)
	}
}

// TestSnapshotKeepsClaims: an enabled instance whose template disappears
// keeps its volume, client and Traefik names against newcomers.
func TestSnapshotKeepsClaims(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	snap := f.h.st.Published["grafana"]
	f.h.mu.RUnlock()
	if strings.Join(snap.Volumes, ",") != "portcullis_grafana-data" || len(snap.Traefik) == 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
	// grafana's template goes away; a newcomer reusing its volume and a
	// Traefik name is skipped.
	os.RemoveAll(filepath.Join(f.src, "grafana"))
	newcomer := strings.Replace(v2GrafanaManifest, "name: Grafana", "name: Copy", 1)
	newcomer = strings.NewReplacer("users_grafana", "users_copy", "admin_grafana", "admin_copy").Replace(newcomer)
	writeFile(t, filepath.Join(f.src, "copy", "manifest.yaml"), newcomer)
	writeFile(t, filepath.Join(f.src, "copy", "compose.yml"), strings.Replace(v2GrafanaCompose, "grafana.portcullis.local", "copy.portcullis.local", -1))
	f.h.Discover()
	if f.h.Template("copy") != nil {
		t.Error("a newcomer took a missing template's claimed names")
	}
}

// TestDiscoverStatefulClaimsFirst: a disabled template with state keeps
// its names against a newcomer earlier in source order.
func TestDiscoverStatefulClaimsFirst(t *testing.T) {
	newcomer := strings.Replace(v2GrafanaManifest, "name: Grafana", "name: Aaa", 1)
	newcomer = strings.NewReplacer("users_grafana", "users_aaa", "admin_grafana", "admin_aaa").Replace(newcomer)
	aaaCompose := strings.Replace(v2GrafanaCompose, "grafana.portcullis.local", "aaa.portcullis.local", -1)
	f := newInstanceFixtureExtra(t, func(st *state.AppState) {
		st.Settings["grafana"] = state.InstanceSettings{Ports: map[string]string{"K": "v"}}
	}, nil, map[string][2]string{"aaa": {newcomer, aaaCompose}})
	if f.h.Template("grafana") == nil || f.h.Template("aaa") != nil {
		t.Errorf("grafana %v, aaa %v: the stateful template must keep its names", f.h.Template("grafana") != nil, f.h.Template("aaa") != nil)
	}
}
