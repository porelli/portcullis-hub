package hub

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/credentials"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

const (
	smbB     = smbID + "-b"
	smbKey   = "share_password"
	testPass = "Abcd-EFGH-jkmn-PQRS-tuvw-2345"
)

// credFixture is smbFixture with a usable secrets volume (<root>/secrets,
// 0700, the test's uid), an audit and a directory (alice, bob, carol in
// users_smbfixture); connect_address set on both instances.
func credFixture(t *testing.T) (*fixture, *fakeAudit, string) {
	t.Helper()
	var secrets string
	f := credFixtureWith(t, func(root string, c *Config) {
		secrets = filepath.Join(root, "secrets")
		if err := os.Mkdir(secrets, 0700); err != nil {
			t.Fatal(err)
		}
		c.SecretsDir = secrets
	})
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	return f, audit, secrets
}

func credFixtureWith(t *testing.T, cfg func(root string, c *Config)) *fixture {
	t.Helper()
	m := mustRead(t, filepath.Join("testdata", "settings", smbID, "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", smbID, "compose.yml"))
	f := newInstanceFixtureCfg(t, nil, nil, map[string][2]string{smbID: {string(m), string(c)}}, cfg)
	if f.h.Template(smbID) == nil {
		t.Fatalf("smbfixture not loaded (see the log)")
	}
	if err := f.h.CreateInstance(smbID, smbB, nil); err != nil {
		t.Fatal(err)
	}
	smbPeople(f.h)
	simulateCompose(f, 0)
	for _, id := range []string{smbID, smbB} {
		if err := f.h.save(id, SettingsUpdate{Values: vals("connect_address", "files.example.org")}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// smbPeople wires a directory with alice, bob, carol in both instances'
// access groups.
func smbPeople(h *Hub) {
	people := newFakePeople()
	people.addGroup("users_"+smbID, "alice", "bob", "carol")
	people.addGroup("admin_" + smbID)
	people.addGroup("users_"+smbB, "alice", "bob", "carol")
	people.addGroup("admin_" + smbB)
	h.SetPeople(people)
	h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{}})
}

// addCred records an active credential of user on (inst, smbKey) with
// hash, as a create does: metadata, then the hash file and the epoch.
func addCred(t *testing.T, h *Hub, inst, user, hash string) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.st.Credentials[inst] == nil {
		h.st.Credentials[inst] = map[string]map[string]state.Credential{}
	}
	if h.st.Credentials[inst][smbKey] == nil {
		h.st.Credentials[inst][smbKey] = map[string]state.Credential{}
	}
	h.st.Credentials[inst][smbKey][user] = state.Credential{ID: "c-" + user, Version: 1, UUID: "u-" + user, CreatedAt: time.Now().UTC(), CreatedBy: user}
	if err := h.writeHashLocked(inst, smbKey, user, hash); err != nil {
		t.Fatal(err)
	}
}

func credOf(h *Hub, inst, user string) (state.Credential, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	c, ok := h.st.Credentials[inst][smbKey][user]
	return c, ok
}

// restart builds a new Hub over f's directories (a Hub restart), with
// audit, and runs Init.
func restart(t *testing.T, f *fixture, secrets string, audit *fakeAudit, hook func(string)) *Hub {
	t.Helper()
	h, err := New(Config{ProjectDir: f.project, ProjectHostDir: "/host/project", DataDir: f.data, Domain: "example.org", SecretsDir: secrets}, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h.lockPoll = 5 * time.Millisecond
	h.SetAudit(audit)
	h.testHookInit = hook
	h.Init()
	t.Cleanup(h.Wait)
	return h
}

func voidAudits(a *fakeAudit) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.entries {
		if e.Action == "credential.void_restore" {
			out = append(out, e.Target+" "+e.Detail)
		}
	}
	return out
}

func volumeFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

func TestHashFileLayout(t *testing.T) {
	f, _, secrets := credFixture(t)
	hash := credentials.NTHash([]byte(testPass))
	addCred(t, f.h, smbB, "alice", hash)
	p := filepath.Join(secrets, smbB, smbKey, "alice.nt")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 33 || string(b) != hash+"\n" {
		t.Errorf("hash file = %q", b)
	}
	for path, want := range map[string]os.FileMode{p: 0600, filepath.Dir(p): 0700, filepath.Dir(filepath.Dir(p)): 0700} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode %v %v, want %v", path, fi.Mode().Perm(), err, want)
		}
	}
	gp, err := f.h.secretPath(smbB, smbKey, "alice")
	if err != nil || gp != p {
		t.Errorf("secretPath = %q %v", gp, err)
	}
	// F11: neither the hash (either case) nor the password in state.yaml
	// or the instance archive's instance.yaml.
	st := readFile(t, filepath.Join(f.data, "state.yaml"))
	entry, err := f.h.BackupInstance(smbB, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	_, data, _ := readArchive(t, archivePath(f, entry.Archive))
	for name, text := range map[string]string{"state.yaml": st, "instance.yaml": string(data["config/instance.yaml"])} {
		for _, s := range []string{hash, strings.ToLower(hash), testPass} {
			if strings.Contains(text, s) {
				t.Errorf("%s holds %q", name, s)
			}
		}
	}
	if !strings.Contains(st, "credentials:") {
		t.Error("state.yaml has no credentials metadata")
	}
	ep := strings.TrimSpace(readFile(t, filepath.Join(secrets, ".epoch")))
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(ep) || ep != loadState(t, f).SecretsEpoch {
		t.Errorf(".epoch %q, state %q", ep, loadState(t, f).SecretsEpoch)
	}
}

func TestEpochMismatchVoidsAll(t *testing.T) {
	f, audit, secrets := credFixture(t)
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	addCred(t, f.h, smbB, "bob", credentials.NTHash([]byte("b")))
	statePath := filepath.Join(f.data, "state.yaml")
	old := readFile(t, statePath)
	// A credential change after the copy: the volume's epoch moves on.
	addCred(t, f.h, smbB, "carol", credentials.NTHash([]byte("c")))
	f.h.Wait()
	writeFile(t, statePath, old) // a restored state.yaml next to a newer volume
	var stages []string
	h := restart(t, f, secrets, audit, func(s string) { stages = append(stages, s) })
	for _, u := range []string{"alice", "bob"} {
		c, ok := credOf(h, smbB, u)
		if !ok || c.Active() || c.Reason != state.CredentialReasonRestore || c.RevokedAt == nil {
			t.Errorf("%s = %+v %v, want voided (restore)", u, c, ok)
		}
	}
	if got := volumeFiles(t, secrets); len(got) != 1 || got[0] != ".epoch" {
		t.Errorf("volume = %v, want only .epoch", got)
	}
	if ep := strings.TrimSpace(readFile(t, filepath.Join(secrets, ".epoch"))); ep == "" || ep != loadState(t, f).SecretsEpoch {
		t.Errorf("epochs differ after the void")
	}
	if got := voidAudits(audit); len(got) != 1 || got[0] != smbB+" count=2 reason=restore" {
		t.Errorf("audits = %v", got)
	}
	// The pools advanced before any delivery (Task 5 carry).
	if got := strings.Join(stages, ","); got != "secrets,pools,requeue" {
		t.Errorf("Init stages = %s", got)
	}
	if p := loadState(t, f).PersonIDs[templates.PoolPOSIXUID]; p.Next < 20000+PoolRewindStep {
		t.Errorf("pool next = %d: not advanced", p.Next)
	}
	// A matching epoch at the next start voids nothing more.
	n := len(voidAudits(audit))
	var again []string
	restart(t, f, secrets, audit, func(s string) { again = append(again, s) })
	if len(voidAudits(audit)) != n || strings.Join(again, ",") != "secrets,requeue" {
		t.Errorf("second start voided again or advanced: %v %v", voidAudits(audit), again)
	}
}

func TestCoreRestoreEmptyVolumeVoidsAll(t *testing.T) {
	f, audit, secrets := credFixture(t)
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	// Core's restore empties hub_secrets (no .epoch).
	os.RemoveAll(filepath.Join(secrets, smbB))
	os.Remove(filepath.Join(secrets, ".epoch"))
	h := restart(t, f, secrets, audit, nil)
	if c, _ := credOf(h, smbB, "alice"); c.Active() || c.Reason != state.CredentialReasonRestore {
		t.Errorf("alice = %+v", c)
	}
	if got := voidAudits(audit); len(got) != 1 || got[0] != smbB+" count=1 reason=restore" {
		t.Errorf("audits = %v", got)
	}
}

func TestCrashBetweenHashAndStateFailsClosed(t *testing.T) {
	f, audit, secrets := credFixture(t)
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	// The state save after the volume's epoch write fails (F57).
	if err := os.Chmod(f.data, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(f.data, 0755) })
	f.h.mu.Lock()
	f.h.st.Credentials[smbB][smbKey]["bob"] = state.Credential{ID: "c-bob", Version: 1, UUID: "u-bob", CreatedBy: "bob"}
	err := f.h.writeHashLocked(smbB, smbKey, "bob", credentials.NTHash([]byte("b")))
	mem := f.h.st.SecretsEpoch
	f.h.mu.Unlock()
	os.Chmod(f.data, 0755)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusInternalServerError {
		t.Fatalf("err = %v, want 500", err)
	}
	if vol := strings.TrimSpace(readFile(t, filepath.Join(secrets, ".epoch"))); vol != mem || vol == loadState(t, f).SecretsEpoch {
		t.Errorf("in-memory epoch %q, volume %q, disk %q: memory must equal the volume, disk differ", mem, vol, loadState(t, f).SecretsEpoch)
	}
	f.h.Wait()
	h := restart(t, f, secrets, audit, nil)
	if c, _ := credOf(h, smbB, "alice"); c.Active() {
		t.Error("alice still active after the interrupted change")
	}
	if got := volumeFiles(t, secrets); len(got) != 1 {
		t.Errorf("volume = %v", got)
	}
}

func TestOrphansReconciled(t *testing.T) {
	f, audit, secrets := credFixture(t)
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	addCred(t, f.h, smbB, "bob", credentials.NTHash([]byte("b")))
	// A hash file without active metadata; bob's file gone.
	writeFile(t, filepath.Join(secrets, smbB, smbKey, "mallory.nt"), credentials.NTHash([]byte("m"))+"\n")
	writeFile(t, filepath.Join(secrets, smbB, smbKey, "alice.nt.tmp-123"), "x")
	os.Remove(filepath.Join(secrets, smbB, smbKey, "bob.nt"))
	n, err := f.h.reconcileSecrets("test")
	if err != nil || n != 1 {
		t.Fatalf("reconcile = %d %v", n, err)
	}
	if got := strings.Join(volumeFiles(t, secrets), ","); got != ".epoch,"+smbB+"/"+smbKey+"/alice.nt" {
		t.Errorf("volume = %s", got)
	}
	if c, _ := credOf(f.h, smbB, "alice"); !c.Active() {
		t.Error("alice voided")
	}
	if c, _ := credOf(f.h, smbB, "bob"); c.Active() || c.Reason != state.CredentialReasonRestore {
		t.Errorf("bob = %+v", c)
	}
	if got := voidAudits(audit); len(got) != 1 || got[0] != smbB+" count=1 reason=restore" {
		t.Errorf("audits = %v", got)
	}
	if ep := strings.TrimSpace(readFile(t, filepath.Join(secrets, ".epoch"))); ep != loadState(t, f).SecretsEpoch {
		t.Error("epochs differ")
	}
}

func TestSecretPathRefusesBadNames(t *testing.T) {
	f, _, _ := credFixture(t)
	for _, c := range [][3]string{{smbB, smbKey, "../x"}, {smbB, smbKey, "Alice"}, {smbB, "..", "alice"}, {"../etc", smbKey, "alice"}, {smbB, smbKey, ".hidden"}, {smbB, smbKey, strings.Repeat("a", 65)}, {smbB, smbKey, "a/b"}} {
		if _, err := f.h.secretPath(c[0], c[1], c[2]); err == nil {
			t.Errorf("secretPath%v accepted", c)
		} else if se := (*StatusError)(nil); !errors.As(err, &se) || se.Status != 500 {
			t.Errorf("secretPath%v = %v, want 500", c, err)
		}
		f.h.mu.Lock()
		err := f.h.writeHashLocked(c[0], c[1], c[2], credentials.NTHash([]byte("x")))
		f.h.mu.Unlock()
		if err == nil {
			t.Errorf("writeHashLocked%v accepted", c)
		}
	}
	f.h.mu.Lock()
	err := f.h.writeHashLocked(smbB, smbKey, "alice", "not-a-hash")
	f.h.mu.Unlock()
	if err == nil || strings.Contains(err.Error(), "not-a-hash") {
		t.Errorf("non-hash = %v", err)
	}
}

func TestSecretsMountSubpath(t *testing.T) {
	f, _, secrets := credFixture(t)
	var dirOK bool
	prev := f.runner.createHook
	f.runner.createHook = func(project string) {
		fi, err := os.Stat(filepath.Join(secrets, smbB, smbKey))
		dirOK = err == nil && fi.IsDir() && fi.Mode().Perm() == 0700
		prev(project)
	}
	if err := f.h.Enable(smbB); err != nil {
		t.Fatal(err)
	}
	if !dirOK {
		t.Error("the hash directory didn't exist (0700) before compose up")
	}
	ov := readFile(t, f.h.overridePath(smbB))
	for _, want := range []string{
		"      - type: volume\n        source: portcullis-hub-secrets\n        target: \"/portcullis/secrets\"\n        read_only: true\n        volume:\n          subpath: \"smbfixture-b/share_password\"\n",
		"volumes:\n  portcullis-hub-secrets:\n    external: true\n    name: \"portcullis_hub_secrets\"\n",
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("override lacks\n%s\ngot:\n%s", want, ov)
		}
	}
	if strings.Count(ov, "portcullis-hub-secrets") != 2 || !strings.Contains(ov, "  smb:\n") {
		t.Errorf("the secrets mount is not on smb only:\n%s", ov)
	}
}

// TestPreUpCheckRefusesOtherMounts: custom overrides stored without
// their save checks (the pre-up check is the last line).
func TestPreUpCheckRefusesOtherMounts(t *testing.T) {
	f, _, _ := credFixture(t)
	if err := f.h.Enable(smbB); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"another subpath": "services:\n  smb:\n    volumes:\n      - type: volume\n        source: portcullis-hub-secrets\n        target: /portcullis/secrets\n        read_only: true\n        volume: {subpath: smbfixture/share_password}\n",
		"writable":        "services:\n  smb:\n    volumes:\n      - type: volume\n        source: portcullis-hub-secrets\n        target: /portcullis/secrets\n        read_only: false\n        volume: {subpath: smbfixture-b/share_password}\n",
		"whole volume":    "services:\n  smb:\n    volumes:\n      - portcullis-hub-secrets:/all:ro\n",
		"another key":     "volumes:\n  sneaky:\n    external: true\n    name: portcullis_hub_secrets\nservices:\n  smb:\n    volumes:\n      - sneaky:/all\n",
	}
	for name, ov := range cases {
		writeFile(t, f.h.userOverridePath(smbB), ov)
		live := f.h.Template(smbB)
		err := f.h.checkSecretsMounts(t.Context(), live)
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 409 {
			t.Errorf("%s: err = %v, want 409", name, err)
		}
	}
	os.Remove(f.h.userOverridePath(smbB))
	if err := f.h.checkSecretsMounts(t.Context(), f.h.Template(smbB)); err != nil {
		t.Errorf("the Hub's own mount refused: %v", err)
	}
	// An Engine API without subpath mounts.
	f.engine.mu.Lock()
	f.engine.apiVersion = "1.44"
	f.engine.mu.Unlock()
	if err := f.h.checkSecretsMounts(t.Context(), f.h.Template(smbB)); err == nil || !strings.Contains(err.Error(), "1.45") {
		t.Errorf("API 1.44 = %v", err)
	}
}

func TestCustomOverrideRefusesSecretsKey(t *testing.T) {
	f, _, _ := credFixture(t)
	for _, ov := range []string{
		"services:\n  smb:\n    volumes:\n      - portcullis-hub-secrets:/x:ro\n",
		"services:\n  smb:\n    volumes:\n      - type: volume\n        source: portcullis-hub-secrets\n        target: /x\n",
		"services:\n  smb:\n    volumes:\n      - Portcullis-Hub-Secrets:/x\n",
		"volumes:\n  portcullis-hub-secrets:\n    labels: {a: b}\n",
	} {
		if _, _, err := f.h.SaveUserOverride(smbB, ov); err == nil || !strings.Contains(err.Error(), "portcullis-hub-secrets") {
			t.Errorf("override accepted (%v):\n%s", err, ov)
		}
	}
}

func TestSecretsUnusableFailsClosed(t *testing.T) {
	var secrets string
	f := credFixtureWith(t, func(root string, c *Config) {
		secrets = filepath.Join(root, "secrets")
		os.Mkdir(secrets, 0755) // not 0700
		c.SecretsDir = secrets
	})
	err := f.h.SecretsUsable()
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 503 || !strings.Contains(err.Error(), "0700") {
		t.Errorf("SecretsUsable = %v", err)
	}
	err = f.h.Enable(smbB)
	if err == nil || !strings.Contains(err.Error(), "secrets volume") {
		t.Errorf("enable = %v, want a refusal naming the secrets volume", err)
	}
	if f.h.IsEnabled(smbB) || len(f.runner.Creates()) != 0 {
		t.Error("the instance started")
	}
	// Other instances are unaffected (the Hub runs).
	if err := checkSecretsDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing dir passes")
	}
	if err := checkSecretsDir(""); err == nil {
		t.Error("no dir passes")
	}
}

func TestBackupExcludesCredentials(t *testing.T) {
	f, _, _ := credFixture(t)
	hash := credentials.NTHash([]byte(testPass))
	addCred(t, f.h, smbB, "alice", hash)
	entry, err := f.h.BackupInstance(smbB, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(archivePath(f, entry.Archive))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{hash, strings.ToLower(hash)} {
		if strings.Contains(string(raw), s) {
			t.Error("the archive holds the hash")
		}
	}
	_, data, _ := readArchive(t, archivePath(f, entry.Archive))
	if strings.Contains(string(data["config/instance.yaml"]), "credentials") {
		t.Error("instance.yaml has a credentials key")
	}
}

// hubSecretsVolume adds core's hub_secrets volume to the fake engine —
// adversarially labelled with the instance's project too.
func hubSecretsVolume(f *fixture) {
	f.engine.addVolume(DefaultSecretsVolume, projectName(smbB), "hub_secrets", 10001, fakeFile{Name: "x.nt", Mode: 0600, UID: 10001, Body: "SECRET"})
}

func TestBackupExcludesHubSecretsVolume(t *testing.T) {
	f, _, _ := credFixture(t)
	hubSecretsVolume(f)
	if err := f.h.Enable(smbB); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance(smbB, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	names, data, _ := readArchive(t, archivePath(f, entry.Archive))
	for _, n := range names {
		if strings.HasPrefix(n, "volumes/") {
			t.Errorf("archived volume %s", n)
		}
	}
	if strings.Contains(string(data["MANIFEST.json"]), DefaultSecretsVolume) {
		t.Error("the manifest lists the secrets volume")
	}
	if _, err := f.h.RestoreInstance(smbB, entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.DeleteInstance(smbB, smbB, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if !slicesContain(f.engine.volumeNames(), DefaultSecretsVolume) {
		t.Error("the secrets volume was removed")
	}
	for _, s := range f.engine.vol().helperLog {
		if _, ok := s.Volumes[DefaultSecretsVolume]; ok {
			t.Errorf("a helper mounted the secrets volume: %+v", s)
		}
	}
}

func slicesContain(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestRestoreVoidsCredentials(t *testing.T) {
	f, audit, secrets := credFixture(t)
	if err := f.h.Enable(smbB); err != nil {
		t.Fatal(err)
	}
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	addCred(t, f.h, smbB, "bob", credentials.NTHash([]byte("b")))
	addCred(t, f.h, smbID, "carol", credentials.NTHash([]byte("c")))
	entry, err := f.h.BackupInstance(smbB, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	// The void happens before the restored start: no hash file is there
	// when compose creates the containers.
	var atCreate []string
	prev := f.runner.createHook
	f.runner.createHook = func(project string) {
		if project == projectName(smbB) {
			atCreate = volumeFiles(t, filepath.Join(secrets, smbB))
		}
		prev(project)
	}
	if _, err := f.h.RestoreInstance(smbB, entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if len(atCreate) != 0 {
		t.Errorf("hash files at the restored start: %v", atCreate)
	}
	for _, u := range []string{"alice", "bob"} {
		if c, _ := credOf(f.h, smbB, u); c.Active() || c.Reason != state.CredentialReasonRestore {
			t.Errorf("%s = %+v", u, c)
		}
	}
	if !f.h.IsEnabled(smbB) {
		t.Error("not enabled again")
	}
	// TestRestoreDoesNotTouchHubSecrets: the other instance keeps its
	// credential and file.
	if c, _ := credOf(f.h, smbID, "carol"); !c.Active() {
		t.Error("carol (another instance) voided")
	}
	if _, err := os.Stat(filepath.Join(secrets, smbID, smbKey, "carol.nt")); err != nil {
		t.Errorf("carol's hash file: %v", err)
	}
	if got := voidAudits(audit); len(got) != 1 || got[0] != smbB+" count=2 reason=restore" {
		t.Errorf("audits = %v", got)
	}
	// Into a new id: no credentials, nothing audited.
	if _, err := f.h.RestoreInstanceAs(entry.Archive, smbID+"-c", directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	_, has := f.h.st.Credentials[smbID+"-c"]
	f.h.mu.RUnlock()
	if has {
		t.Error("the new instance has credentials")
	}
	if got := voidAudits(audit); len(got) != 1 {
		t.Errorf("audits = %v", got)
	}
	// A second restore voids nothing more (none active): no audit.
	if _, err := f.h.RestoreInstance(smbB, entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if got := voidAudits(audit); len(got) != 1 {
		t.Errorf("audits after a restore without credentials = %v", got)
	}
}

func TestRestoreDoesNotTouchHubSecrets(t *testing.T) {
	f, _, secrets := credFixture(t)
	hubSecretsVolume(f)
	addCred(t, f.h, smbID, "carol", credentials.NTHash([]byte("c")))
	entry, err := f.h.BackupInstance(smbB, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstance(smbB, entry.Archive, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if !slicesContain(f.engine.volumeNames(), DefaultSecretsVolume) {
		t.Error("the secrets volume was replaced or removed")
	}
	if _, err := os.Stat(filepath.Join(secrets, smbID, smbKey, "carol.nt")); err != nil {
		t.Error(err)
	}
}

func TestInstanceDeleteRevokes(t *testing.T) {
	f, audit, secrets := credFixture(t)
	if err := f.h.Enable(smbB); err != nil {
		t.Fatal(err)
	}
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	addCred(t, f.h, smbID, "carol", credentials.NTHash([]byte("c")))
	// The secrets go right after the delete's compose down, before
	// anything later can fail.
	var atDown []string
	f.runner.onDown = func(project string) {
		if project == projectName(smbB) {
			atDown = append(atDown, "down")
		}
	}
	f.idp.mu.Lock()
	f.idp.callbackErr = errors.New("keycloak down")
	f.idp.mu.Unlock()
	if _, err := f.h.DeleteInstance(smbB, smbB, directory.Human("root")); err == nil {
		t.Fatal("the delete didn't fail part-way")
	}
	if len(atDown) == 0 {
		t.Fatal("no compose down")
	}
	if _, err := os.Stat(filepath.Join(secrets, smbB)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("<secrets>/%s after a failed delete: %v", smbB, err)
	}
	f.h.mu.RLock()
	_, has := f.h.st.Credentials[smbB]
	f.h.mu.RUnlock()
	if has || strings.Contains(readFile(t, filepath.Join(f.data, "state.yaml")), "c-alice") {
		t.Error("the metadata survived")
	}
	if c, _ := credOf(f.h, smbID, "carol"); !c.Active() {
		t.Error("another instance's credential went")
	}
	if len(voidAudits(audit)) != 0 {
		t.Error("a delete audits credential voids")
	}
	if ep := strings.TrimSpace(readFile(t, filepath.Join(secrets, ".epoch"))); ep != loadState(t, f).SecretsEpoch {
		t.Error("epochs differ after the delete")
	}
}

func TestDeleteRemovesSecrets(t *testing.T) {
	f, _, secrets := credFixture(t)
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	if _, err := f.h.DeleteInstance(smbB, smbB, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(secrets, smbB)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("<secrets>/%s: %v", smbB, err)
	}
	if _, ok := loadState(t, f).Credentials[smbB]; ok {
		t.Error("metadata in state.yaml")
	}
}

func TestDeleteKeepsHubSecretsVolume(t *testing.T) {
	f, _, _ := credFixture(t)
	hubSecretsVolume(f)
	if _, err := f.h.DeleteInstance(smbB, smbB, directory.Human("root")); err != nil {
		t.Fatal(err)
	}
	if !slicesContain(f.engine.volumeNames(), DefaultSecretsVolume) {
		t.Error("the delete removed the secrets volume")
	}
}

func TestPathSettingDockerRoot(t *testing.T) {
	f, _ := immichFixture(t)
	fx := f.engine.fx()
	fx.fmu.Lock()
	fx.dockerRoot = "/srv/docker"
	fx.fmu.Unlock()
	for _, p := range []string{"/srv/docker", "/srv/docker/volumes/portcullis_hub_secrets/_data", "/srv"} {
		err := f.h.save("immich", SettingsUpdate{Values: vals("library", p)})
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 400 {
			t.Errorf("library %s = %v, want 400", p, err)
		}
	}
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "/srv/photos")}); err != nil {
		t.Errorf("a path beside the Docker root: %v", err)
	}
	// Unreadable Docker root: 503.
	fx.fmu.Lock()
	fx.rootErr = errors.New("info failed")
	fx.fmu.Unlock()
	err := f.h.save("immich", SettingsUpdate{Values: vals("uploads", "/srv/up")})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 503 {
		t.Errorf("unreadable root = %v, want 503", err)
	}
	fx.fmu.Lock()
	fx.rootErr = nil
	fx.fmu.Unlock()
	// Restore: an archived path under the Docker root is refused.
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "/srv/photos")}); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("immich", directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	fx.fmu.Lock()
	fx.dockerRoot = "/srv/photos/docker"
	fx.fmu.Unlock()
	_, err = f.h.RestoreInstance("immich", entry.Archive, directory.Human("root"))
	if !errors.As(err, &se) || se.Status != 400 {
		t.Errorf("restore = %v, want 400", err)
	}
}

// ── fix round 1 ──────────────────────────────────────────

// lockDir makes dir unwritable (its files can't be removed) until the
// returned func runs (also at cleanup).
func lockDir(t *testing.T, dir string) func() {
	t.Helper()
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	undo := func() { os.Chmod(dir, 0700) }
	t.Cleanup(undo)
	return undo
}

func createsOf(f *fixture, id string) int {
	n := 0
	for _, c := range f.runner.Creates() {
		if c == projectName(id) {
			n++
		}
	}
	return n
}

func TestReconcileFailureFailsClosed(t *testing.T) {
	f, audit, secrets := credFixture(t)
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	f.h.Wait()
	// A core restore (no .epoch) whose emptying fails part-way.
	os.Remove(filepath.Join(secrets, ".epoch"))
	unlock := lockDir(t, filepath.Join(secrets, smbB, smbKey))
	h := restart(t, f, secrets, audit, nil)
	smbPeople(h)
	var se *StatusError
	if err := h.SecretsUsable(); !errors.As(err, &se) || se.Status != 503 {
		t.Errorf("SecretsUsable = %v, want 503", err)
	}
	before := createsOf(f, smbB)
	if err := h.Enable(smbB); err == nil {
		t.Fatal("enabled with the old hash files still on the volume")
	}
	if createsOf(f, smbB) != before || h.IsEnabled(smbB) {
		t.Error("compose ran while the reconcile had failed")
	}
	// Fixed: the next operation reconciles again and the old hashes go
	// before anything mounts them.
	unlock()
	var atCreate []string
	prev := f.runner.createHook
	f.runner.createHook = func(project string) {
		if project == projectName(smbB) {
			atCreate = volumeFiles(t, filepath.Join(secrets, smbB))
		}
		prev(project)
	}
	if err := h.Enable(smbB); err != nil {
		t.Fatalf("enable after the fix: %v", err)
	}
	if len(atCreate) != 0 {
		t.Errorf("old hashes mounted: %v", atCreate)
	}
	if err := h.SecretsUsable(); err != nil {
		t.Errorf("SecretsUsable after the retry = %v", err)
	}
	if c, _ := credOf(h, smbB, "alice"); c.Active() {
		t.Error("alice still active")
	}
}

func TestPreUpRefusesSharedNamespaces(t *testing.T) {
	f, _, _ := credFixture(t)
	if err := f.h.Enable(smbB); err != nil {
		t.Fatal(err)
	}
	for name, ov := range map[string]string{
		"pid service":         "services:\n  spy:\n    image: x\n    pid: service:smb\n",
		"ipc service":         "services:\n  spy:\n    image: x\n    ipc: service:smb\n",
		"pid host":            "services:\n  spy:\n    image: x\n    pid: host\n",
		"ipc host":            "services:\n  spy:\n    image: x\n    ipc: host\n",
		"pid ctr":             "services:\n  spy:\n    image: x\n    pid: container:abc\n",
		"mounter pid service": "services:\n  web:\n    image: x\n  smb:\n    pid: service:web\n",
		"mounter ipc service": "services:\n  web:\n    image: x\n  smb:\n    ipc: service:web\n",
		"unrelated pair":      "services:\n  a:\n    image: x\n  b:\n    image: x\n    pid: service:a\n",
	} {
		writeFile(t, f.h.userOverridePath(smbB), ov)
		err := f.h.checkSecretsMounts(t.Context(), f.h.Template(smbB))
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 409 {
			t.Errorf("%s: err = %v, want 409", name, err)
		}
	}
}

func TestPreUpRefusesDockerRootPaths(t *testing.T) {
	f, _, _ := credFixture(t)
	cases := map[string]string{
		"bind under":   "services:\n  smb:\n    volumes:\n      - /var/lib/docker/volumes/portcullis_hub_secrets/_data:/x:ro\n",
		"bind above":   "services:\n  smb:\n    volumes:\n      - type: bind\n        source: /var/lib\n        target: /x\n",
		"local device": "volumes:\n  v:\n    driver: local\n    driver_opts: {type: none, o: bind, device: /var/lib/docker}\nservices:\n  smb:\n    volumes: [\"v:/y\"]\n",
	}
	for name, ov := range cases {
		writeFile(t, f.h.userOverridePath(smbB), ov)
		err := f.h.checkSecretsMounts(t.Context(), f.h.Template(smbB))
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 400 {
			t.Errorf("%s: err = %v, want 400", name, err)
		}
	}
	// Beside the root: fine (also for an instance without secrets).
	writeFile(t, f.h.userOverridePath(smbB), "services:\n  smb:\n    volumes:\n      - /srv/media:/media:ro\n")
	if err := f.h.checkSecretsMounts(t.Context(), f.h.Template(smbB)); err != nil {
		t.Errorf("a bind beside the Docker root: %v", err)
	}
	fx := f.engine.fx()
	fx.fmu.Lock()
	fx.rootErr = errors.New("info down")
	fx.fmu.Unlock()
	err := f.h.checkSecretsMounts(t.Context(), f.h.Template(smbB))
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 503 {
		t.Errorf("unreadable root = %v, want 503", err)
	}
}

func TestLoaderErrorNotEchoed(t *testing.T) {
	f, _, _ := credFixture(t)
	writeFile(t, f.h.userOverridePath(smbB), "services:\n  smb:\n    environment: [\"TOKEN=SuperSecret123\"\n")
	err := f.h.checkSecretsMounts(t.Context(), f.h.Template(smbB))
	if err == nil || strings.Contains(err.Error(), "SuperSecret123") || !strings.Contains(err.Error(), "don't parse") {
		t.Errorf("err = %v", err)
	}
}

func TestRestoreRolledBackBeforeVoid(t *testing.T) {
	f, audit, secrets := credFixture(t)
	if err := f.h.Enable(smbB); err != nil {
		t.Fatal(err)
	}
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	entry, err := f.h.BackupInstance(smbB, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	failed := false
	f.h.testHookApplyRestore = func(stage string) error {
		if stage == "volumes" && !failed {
			failed = true
			return errors.New("injected volume failure")
		}
		return nil
	}
	if _, err := f.h.RestoreInstance(smbB, entry.Archive, directory.Human("root")); err == nil {
		t.Fatal("the restore didn't fail")
	}
	if c, _ := credOf(f.h, smbB, "alice"); !c.Active() {
		t.Error("a rolled-back restore voided alice")
	}
	if _, err := os.Stat(filepath.Join(secrets, smbB, smbKey, "alice.nt")); err != nil {
		t.Errorf("alice's hash file: %v", err)
	}
	if len(voidAudits(audit)) != 0 {
		t.Errorf("audits = %v", voidAudits(audit))
	}
	if !f.h.IsEnabled(smbB) {
		t.Error("not running again after the rollback")
	}
}

func TestRestoreVoidErrorNeverStartsOldHashes(t *testing.T) {
	f, _, secrets := credFixture(t)
	if err := f.h.Enable(smbB); err != nil {
		t.Fatal(err)
	}
	addCred(t, f.h, smbB, "alice", credentials.NTHash([]byte("a")))
	entry, err := f.h.BackupInstance(smbB, directory.Human("root"))
	if err != nil {
		t.Fatal(err)
	}
	unlock := lockDir(t, filepath.Join(secrets, smbB, smbKey))
	before := createsOf(f, smbB)
	if _, err := f.h.RestoreInstance(smbB, entry.Archive, directory.Human("root")); err == nil {
		t.Fatal("the restore didn't fail")
	}
	if createsOf(f, smbB) != before || f.h.IsEnabled(smbB) {
		t.Error("the instance started with the old hash files")
	}
	if c, _ := credOf(f.h, smbB, "alice"); c.Active() {
		t.Error("alice still active after a void that failed")
	}
	unlock()
	if err := f.h.SecretsUsable(); err != nil {
		t.Errorf("after the fix: %v", err)
	}
	if _, err := os.Stat(filepath.Join(secrets, smbB, smbKey, "alice.nt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("alice's old hash file: %v", err)
	}
}
