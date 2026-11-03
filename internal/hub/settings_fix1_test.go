package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/dotenv"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// composeReads is the .env as compose's own dotenv parser reads it (no
// outside variables).
func composeReads(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := dotenv.UnmarshalBytesWithLookup(b, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("compose can't parse %s: %v\n%s", path, err, b)
	}
	return m
}

// Fix 1 (Critical): a value with a backslash is refused; what the Hub
// writes reads back intact under compose's dotenv, every line after it
// included.
func TestEnvBackslashNeverBreaksALine(t *testing.T) {
	if _, err := envQuote(`x\`); err == nil {
		t.Fatal(`envQuote accepted x\`)
	}
	// What would happen: a quoted x\ swallows the next line.
	p := filepath.Join(t.TempDir(), "raw.env")
	os.WriteFile(p, []byte("A='x\\'\nB='y'\nC=z\n"), 0600)
	if m, err := dotenv.UnmarshalBytesWithLookup(mustRead(t, p), nil); err == nil && m["C"] == "z" && m["B"] == "y" {
		t.Logf("note: this compose-go version reads the trailing backslash safely")
	}

	f, _ := immichFixture(t)
	if err := f.h.save("immich", SettingsUpdate{Values: vals("version", `a$b #c "d"`, "version_sha", "x y", "banner", "%PATH% ;$$", "disks", []string{"/dev/a b", "#x"})}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	got := composeReads(t, f.h.envPath("immich"))
	for k, want := range map[string]string{
		"IMMICH_VERSION": `a$b #c "d"`, "IMMICH_VERSION_SHA": "x y", "IMMICH_BANNER": "%PATH% ;$$",
		"DISK_1": "/dev/a b", "DISK_2": "#x", "DISK_3": "", "IMMICH_TRASH_DAYS": "7",
		"PORTCULLIS_INSTANCE": "immich", "PORTCULLIS_HOST_IMMICH": "immich.example.org",
	} {
		if got[k] != want {
			t.Errorf("compose reads %s = %q, want %q", k, got[k], want)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Fix 2: lines the Hub doesn't own keep their raw text byte for byte
// (core-env references, preserved lines, Expert values).
func TestEnvForeignLinesKeptRaw(t *testing.T) {
	f, _ := immichFixture(t)
	writeFile(t, filepath.Join(f.project, ".env"), "CORE_VAR=core-value\nCORE_NOTE=bar  # note\n")
	raw := []string{"FOO=bar  # note", "X=$$2y$$10x", `Y="a$b"`, "Z=${OTHER}"}
	writeFile(t, f.h.envPath("immich"), "# kept\n"+strings.Join(raw, "\n")+"\n")
	if err := f.h.SaveEnv("immich", map[string]string{"W": "${OTHER}"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.save("immich", SettingsUpdate{Values: vals("trash_days", 30)}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.save("immich", SettingsUpdate{Values: vals("trash_days", 31)}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if err := f.h.RestartApp("immich"); err != nil {
		t.Fatal(err)
	}
	env := envOf(t, f, "immich")
	for _, l := range append(raw, "W=${OTHER}", "CORE_NOTE=bar  # note", "IMMICH_TRASH_DAYS='31'") {
		if !strings.Contains(env, "\n"+l+"\n") {
			t.Errorf("env lacks the line %q:\n%s", l, env)
		}
	}
	got := composeReads(t, f.h.envPath("immich"))
	if got["FOO"] != "bar" || got["X"] != "$2y$10x" || got["CORE_NOTE"] != "bar" {
		t.Errorf("compose reads FOO=%q X=%q CORE_NOTE=%q", got["FOO"], got["X"], got["CORE_NOTE"])
	}
}

// Fix 3: a committed save whose env / override write fails is audited
// as committed (before -> after), plus one error entry for the failure.
func TestCommittedSaveAuditedOnDeliveryFailure(t *testing.T) {
	f, audit := immichFixture(t)
	if err := f.h.save("immich", SettingsUpdate{Values: vals("trash_days", 30)}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(f.h.overridePath("immich"))
	os.Chmod(dir, 0500)
	defer os.Chmod(dir, 0755)
	n := len(audit.entries)
	_, err := f.h.SaveSettings("immich", SettingsUpdate{Values: vals("uploads", "/srv/up")}, "alice")
	if statusOf(err) != 500 {
		t.Fatalf("err = %v", err)
	}
	es := audit.entries[n:]
	if len(es) != 2 || es[0].Target != "immich/uploads" || es[0].Result != "ok" || es[0].Detail != "scope=instance: unset -> /srv/up" ||
		es[1].Target != "immich" || es[1].Detail != "delivery" || es[1].Result != "error" {
		t.Errorf("entries = %+v", es)
	}
	f.h.mu.RLock()
	v := f.h.st.Settings["immich"].Values["uploads"]
	f.h.mu.RUnlock()
	if v != "/srv/up" {
		t.Errorf("committed value = %v", v)
	}
}

// Fix 4 and 6: an env-delivered option restarts a running instance
// whatever its applies; a disabled one reports the options' own effect.
func TestEffectEnvAndDisabled(t *testing.T) {
	f, _ := immichFixture(t)
	for k, v := range map[string]any{"motd": "hi", "banner": "b", "uploads": "/srv/up"} {
		res, err := f.h.SaveSettings("immich", SettingsUpdate{Values: vals(k, v)}, "admin")
		want := settings.EffectNone
		if k == "uploads" {
			want = settings.EffectRestart // a path applies at restart
		}
		if err != nil || res.Effect != want {
			t.Errorf("disabled, %s: %+v %v (want %s)", k, res, err, want)
		}
	}
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	before := ups(f, "immich")
	res, err := f.h.SaveSettings("immich", SettingsUpdate{Values: vals("banner", "c")}, "admin")
	f.h.Wait()
	if err != nil || res.Effect != settings.EffectRestart || ups(f, "immich") != before+1 {
		t.Errorf("env-delivered live option: %+v %v, ups %d", res, err, ups(f, "immich")-before)
	}
}

// Fix 5: a shared folder's resolved host path is checked like any path.
func TestFolderHostPathChecked(t *testing.T) {
	f, _ := immichFixture(t)
	f.h.SetFolderSource(fakeFolders{"bad": "/tank/a:b", "rel": "tank", "root": "/"})
	for _, id := range []string{"bad", "rel", "root"} {
		if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "folder:"+id)}); statusOf(err) != 400 {
			t.Errorf("folder %s = %v", id, err)
		}
	}
}

// Fix 7: the restore paths and "create missing groups" seed a person
// option that has no stored configuration.
func TestSeedOnRestoreAndMissingGroups(t *testing.T) {
	f, _ := immichFixture(t)
	simulateCompose(f, 0)
	groups := &fakeGroups{}
	f.h.SetGroups(groups)
	if err := f.h.CreateInstance("immich", "immich-b", nil); err != nil {
		t.Fatal(err)
	}
	unseed := func(id string) {
		f.h.mu.Lock()
		s := f.h.st.Settings[id]
		delete(s.Person, "quota")
		f.h.st.Settings[id] = s
		f.h.saveLocked()
		f.h.mu.Unlock()
	}
	seeded := func(id string) bool {
		f.h.mu.RLock()
		defer f.h.mu.RUnlock()
		p, ok := f.h.st.Settings[id].Person["quota"]
		return ok && len(p.Rows) == 1 && p.Rows[0].Group == templates.PlaceholderAdminGroup
	}
	unseed("immich-b")
	entry, err := f.h.BackupInstance("immich-b", "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "immich-c", "root"); err != nil {
		t.Fatal(err)
	}
	if !seeded("immich-c") {
		t.Error("restore-as didn't seed")
	}
	if _, err := f.h.RestoreInstance("immich-b", entry.Archive, "root"); err != nil {
		t.Fatal(err)
	}
	if !seeded("immich-b") {
		t.Error("same-instance restore didn't seed")
	}
	if err := f.h.Enable("immich-c"); err != nil {
		t.Fatal(err)
	}
	unseed("immich-c")
	if _, err := f.h.CreateMissingGroups(context.Background(), []string{"immich-c"}, "root"); err != nil {
		t.Fatal(err)
	}
	if !seeded("immich-c") {
		t.Error("create missing groups didn't seed")
	}
}

// Fix 9: settings in the old flat form are never read silently (a lost
// _BIND would publish the port everywhere): an archive holding them is
// refused, naming the instance.
func TestRestoreRefusesLegacyFlatSettings(t *testing.T) {
	f, _, _ := grafanaB(t)
	entry, err := f.h.BackupInstance("grafana-b", "root")
	if err != nil {
		t.Fatal(err)
	}
	p := archivePath(f, entry.Archive)
	_, data, _ := readArchive(t, p)
	cfg := string(data["config/instance.yaml"])
	if strings.Contains(cfg, "settings:") {
		t.Fatalf("fixture already has settings:\n%s", cfg)
	}
	rewriteMember(t, p, "config/instance.yaml", []byte(cfg+"settings:\n  GRAFANA_PORT: \"3301\"\n  GRAFANA_PORT_BIND: 127.0.0.1\n"))
	_, err = f.h.RestoreInstance("grafana-b", entry.Archive, "root")
	if err == nil || !strings.Contains(err.Error(), "grafana-b") || !strings.Contains(err.Error(), "old flat form") {
		t.Fatalf("restore of flat settings = %v", err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "grafana-c", "root"); err == nil || !strings.Contains(err.Error(), "old flat form") {
		t.Fatalf("restore-as of flat settings = %v", err)
	}
}
