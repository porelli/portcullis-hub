package hub

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
	"gopkg.in/yaml.v3"
)

// immichManifest is the settings fixture (contract v3): instance options
// delivered by env (restart), a live option delivered by a hook, a bool
// rendered as 1/0, a requires pair, an indexed list, two host paths (one
// read-only, writing as a key-referenced uid) and a per-person size with
// a group_values placeholder row.
const immichManifest = `name: Immich
category: media
instances: multi
auth:
  method: header-auth
  group_access: true
  access_group: users_immich
  admin_group: admin_immich
urls:
  - label: Photos
    url: "https://{{HOST_IMMICH}}"
files:
  - {name: people, service: server, mount: /portcullis, on_membership_change: restart}
hooks:
  - {name: motd, service: server, command: [/bin/motd], when: [settings_change]}
settings:
  options:
    - key: trash_days
      label: Trash days
      type: int
      min: 1
      default: 7
      applies: restart
      delivery: [{env: IMMICH_TRASH_DAYS}]
    - key: motd
      label: Message of the day
      type: string
      applies: live
      delivery: [{hook: motd}]
    - key: banner
      label: Banner
      type: string
      applies: live
      delivery: [{env: IMMICH_BANNER}, {hook: motd}]
    - key: ml
      label: Machine learning
      type: bool
      default: false
      delivery: [{env: IMMICH_ML, render: {"true": "1", "false": "0"}}]
    - key: version
      label: Version
      type: string
      delivery: [{env: IMMICH_VERSION}]
    - key: version_sha
      label: Version checksum
      type: string
      requires: [version]
      delivery: [{env: IMMICH_VERSION_SHA}]
    - key: puid
      label: User id
      type: int
      default: 1000
      delivery: [{env: IMMICH_UID}]
    - key: library
      label: Library
      type: path
      target: {service: server, mount: /library}
      mode: ro
      needs: read
      writes_as: {uid: puid, gid: 1001}
    - key: uploads
      label: Uploads
      type: path
      target: {service: server, mount: /uploads}
      mode: rw
      needs: write
    - key: disks
      label: Disks
      type: list
      items: {type: string}
      max_items: 3
      delivery: [{env: "DISK_{n}"}]
    - key: quota
      label: Quota
      type: size
      scope: person
      default: 10GiB
      resolve: max
      group_values: {"{{ADMIN_GROUP}}": 100GiB}
      delivery: [{file: {name: people, field: quota}}]
    - key: admin_token
      label: Admin token
      type: secret
      applies: live
      delivery: [{hook: motd}]
ports:
  - key: IMMICH_PORT
    container: 2283
    default: 2283
    service: server
`

const immichCompose = "services:\n" +
	"  server:\n" +
	"    image: immich\n" +
	"    environment:\n" +
	"      TRASH: ${IMMICH_TRASH_DAYS}\n" +
	"      ML: ${IMMICH_ML}\n" +
	"      BANNER: ${IMMICH_BANNER}\n" +
	"      NOTE: ${CORE_NOTE}\n" +
	"      V: ${IMMICH_VERSION}\n" +
	"      VS: ${IMMICH_VERSION_SHA}\n" +
	"      APP_UID: ${IMMICH_UID}\n" +
	"      D1: ${DISK_1:-}\n" +
	"      D2: ${DISK_2:-}\n" +
	"      D3: ${DISK_3:-}\n" +
	"    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.immich.rule: Host(`${PORTCULLIS_HOST_IMMICH:-immich.portcullis.local}`)\n" +
	"      traefik.http.routers.immich.entrypoints: websecure\n" +
	"      traefik.http.routers.immich.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"      traefik.http.services.immich.loadbalancer.server.port: \"2283\"\n"

// immichFixture loads the settings fixture next to the instance fixtures,
// with an audit log.
func immichFixture(t *testing.T) (*fixture, *fakeAudit) {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"immich": {immichManifest, immichCompose}})
	if f.h.Template("immich") == nil {
		t.Fatalf("immich fixture not loaded (see the log)")
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	return f, audit
}

func ups(f *fixture, id string) int {
	n := 0
	for _, c := range f.runner.Calls() {
		if c == "up:"+projectName(id) {
			n++
		}
	}
	return n
}

func envOf(t *testing.T, f *fixture, id string) string {
	t.Helper()
	b, err := os.ReadFile(f.h.envPath(id))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSaveRestartsOnlyWhenNeeded(t *testing.T) {
	f, _ := immichFixture(t)
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	before := ups(f, "immich")

	res, err := f.h.SaveSettings("immich", SettingsUpdate{Values: vals("motd", "hello")}, "admin")
	f.h.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if res.Effect != settings.EffectNone || !reflect.DeepEqual(res.Changed, []string{"motd"}) || res.Deliveries == nil {
		t.Errorf("motd only: %+v", res)
	}
	if n := ups(f, "immich"); n != before {
		t.Errorf("a live option restarted the app (%d ups, was %d)", n, before)
	}

	res, err = f.h.SaveSettings("immich", SettingsUpdate{Values: vals("motd", "bye", "trash_days", 30)}, "admin")
	f.h.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if res.Effect != settings.EffectRestart || len(res.Changed) != 2 {
		t.Errorf("both: %+v", res)
	}
	if n := ups(f, "immich"); n != before+1 {
		t.Errorf("ups = %d, want one restart (%d)", n, before+1)
	}

	// Unchanged values, and a disabled instance: no restart.
	res, err = f.h.SaveSettings("immich", SettingsUpdate{Values: vals("trash_days", 30)}, "admin")
	f.h.Wait()
	if err != nil || res.Effect != settings.EffectNone || len(res.Changed) != 0 || ups(f, "immich") != before+1 {
		t.Errorf("unchanged: %+v %v", res, err)
	}
	// A port or path change is always a restart.
	res, err = f.h.SaveSettings("immich", SettingsUpdate{Ports: map[string]string{"IMMICH_PORT": "2290"}}, "admin")
	f.h.Wait()
	if err != nil || res.Effect != settings.EffectRestart || ups(f, "immich") != before+2 {
		t.Errorf("port: %+v %v", res, err)
	}
	res, err = f.h.SaveSettings("immich", SettingsUpdate{Values: vals("uploads", "/srv/up")}, "admin")
	f.h.Wait()
	if err != nil || res.Effect != settings.EffectRestart || ups(f, "immich") != before+3 {
		t.Errorf("path: %+v %v", res, err)
	}
}

func TestSaveValidatesTypes(t *testing.T) {
	f, _ := immichFixture(t)
	for name, c := range map[string]struct {
		u    SettingsUpdate
		want []string
	}{
		"wrong type":     {SettingsUpdate{Values: vals("trash_days", "x")}, []string{"trash_days"}},
		"below min":      {SettingsUpdate{Values: vals("trash_days", 0)}, []string{"trash_days"}},
		"unknown key":    {SettingsUpdate{Values: vals("nope", 1)}, []string{`unknown setting "nope"`}},
		"person as inst": {SettingsUpdate{Values: vals("quota", "1GiB")}, []string{"quota", "person"}},
		"unknown port":   {SettingsUpdate{Ports: map[string]string{"NOPE": "1"}}, []string{`unknown port setting "NOPE"`}},
		"requires":       {SettingsUpdate{Values: vals("version_sha", "abc")}, []string{"version_sha", "version"}},
		"quote in env":   {SettingsUpdate{Values: vals("version", "it's")}, []string{"version", "IMMICH_VERSION"}},
		"backslash":      {SettingsUpdate{Values: vals("version", `x\`)}, []string{"version", "IMMICH_VERSION", "backslash"}},
		"backslash item": {SettingsUpdate{Values: vals("disks", []string{`C:\d`})}, []string{"disks", "DISK_1"}},
		"too many items": {SettingsUpdate{Values: vals("disks", []string{"a", "b", "c", "d"})}, []string{"disks"}},
		"folder":         {SettingsUpdate{Values: vals("library", "folder:photos")}, []string{"library", "shared folder"}},
		"secret change":  {SettingsUpdate{Secrets: map[string]SecretChange{"motd": {Generate: true}}}, []string{"motd"}},
		"person default": {SettingsUpdate{Person: map[string]PersonChange{"quota": {Default: json.RawMessage(`"lots"`)}}}, []string{"quota", "default"}},
		"duplicate rows": {SettingsUpdate{Person: map[string]PersonChange{"quota": {Default: json.RawMessage(`"1GiB"`), Rows: []GroupValueInput{{Group: "staff", Value: json.RawMessage(`"2GiB"`)}, {Group: "staff", Value: json.RawMessage(`"3GiB"`)}}}}}, []string{"quota", "staff", "more than one row"}},
	} {
		_, err := f.h.SaveSettings("immich", c.u, "admin")
		if statusOf(err) != 400 {
			t.Errorf("%s: err = %v, want 400", name, err)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q doesn't name %q", name, err, w)
			}
		}
	}
	// Nothing was stored.
	f.h.mu.RLock()
	s, ok := f.h.st.Settings["immich"]
	f.h.mu.RUnlock()
	if ok && len(s.Values)+len(s.Ports) > 0 {
		t.Errorf("refused saves stored %+v", s)
	}
	// The pair together is fine; the size is stored canonical.
	if err := f.h.save("immich", SettingsUpdate{Values: vals("version", "1.2.3", "version_sha", "abc", "trash_days", "14")}); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	s = f.h.st.Settings["immich"]
	f.h.mu.RUnlock()
	if s.Values["trash_days"] != int64(14) || s.Types["trash_days"] != templates.TypeInt {
		t.Errorf("stored %#v types %v", s.Values, s.Types)
	}
	// Clearing the required half of a pair is refused.
	if err := f.h.save("immich", SettingsUpdate{Values: vals("version", nil)}); statusOf(err) != 400 {
		t.Errorf("clearing version under version_sha = %v", err)
	}
}

func TestEnvDeliveryRendered(t *testing.T) {
	f, _ := immichFixture(t)
	if err := f.h.save("immich", SettingsUpdate{Values: vals("trash_days", 30, "ml", true, "disks", []string{"/dev/sda", "/dev/a b$c"})}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	env := envOf(t, f, "immich")
	for _, want := range []string{"\nIMMICH_TRASH_DAYS='30'\n", "\nIMMICH_ML='1'\n", "\nDISK_1='/dev/sda'\n", "\nDISK_2='/dev/a b$c'\n", "\nDISK_3=\n", "\nIMMICH_UID='1000'\n", "\nIMMICH_VERSION=\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %q:\n%s", want, env)
		}
	}
	if got := readEnvFile(f.h.envPath("immich")); got["DISK_2"] != "/dev/a b$c" || got["IMMICH_TRASH_DAYS"] != "30" {
		t.Errorf("read back: %v", got)
	}
	// null: back to the default, written at once; a bool's false render.
	if err := f.h.save("immich", SettingsUpdate{Values: vals("trash_days", nil, "ml", false, "disks", nil)}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	env = envOf(t, f, "immich")
	for _, want := range []string{"\nIMMICH_TRASH_DAYS='7'\n", "\nIMMICH_ML='0'\n", "\nDISK_1=\n", "\nDISK_2=\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("after reset, env lacks %q:\n%s", want, env)
		}
	}
	f.h.mu.RLock()
	_, stored := f.h.st.Settings["immich"].Values["trash_days"]
	f.h.mu.RUnlock()
	if stored {
		t.Error("null stored a value")
	}
}

type fakeFolders map[string]string

func (f fakeFolders) FolderHostPath(id, sub string) (string, error) {
	p, ok := f[id]
	if !ok {
		return "", errors.New("no such folder")
	}
	return filepath.Join(p, sub), nil
}

func TestPathMountReadOnly(t *testing.T) {
	f, _ := immichFixture(t)
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "/srv/$photos", "uploads", "/srv/up/")}); err != nil {
		t.Fatal(err)
	}
	ov := readFile(t, f.h.overridePath("immich"))
	if !strings.Contains(ov, `- "/srv/$$photos:/library:ro"`) || !strings.Contains(ov, `- "/srv/up:/uploads"`) {
		t.Errorf("override:\n%s", ov)
	}
	// folder:… without a FolderSource: refused.
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "folder:photos/2024")}); statusOf(err) != 400 {
		t.Errorf("folder without source = %v", err)
	}
	f.h.SetFolderSource(fakeFolders{"photos": "/tank/photos"})
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "folder:nope")}); statusOf(err) != 400 {
		t.Errorf("unknown folder = %v", err)
	}
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "folder:photos/../x")}); statusOf(err) != 400 {
		t.Errorf("escaping subpath = %v", err)
	}
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "folder:photos/2024")}); err != nil {
		t.Fatal(err)
	}
	ov = readFile(t, f.h.overridePath("immich"))
	if !strings.Contains(ov, `- "/tank/photos/2024:/library:ro"`) {
		t.Errorf("override with a folder:\n%s", ov)
	}
}

func TestPathUsages(t *testing.T) {
	f, _ := immichFixture(t)
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "/srv/photos", "puid", 1234)}); err != nil {
		t.Fatal(err)
	}
	if got := f.h.PathUsages(); len(got) != 0 {
		t.Errorf("disabled instance listed: %+v", got)
	}
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	got := f.h.PathUsages()
	want := []PathUsage{{Instance: "immich", Key: "library", Type: "path", HostPath: "/srv/photos", Service: "server",
		Mount: "/library", Mode: "ro", Needs: "read", UID: 1234, GID: 1001, OwnerKnown: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("usages = %+v", got)
	}
	if err := f.h.save("immich", SettingsUpdate{Values: vals("uploads", "/srv/up")}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	got = f.h.PathUsages()
	if len(got) != 2 || got[1].Key != "uploads" || got[1].Mode != "rw" || got[1].Needs != "write" || got[1].OwnerKnown {
		t.Errorf("usages = %+v", got)
	}
}

func TestSettingsAudited(t *testing.T) {
	f, audit := immichFixture(t)
	if err := f.h.save("immich", SettingsUpdate{Values: vals("trash_days", 30)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveSettings("immich", SettingsUpdate{Values: vals("trash_days", 60)}, "alice"); err != nil {
		t.Fatal(err)
	}
	e := audit.last()
	if e.Action != "settings.change" || e.Target != "immich/trash_days" || e.Detail != "scope=instance: 30 -> 60" || e.Actor != "alice" || e.Result != "ok" {
		t.Errorf("entry = %+v", e)
	}
	if _, err := f.h.SaveSettings("immich", SettingsUpdate{Ports: map[string]string{"IMMICH_PORT": "2290"}}, "alice"); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Target != "immich/IMMICH_PORT" || e.Detail != "scope=port: default -> 2290" {
		t.Errorf("port entry = %+v", e)
	}
	n := len(audit.entries)
	if _, err := f.h.SaveSettings("immich", SettingsUpdate{Values: vals("trash_days", "x")}, "bob"); statusOf(err) != 400 {
		t.Fatal(err)
	}
	if e := audit.last(); len(audit.entries) != n+1 || e.Action != "settings.change" || e.Target != "immich/trash_days" || e.Result != "refused" || e.Actor != "bob" {
		t.Errorf("refused entry = %+v", e)
	}
	// One entry per changed key; nothing for an unchanged one.
	n = len(audit.entries)
	if _, err := f.h.SaveSettings("immich", SettingsUpdate{Values: vals("trash_days", 60, "motd", "hi", "ml", true)}, "alice"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range audit.entries[n:] {
		got = append(got, e.Target+" "+e.Detail)
	}
	if want := []string{"immich/ml scope=instance: No -> Yes", "immich/motd scope=instance: unset -> hi"}; !reflect.DeepEqual(got, want) {
		t.Errorf("entries = %q", got)
	}
}

func TestSeedOnCreate(t *testing.T) {
	f, _ := immichFixture(t)
	if err := f.h.CreateInstance("immich", "immich-b", nil); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	s := f.h.st.Settings["immich-b"].Clone()
	f.h.mu.RUnlock()
	if len(s.Values) != 0 || len(s.Ports) != 0 {
		t.Errorf("instance values stored: %+v", s)
	}
	want := state.PersonSetting{Default: int64(10 << 30), Rows: []state.GroupValue{{Group: templates.PlaceholderAdminGroup, Value: int64(100 << 30)}}}
	if !reflect.DeepEqual(s.Person["quota"], want) || s.Types["quota"] != templates.TypeSize {
		t.Errorf("person = %#v types %v", s.Person, s.Types)
	}
	// A default instance is seeded on its first enable; a stored
	// configuration is never re-seeded.
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	p := f.h.st.Settings["immich"].Person["quota"]
	if len(p.Rows) != 1 {
		t.Errorf("default instance not seeded: %+v", f.h.st.Settings["immich"])
	}
	p.Rows = nil
	f.h.st.Settings["immich"].Person["quota"] = p
	f.h.seedSettingsLocked(f.h.findLocked("immich"))
	rows := f.h.st.Settings["immich"].Person["quota"].Rows
	f.h.mu.Unlock()
	if len(rows) != 0 {
		t.Errorf("re-seeded: %+v", rows)
	}
	// Survives state.yaml.
	st, err := state.Load(filepath.Join(f.data, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Settings["immich-b"].Person["quota"]; got.Rows[0].Group != templates.PlaceholderAdminGroup || got.Rows[0].GroupID != 0 {
		t.Errorf("loaded %+v", got)
	}
}

func TestBackupCarriesTypedSettings(t *testing.T) {
	f, _ := immichFixture(t)
	simulateCompose(f, 0)
	f.h.SetGroups(&fakeGroups{})
	if err := f.h.CreateInstance("immich", "immich-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.save("immich-b", SettingsUpdate{Values: vals("trash_days", 30, "disks", []string{"/dev/sda"}), Ports: map[string]string{"IMMICH_PORT": "2290"}}); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	s := f.h.st.Settings["immich-b"]
	s.Person["quota"] = state.PersonSetting{Default: int64(5 << 30), Resolve: "max", Rows: []state.GroupValue{{Group: "staff", GroupID: 7, Value: "unlimited"}}}
	f.h.st.Settings["immich-b"] = s
	f.h.saveLocked()
	f.h.mu.Unlock()
	// A real secret: its metadata in state, its value in the store.
	const secret = "tok-9f8e7d6c5b4a"
	if err := f.h.save("immich-b", SettingsUpdate{Secrets: map[string]SecretChange{"admin_token": setSecret(secret)}}); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	want := f.h.st.Settings["immich-b"].Clone()
	f.h.mu.Unlock()
	if _, ok := want.Secrets["admin_token"]; !ok {
		t.Fatalf("no secret metadata: %+v", want.Secrets)
	}

	entry, err := f.h.BackupInstance("immich-b", "root")
	if err != nil {
		t.Fatal(err)
	}
	_, data, _ := readArchive(t, archivePath(f, entry.Archive))
	var cfg instanceConfig
	if err := yaml.Unmarshal(data["config/instance.yaml"], &cfg); err != nil || cfg.Settings == nil {
		t.Fatalf("instance.yaml: %v\n%s", err, data["config/instance.yaml"])
	}
	if _, ok := cfg.Settings.Secrets["admin_token"]; !ok {
		t.Errorf("instance.yaml lacks the secret's metadata:\n%s", data["config/instance.yaml"])
	}
	// The value is in config/settings-secrets.json and nowhere else.
	if !bytes.Contains(data[secretsMember], []byte(secret)) {
		t.Errorf("%s lacks the secret", secretsMember)
	}
	for name, b := range data {
		if name != secretsMember && bytes.Contains(b, []byte(secret)) {
			t.Errorf("archive member %s holds the secret value", name)
		}
	}
	// The size row is not valid for quota without allow_unlimited:
	// refused on restore, nothing changes.
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "immich-c", "root"); statusOf(err) != 409 || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("restore with an invalid row = %v", err)
	}
	f.h.mu.Lock()
	s = f.h.st.Settings["immich-b"]
	s.Person["quota"] = state.PersonSetting{Default: int64(5 << 30), Resolve: "max", Rows: []state.GroupValue{{Group: "staff", GroupID: 7, Value: "2GiB"}}}
	f.h.st.Settings["immich-b"] = s
	f.h.saveLocked()
	f.h.mu.Unlock()
	want.Person["quota"] = state.PersonSetting{Default: int64(5 << 30), Resolve: "max", Rows: []state.GroupValue{{Group: "staff", GroupID: 7, Value: int64(2 << 30)}}}
	if entry, err = f.h.BackupInstance("immich-b", "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "immich-c", "root"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	got := f.h.st.Settings["immich-c"].Clone()
	f.h.mu.RUnlock()
	if _, ok := got.Secrets["admin_token"]; !ok || storedSecrets(t, f, "immich-c")["admin_token"] != secret {
		t.Errorf("restore-as didn't copy the secret: %+v", got.Secrets)
	}
	if fmt.Sprint(got.Values) != fmt.Sprint(want.Values) || !reflect.DeepEqual(got.Ports, want.Ports) || fmt.Sprint(got.Person) != fmt.Sprint(want.Person) || len(got.Groups) != 0 {
		t.Errorf("restored:\n got %#v\nwant %#v", got, want)
	}
	if got.Types["trash_days"] != templates.TypeInt || got.Types["quota"] != templates.TypeSize {
		t.Errorf("types = %v", got.Types)
	}
	// Same-instance restore puts the archived values back.
	if err := f.h.save("immich-b", SettingsUpdate{Values: vals("trash_days", 99)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.RestoreInstance("immich-b", entry.Archive, "root"); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	v := f.h.st.Settings["immich-b"].Values["trash_days"]
	f.h.mu.RUnlock()
	if fmt.Sprint(v) != "30" {
		t.Errorf("trash_days after restore = %v", v)
	}
}

// The env quoting: what the Hub writes reads back as it was.
func TestEnvQuoteHelpers(t *testing.T) {
	for _, v := range []string{"a$b", "x y#z", `"q"`, "", "plain"} {
		p := filepath.Join(t.TempDir(), "e.env")
		if err := setEnvVars(p, map[string]string{"K": v}, true); err != nil {
			t.Fatal(err)
		}
		if got := readEnvFile(p)["K"]; got != v {
			t.Errorf("%q read back as %q", v, got)
		}
	}
	if _, err := envQuote("it's"); err == nil {
		t.Error("a single quote was quoted")
	}
	if _, err := envQuote("a\nb"); err == nil {
		t.Error("a newline was quoted")
	}
	if l := envLine("K", "a b # c", false); l != "K=a b # c" {
		t.Errorf("a value the Hub doesn't own is written raw: %s", l)
	}
	if l := envLine("K", "a b", true); l != "K='a b'" {
		t.Errorf("option value: %s", l)
	}
	if l := envLine("K", "", true); l != "K=" {
		t.Errorf("empty option value: %s", l)
	}
}
