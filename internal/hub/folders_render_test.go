package hub

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Task 7: rendering and settings integration of shared folders (contract
// §13.15, §14.1–14.2).

const jellyfinManifest = `name: Jellyfin
category: media
instances: multi
auth:
  method: header-auth
  group_access: true
  access_group: users_jellyfin
  admin_group: admin_jellyfin
urls:
  - label: Media
    url: "https://{{HOST_JELLYFIN}}"
settings:
  options:
    - key: movies
      label: Movies
      type: path
      target: {service: jellyfin, mount: /data/movies}
      folder: {access: read, runs_as: {uid: 0, gid: 0}}
      checks:
        - {kind: free_space, min: 1GiB, reason: room for posters}
      applies: restart
    - key: tv
      label: TV
      type: path
      target: {service: jellyfin, mount: /data/tv}
      applies: restart
    - key: puid
      label: User id
      type: int
      default: 1000
      delivery: [{env: PUID}]
    - key: pgid
      label: Group id
      type: int
      default: 1000
      delivery: [{env: PGID}]
    - key: media_gid
      label: Media group
      type: int
      default: 1000
      delivery: [{env: MEDIA_GID}]
    - key: library
      label: Library
      type: path
      target: {service: arr, mount: /data}
      folder: {access: write, runs_as: {uid_env: PUID, gid_env: PGID}, joins_group: gid_env}
      applies: restart
    - key: share
      label: Share
      type: path
      target: {service: samba, mount: /share}
      folder: {access: write, runs_as: {uid: 2000, gid: 0}, joins_group: template, must_own: true}
      applies: restart
`

const jellyfinCompose = "services:\n" +
	"  jellyfin:\n" +
	"    image: jellyfin\n" +
	"    group_add: [\"${MEDIA_GID}\"]\n" +
	"    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.jellyfin.rule: Host(`${PORTCULLIS_HOST_JELLYFIN:-jellyfin.portcullis.local}`)\n" +
	"      traefik.http.routers.jellyfin.entrypoints: websecure\n" +
	"      traefik.http.routers.jellyfin.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"      traefik.http.services.jellyfin.loadbalancer.server.port: \"8096\"\n" +
	"  arr:\n" +
	"    image: arr\n" +
	"    user: \"${PUID:-1000}:${PGID:-1000}\"\n" +
	"  samba:\n" +
	"    image: samba\n"

// jellyfinFixture: the jellyfin template, the fixer's own image found
// and a fake disk with /srv/media (folder media, "Family media", gid
// 60001) and its movies, tv and lib directories.
func jellyfinFixture(t *testing.T) (*fixture, *fakeDisk) {
	t.Helper()
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"jellyfin": {jellyfinManifest, jellyfinCompose}})
	if f.h.Template("jellyfin") == nil {
		t.Fatal("jellyfin fixture not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	fx := f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	d := &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}
	fx.run = d.run
	addFolder(t, f, d, "media", "Family media", "/srv/media", 60001)
	for _, sub := range []string{"movies", "tv", "lib"} {
		d.add("/srv/media/"+sub, "ext4")
	}
	return f, d
}

// addFolder defines folder id at p (on the fake disk) with gid.
func addFolder(t *testing.T, f *fixture, d *fakeDisk, id, name, p string, gid int) {
	t.Helper()
	e := d.add(p, "ext4")
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	if f.h.st.Folders == nil {
		f.h.st.Folders = map[string]state.Folder{}
	}
	f.h.st.Folders[id] = state.Folder{Name: name, Path: p, GID: gid, Dev: e.dev, Ino: e.ino, MountRoot: p}
	f.h.st.FolderGIDs = append(f.h.st.FolderGIDs, gid)
	slices.Sort(f.h.st.FolderGIDs)
}

// setStored stores instance id's values as an assignment would (bypassing
// SaveSettings, which refuses folder values).
func setStored(f *fixture, id string, kv ...any) {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	s := f.h.st.Settings[id].Clone()
	if s.Values == nil {
		s.Values = map[string]any{}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		s.Values[kv[i].(string)] = kv[i+1]
	}
	f.h.st.Settings[id] = s
}

func renderOverride(t *testing.T, f *fixture, id string) (string, error) {
	t.Helper()
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	live := f.h.findLocked(id)
	if live == nil {
		t.Fatalf("no instance %s", id)
	}
	return f.h.renderOverrideLocked(live, f.h.st.Settings[id])
}

func mustRender(t *testing.T, f *fixture, id string) string {
	t.Helper()
	ov, err := renderOverride(t, f, id)
	if err != nil {
		t.Fatalf("render %s: %v", id, err)
	}
	return ov
}

func optionEnv(t *testing.T, f *fixture, id string) map[string]string {
	t.Helper()
	f.h.mu.RLock()
	defer f.h.mu.RUnlock()
	env, err := f.h.optionEnvLocked(f.h.findLocked(id), nil)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// serviceBlock is the override's block of service svc ("" = none).
func serviceBlock(ov, svc string) string {
	i := strings.Index(ov, "\n  "+svc+":\n")
	if i < 0 {
		return ""
	}
	rest := ov[i+len("\n  "+svc+":\n"):]
	for j, line := range strings.SplitAfter(rest, "\n") {
		if !strings.HasPrefix(line, "    ") {
			return strings.Join(strings.SplitAfter(rest, "\n")[:j], "")
		}
	}
	return rest
}

func bindEntry(source, target string, ro bool) string {
	return "      - type: bind\n" +
		"        source: " + yamlQuote(source) + "\n" +
		"        target: " + yamlQuote(target) + "\n" +
		"        read_only: " + map[bool]string{true: "true", false: "false"}[ro] + "\n" +
		"        bind:\n" +
		"          create_host_path: false\n"
}

func TestFolderMountRendered(t *testing.T) {
	f, _ := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies")
	if err := f.h.Enable("jellyfin"); err != nil {
		t.Fatal(err)
	}
	ov := readFile(t, f.h.overridePath("jellyfin"))
	jf := serviceBlock(ov, "jellyfin")
	if !strings.Contains(jf, bindEntry("/srv/media/movies", "/data/movies", true)) {
		t.Errorf("no long-syntax read-only bind:\n%s", ov)
	}
	if !strings.Contains(jf, "    group_add:\n      - \"60001\"\n") {
		t.Errorf("no group_add on jellyfin:\n%s", ov)
	}
	if strings.Contains(ov, "/srv/media/movies:") {
		t.Errorf("short syntax used:\n%s", ov)
	}
	env := envOf(t, f, "jellyfin")
	for _, want := range []string{"PORTCULLIS_FOLDER_GID_MOVIES='60001'\n", "PORTCULLIS_FOLDER_UID_MOVIES=\n",
		"PORTCULLIS_FOLDER_GID_TV=\n", "PORTCULLIS_FOLDER_GID_LIBRARY=\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %q:\n%s", want, env)
		}
	}
	// The up probed the folder root and subpath before Create, right
	// before the up (ruling 24, M1) and again after the start.
	if n := probes(f); n != 6 {
		t.Errorf("probes = %d, want 2 before Create, 2 before the up and 2 after it", n)
	}
	// Unassigned: the variable is written empty, the mount and group go.
	setStored(f, "jellyfin", "movies", nil)
	if err := f.h.RestartApp("jellyfin"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if env := envOf(t, f, "jellyfin"); !strings.Contains(env, "PORTCULLIS_FOLDER_GID_MOVIES=\n") {
		t.Errorf("unassigned env:\n%s", env)
	}
	if ov := readFile(t, f.h.overridePath("jellyfin")); strings.Contains(ov, "60001") {
		t.Errorf("unassigned override:\n%s", ov)
	}
}

func probes(f *fixture) int {
	n := 0
	for _, s := range f.engine.fx().Specs() {
		if fixerMode(s.Cmd) == "probe" {
			n++
		}
	}
	return n
}

// Call 24: access: read is read-only on a custom host path too.
func TestReadAlwaysRO(t *testing.T) {
	f, _ := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "/srv/films")
	ov := mustRender(t, f, "jellyfin")
	if !strings.Contains(ov, `"/srv/films:/data/movies:ro"`) {
		t.Errorf("override:\n%s", ov)
	}
	if strings.Contains(ov, "group_add") {
		t.Errorf("group_add without a folder:\n%s", ov)
	}
}

// Call 3: a template without a folder block is mounted read-only unless
// the admin confirmed write; group_add either way.
func TestUndeclaredTemplateRO(t *testing.T) {
	f, _ := jellyfinFixture(t)
	setStored(f, "jellyfin", "tv", "folder:media/tv")
	ov := mustRender(t, f, "jellyfin")
	jf := serviceBlock(ov, "jellyfin")
	if !strings.Contains(jf, bindEntry("/srv/media/tv", "/data/tv", true)) || !strings.Contains(jf, "      - \"60001\"\n") {
		t.Errorf("unconfirmed:\n%s", ov)
	}
	f.h.mu.Lock()
	fo := f.h.st.Folders["media"]
	fo.WriteConfirmed = map[string]bool{"jellyfin/tv": true}
	f.h.st.Folders["media"] = fo
	f.h.mu.Unlock()
	ov = mustRender(t, f, "jellyfin")
	jf = serviceBlock(ov, "jellyfin")
	if !strings.Contains(jf, bindEntry("/srv/media/tv", "/data/tv", false)) || !strings.Contains(jf, "      - \"60001\"\n") {
		t.Errorf("confirmed:\n%s", ov)
	}
	// Another instance's confirmation counts for nothing here.
	f.h.mu.Lock()
	f.h.st.Folders["media"] = state.Folder{Name: fo.Name, Path: fo.Path, GID: fo.GID, Dev: fo.Dev, Ino: fo.Ino, MountRoot: fo.MountRoot,
		WriteConfirmed: map[string]bool{"jellyfin-b/tv": true}}
	f.h.mu.Unlock()
	if ov := mustRender(t, f, "jellyfin"); !strings.Contains(ov, bindEntry("/srv/media/tv", "/data/tv", true)) {
		t.Errorf("other instance's confirmation:\n%s", ov)
	}
}

func TestFolderReadOnlyRule(t *testing.T) {
	read := &templates.Option{Key: "m", Type: "path", Folder: &templates.FolderSpec{Access: "read"}}
	write := &templates.Option{Key: "m", Type: "path", Folder: &templates.FolderSpec{Access: "write"}}
	plain := &templates.Option{Key: "m", Type: "path"}
	ro := &templates.Option{Key: "m", Type: "path", Mode: "ro"}
	conf := &state.Folder{WriteConfirmed: map[string]bool{"i/m": true}}
	for _, c := range []struct {
		o    *templates.Option
		f    *state.Folder
		want bool
	}{
		{read, conf, true}, {write, &state.Folder{}, false}, {plain, &state.Folder{}, true}, {plain, conf, false}, {ro, conf, true},
	} {
		if got := folderReadOnly(c.o, c.f, "i", "m"); got != c.want {
			t.Errorf("folderReadOnly(%+v, %+v) = %v", c.o, c.f.WriteConfirmed, got)
		}
	}
}

func TestGIDEnvOverride(t *testing.T) {
	f, _ := jellyfinFixture(t)
	setStored(f, "jellyfin", "library", "folder:media/lib")
	env := optionEnv(t, f, "jellyfin")
	if env["PGID"] != "60001" || env["PUID"] != "1000" || env["PORTCULLIS_FOLDER_GID_LIBRARY"] != "60001" {
		t.Errorf("env = %v", env)
	}
	ov := mustRender(t, f, "jellyfin")
	if strings.Contains(serviceBlock(ov, "arr"), "group_add") {
		t.Errorf("group_add with gid_env:\n%s", ov)
	}
	if !strings.Contains(serviceBlock(ov, "arr"), bindEntry("/srv/media/lib", "/data", false)) {
		t.Errorf("writer mount:\n%s", ov)
	}
	// Written once, on every .env writer: an unrelated save keeps it.
	if err := f.h.Enable("jellyfin"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.save("jellyfin", SettingsUpdate{Values: vals("puid", 1001)}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	file := envOf(t, f, "jellyfin")
	if strings.Count(file, "PGID=") != 1 || !strings.Contains(file, "PGID='60001'\n") {
		t.Errorf(".env:\n%s", file)
	}
}

func TestMustOwnUIDVar(t *testing.T) {
	f, d := jellyfinFixture(t)
	addFolder(t, f, d, "share", "Family share", "/srv/share", 60002)
	simulateCompose(f, 0)
	if err := f.h.CreateInstance("jellyfin", "jellyfin-b", nil); err != nil {
		t.Fatal(err)
	}
	setStored(f, "jellyfin", "share", "folder:share")
	setStored(f, "jellyfin-b", "tv", "folder:share")
	if env := optionEnv(t, f, "jellyfin"); env["PORTCULLIS_FOLDER_UID_SHARE"] != "2000" || env["PORTCULLIS_FOLDER_UID_MOVIES"] != "" {
		t.Errorf("jellyfin env = %v", env)
	}
	if env := optionEnv(t, f, "jellyfin-b"); env["PORTCULLIS_FOLDER_UID_TV"] != "2000" || env["PORTCULLIS_FOLDER_GID_TV"] != "60002" {
		t.Errorf("jellyfin-b env = %v", env)
	}
}

func TestTemplateJoinNoGroupAdd(t *testing.T) {
	f, d := jellyfinFixture(t)
	addFolder(t, f, d, "share", "Family share", "/srv/share", 60002)
	setStored(f, "jellyfin", "share", "folder:share")
	if env := optionEnv(t, f, "jellyfin"); env["PORTCULLIS_FOLDER_GID_SHARE"] != "60002" {
		t.Errorf("env = %v", env)
	}
	ov := mustRender(t, f, "jellyfin")
	if sb := serviceBlock(ov, "samba"); strings.Contains(sb, "group_add") || !strings.Contains(sb, bindEntry("/srv/share", "/share", false)) {
		t.Errorf("override:\n%s", ov)
	}
}

func TestPathUsagesFromFolderBlock(t *testing.T) {
	f, _ := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies", "library", "folder:media/lib", "puid", 1234)
	writeFile(t, f.h.userOverridePath("jellyfin"), "services:\n  jellyfin:\n    volumes:\n      - /srv/extra:/extra:ro\n      - {type: bind, source: /mnt/x, target: /x}\n")
	if err := f.h.Enable("jellyfin"); err != nil {
		t.Fatal(err)
	}
	by := map[string]PathUsage{}
	var custom []PathUsage
	for _, u := range f.h.PathUsages() {
		if u.Source == "custom_override" {
			custom = append(custom, u)
			continue
		}
		by[u.Key] = u
	}
	m := by["movies"]
	want := PathUsage{Instance: "jellyfin", Key: "movies", Label: "Movies", Type: "path", HostPath: "/srv/media/movies", Service: "jellyfin",
		Mount: "/data/movies", Mode: "ro", Needs: "read", Access: "read", ReadOnly: true, UID: 0, GID: 0, OwnerKnown: true,
		Folder: "media", Subpath: "movies", JoinsGroup: "group_add", Source: "folder", Declared: true, GIDs: []int{60001},
		Checks: []templates.Check{{Kind: "free_space", Min: "1GiB", Reason: "room for posters"}}}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("movies = %+v\nwant     %+v", m, want)
	}
	l := by["library"]
	if l.UID != 1234 || l.GID != 60001 || !l.OwnerKnown || l.UIDEnv != "PUID" || l.GIDEnv != "PGID" || l.JoinsGroup != "gid_env" ||
		l.Mode != "rw" || !l.Writes || l.ReadOnly || len(l.GIDs) != 0 {
		t.Errorf("library = %+v", l)
	}
	if len(custom) != 2 || custom[0].HostPath != "/srv/extra" || custom[0].Mount != "/extra" || custom[0].Mode != "ro" || custom[0].Service != "jellyfin" ||
		custom[1].HostPath != "/mnt/x" || custom[1].Mode != "rw" {
		t.Errorf("custom = %+v", custom)
	}
}

func TestResolveRunsAs(t *testing.T) {
	opts := []templates.Option{
		{Key: "puid", Type: "int", Delivery: []templates.Delivery{{Env: "PUID"}}},
		{Key: "pgid", Type: "int"},
	}
	o := &templates.Option{Key: "m", Type: "path", Folder: &templates.FolderSpec{Access: "read", RunsAs: &templates.RunsAs{UIDEnv: "PUID", GIDEnv: "PGID"}}}
	uid, gid, err := settings.ResolveRunsAs(o, opts, map[string]settings.Value{"puid": int64(1001), "pgid": int64(1002)})
	if err != nil || uid != 1001 || gid != 1002 {
		t.Errorf("env form = %d %d %v", uid, gid, err)
	}
	o.Folder.RunsAs = &templates.RunsAs{UIDFrom: "person_uid", GID: new(int)}
	if _, _, err := settings.ResolveRunsAs(o, opts, nil); err == nil || !strings.Contains(err.Error(), "project 3") {
		t.Errorf("uid_from = %v", err)
	}
	o.Folder.RunsAs = &templates.RunsAs{UIDEnv: "NOPE", GID: new(int)}
	if _, _, err := settings.ResolveRunsAs(o, opts, nil); err == nil {
		t.Error("unknown env accepted")
	}
}

func TestSaveSettingsRefusesFolderRefs(t *testing.T) {
	f, _ := jellyfinFixture(t)
	ctx := context.Background()
	assign := "assign through Settings → Shared folders"
	for _, u := range []SettingsUpdate{
		{Values: vals("movies", "folder:media")},
		{Values: vals("tv", "folder:media/tv")},
	} {
		if _, err := f.h.SaveSettings("jellyfin", u, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), assign) {
			t.Errorf("save %v = %v", u.Values, err)
		}
		if _, err := f.h.PreviewSettings(ctx, "jellyfin", u); statusOf(err) != 409 || !strings.Contains(err.Error(), assign) {
			t.Errorf("preview %v = %v", u.Values, err)
		}
	}
	setStored(f, "jellyfin", "movies", "folder:media", "library", "folder:media/lib")
	for _, u := range []SettingsUpdate{{Values: vals("movies", "/srv/films")}, {Values: vals("movies", nil)}} {
		if _, err := f.h.SaveSettings("jellyfin", u, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), assign) {
			t.Errorf("replace %s = %v", u.Values["movies"], err)
		}
	}
	set := "set by shared folder Family media (gid 60001)"
	if _, err := f.h.SaveSettings("jellyfin", SettingsUpdate{Values: vals("pgid", 1001)}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), set) {
		t.Errorf("pgid = %v", err)
	}
	if _, err := f.h.PreviewSettings(ctx, "jellyfin", SettingsUpdate{Values: vals("pgid", 1001)}); statusOf(err) != 409 || !strings.Contains(err.Error(), set) {
		t.Errorf("preview pgid = %v", err)
	}
	// Unrelated options save.
	if err := f.h.save("jellyfin", SettingsUpdate{Values: vals("puid", 1001, "tv", "/srv/tv")}); err != nil {
		t.Errorf("unrelated save = %v", err)
	}
	f.h.mu.RLock()
	v := f.h.st.Settings["jellyfin"].Values
	f.h.mu.RUnlock()
	if v["movies"] != "folder:media" || v["library"] != "folder:media/lib" {
		t.Errorf("stored = %v", v)
	}
}

// Ruling 30: no admin-typed value in 60000–60999 for an option a gid
// reference names (runs_as.gid_env, compose group_add ${X}); uid_env is
// not a gid.
func TestSaveSettingsRefusesFolderGIDRange(t *testing.T) {
	f, _ := jellyfinFixture(t)
	reserved := "gid 60000–60999 is reserved for shared folder groups"
	for _, key := range []string{"pgid", "media_gid"} {
		for _, n := range []int{60000, 60999} {
			if _, err := f.h.SaveSettings("jellyfin", SettingsUpdate{Values: vals(key, n)}, "admin"); statusOf(err) != 409 || !strings.Contains(err.Error(), reserved) {
				t.Errorf("save %s=%d = %v", key, n, err)
			}
			if _, err := f.h.PreviewSettings(context.Background(), "jellyfin", SettingsUpdate{Values: vals(key, n)}); statusOf(err) != 409 || !strings.Contains(err.Error(), reserved) {
				t.Errorf("preview %s=%d = %v", key, n, err)
			}
		}
	}
	if err := f.h.save("jellyfin", SettingsUpdate{Values: vals("puid", 60001, "pgid", 61000, "media_gid", 59999)}); err != nil {
		t.Errorf("outside the range / uid = %v", err)
	}
	// At render time a stored value in the range (a restore, an edited
	// state) fails closed: no override, the env variable empty.
	setStored(f, "jellyfin", "media_gid", int64(60005))
	if _, err := renderOverride(t, f, "jellyfin"); statusOf(err) != 409 || !strings.Contains(err.Error(), reserved) {
		t.Errorf("render = %v", err)
	}
	if env := optionEnv(t, f, "jellyfin"); env["MEDIA_GID"] != "" {
		t.Errorf("env MEDIA_GID = %q", env["MEDIA_GID"])
	}
	if err := f.h.Enable("jellyfin"); statusOf(err) != 409 {
		t.Errorf("enable = %v", err)
	}
	// A folder assignment's gid_env value is the folder's: allowed.
	setStored(f, "jellyfin", "media_gid", nil, "library", "folder:media/lib")
	if _, err := renderOverride(t, f, "jellyfin"); err != nil {
		t.Errorf("assigned render = %v", err)
	}
}

// Ruling 24 / R44: the up probes the subpath before and after the start.
func TestUpRefusesChangedFolder(t *testing.T) {
	f, d := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies")
	changed := "shared folder Family media changed on disk: re-apply it"
	d.mu.Lock()
	d.symlinks["/srv/media/movies"] = true
	d.mu.Unlock()
	if err := f.h.Enable("jellyfin"); statusOf(err) != 409 || !strings.Contains(err.Error(), changed) {
		t.Fatalf("symlinked subpath: %v", err)
	}
	if ups(f, "jellyfin") != 0 {
		t.Error("started anyway")
	}
	// The root replaced (another inode).
	d.mu.Lock()
	delete(d.symlinks, "/srv/media/movies")
	d.paths["/srv/media"].ino = 999
	d.mu.Unlock()
	if err := f.h.Enable("jellyfin"); statusOf(err) != 409 || !strings.Contains(err.Error(), changed) {
		t.Fatalf("replaced root: %v", err)
	}
	// A missing subpath fails closed (Docker never creates it).
	f.h.mu.Lock()
	fo := f.h.st.Folders["media"]
	fo.Ino = 999
	f.h.st.Folders["media"] = fo
	f.h.mu.Unlock()
	setStored(f, "jellyfin", "movies", "folder:media/none")
	if err := f.h.Enable("jellyfin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "doesn't exist") {
		t.Fatalf("missing subpath: %v", err)
	}
	if ups(f, "jellyfin") != 0 {
		t.Error("started anyway")
	}
}

func TestUpReprobesAfterStart(t *testing.T) {
	f, d := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies")
	f.runner.upHook = func(string) {
		d.mu.Lock()
		d.symlinks["/srv/media/movies"] = true
		d.mu.Unlock()
	}
	err := f.h.Enable("jellyfin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "shared folder Family media changed on disk: re-apply it") {
		t.Fatalf("enable = %v", err)
	}
	calls := strings.Join(f.runner.Calls(), ",")
	if !strings.Contains(calls, "up:portcullis-jellyfin,down:portcullis-jellyfin") {
		t.Errorf("calls = %s", calls)
	}
	ch := f.h.FolderChanges()
	if len(ch) != 1 || ch[0].Instance != "jellyfin" || ch[0].Folder != "media" || ch[0].Subpath != "movies" || ch[0].Key != "movies" || ch[0].At.IsZero() {
		t.Fatalf("changes = %+v", ch)
	}
	// A clean up clears it.
	f.runner.upHook = nil
	d.mu.Lock()
	delete(d.symlinks, "/srv/media/movies")
	d.mu.Unlock()
	if err := f.h.Enable("jellyfin"); err != nil {
		t.Fatal(err)
	}
	if ch := f.h.FolderChanges(); len(ch) != 0 {
		t.Errorf("after a clean up: %+v", ch)
	}
}

func TestRestoreClearsMissingFolderRefs(t *testing.T) {
	c := &instanceConfig{Settings: &state.InstanceSettings{Values: map[string]any{"movies": "folder:gone", "tv": "folder:media/tv", "library": "/srv/x"},
		Types: map[string]string{"movies": "path", "tv": "path", "library": "path"}}}
	w := dropMissingFolderRefs(c, map[string]state.Folder{"media": {}})
	if !reflect.DeepEqual(w, []string{"setting movies named shared folder gone, which doesn't exist; cleared"}) {
		t.Errorf("warnings = %q", w)
	}
	if _, ok := c.Settings.Values["movies"]; ok || c.Settings.Values["tv"] != "folder:media/tv" || c.Settings.Values["library"] != "/srv/x" {
		t.Errorf("values = %v", c.Settings.Values)
	}
	if _, ok := c.Settings.Types["movies"]; ok {
		t.Errorf("types = %v", c.Settings.Types)
	}

	// Through both restores.
	f, d := jellyfinFixture(t)
	simulateCompose(f, 0)
	addFolder(t, f, d, "gone", "Gone", "/srv/gone", 60002)
	setStored(f, "jellyfin", "movies", "folder:gone", "tv", "folder:media/tv")
	entry, err := f.h.BackupInstance("jellyfin", "root")
	if err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	delete(f.h.st.Folders, "gone")
	f.h.mu.Unlock()
	res, err := f.h.RestoreInstance("jellyfin", entry.Archive, "root")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Warnings, "setting movies named shared folder gone, which doesn't exist; cleared") {
		t.Errorf("warnings = %q", res.Warnings)
	}
	f.h.mu.RLock()
	v := f.h.st.Settings["jellyfin"].Values
	f.h.mu.RUnlock()
	if _, ok := v["movies"]; ok || v["tv"] != "folder:media/tv" {
		t.Errorf("restored values = %v", v)
	}
	res, err = f.h.RestoreInstanceAs(entry.Archive, "jellyfin-c", "root")
	if err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	v = f.h.st.Settings["jellyfin-c"].Values
	f.h.mu.RUnlock()
	if _, ok := v["movies"]; ok || v["tv"] != "folder:media/tv" {
		t.Errorf("restored-as values = %v", v)
	}
	if !slices.Contains(res.Warnings, "instance jellyfin-c now uses shared folder Family media (setting tv, read-only)") {
		t.Errorf("restore-as warnings = %q", res.Warnings)
	}
}

func TestDeleteInstanceDropsAssignments(t *testing.T) {
	f, _ := jellyfinFixture(t)
	simulateCompose(f, 0)
	f.h.SetGroups(&fakeGroups{})
	if err := f.h.CreateInstance("jellyfin", "jellyfin-b", nil); err != nil {
		t.Fatal(err)
	}
	setStored(f, "jellyfin-b", "tv", "folder:media/tv")
	setStored(f, "jellyfin", "tv", "folder:media/tv")
	f.h.mu.Lock()
	fo := f.h.st.Folders["media"]
	fo.WriteConfirmed = map[string]bool{"jellyfin-b/tv": true, "jellyfin/tv": true}
	f.h.st.Folders["media"] = fo
	f.h.mu.Unlock()
	if _, err := f.h.DeleteInstance("jellyfin-b", "jellyfin-b", "root"); err != nil {
		t.Fatal(err)
	}
	for _, u := range f.h.Folders()[0].Uses {
		if u.Instance == "jellyfin-b" {
			t.Errorf("use left: %+v", u)
		}
	}
	f.h.mu.RLock()
	wc := f.h.st.Folders["media"].WriteConfirmed
	f.h.mu.RUnlock()
	if !reflect.DeepEqual(wc, map[string]bool{"jellyfin/tv": true}) {
		t.Errorf("write confirmations = %v", wc)
	}
	st, err := state.Load(filepath.Join(f.data, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.Folders["media"].WriteConfirmed, map[string]bool{"jellyfin/tv": true}) {
		t.Errorf("saved = %v", st.Folders["media"].WriteConfirmed)
	}
}

// H15: a restart refuses a changed subpath before stopping anything.
func TestRestartRefusesChangedFolderStillRunning(t *testing.T) {
	f, d := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies")
	if err := f.h.Enable("jellyfin"); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.symlinks["/srv/media/movies"] = true
	d.mu.Unlock()
	before := strings.Join(f.runner.Calls(), ",")
	err := f.h.RestartApp("jellyfin")
	f.h.Wait()
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "shared folder Family media changed on disk: re-apply it") {
		t.Fatalf("restart = %v", err)
	}
	if after := strings.Join(f.runner.Calls(), ","); after != before {
		t.Errorf("compose ran: %s", strings.TrimPrefix(after, before))
	}
	if ch := f.h.FolderChanges(); len(ch) != 1 || ch[0].Key != "movies" {
		t.Errorf("changes = %+v", ch)
	}
}

// ── fix round 1 ──────────────────────────────────────────

// I1: the post-start mismatch's down falls back to down by name, then
// SIGKILL; a down that fails entirely is a 500 naming the folder, and
// the change is recorded either way.
func TestPostStartDownFallsBack(t *testing.T) {
	f, d := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies")
	swap := func(string) {
		d.mu.Lock()
		d.symlinks["/srv/media/movies"] = true
		d.mu.Unlock()
	}
	f.runner.upHook = swap
	f.runner.downErr = errors.New("compose down failed")
	err := f.h.Enable("jellyfin")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "changed on disk") {
		t.Fatalf("down by name works: %v", err)
	}
	if !strings.Contains(strings.Join(f.runner.Calls(), ","), "downbyname:portcullis-jellyfin") {
		t.Errorf("calls = %v", f.runner.Calls())
	}
	if len(f.h.FolderChanges()) != 1 {
		t.Errorf("changes = %+v", f.h.FolderChanges())
	}

	f.runner.byNameErr = errors.New("down by name failed")
	f.engine.mu.Lock()
	f.engine.containers = []docker.Container{{ID: "c1", State: "running", Labels: map[string]string{docker.LabelProject: "portcullis-jellyfin"}}}
	f.engine.mu.Unlock()
	d.mu.Lock()
	delete(d.symlinks, "/srv/media/movies")
	d.mu.Unlock()
	err = f.h.Enable("jellyfin")
	if statusOf(err) != 500 || !strings.Contains(err.Error(), "may still be running") || !strings.Contains(err.Error(), "Family media") {
		t.Fatalf("nothing works: %v", err)
	}
	if !slices.Contains(f.engine.Kills(), "c1:KILL") {
		t.Errorf("kills = %v", f.engine.Kills())
	}
	if ch := f.h.FolderChanges(); len(ch) != 1 || ch[0].Subpath != "movies" {
		t.Errorf("changes = %+v", ch)
	}
}

// I2: a failed up with folder probes always takes the project down, and
// records a change the after-start probe sees.
func TestFailedUpWithProbesTakesDown(t *testing.T) {
	f, d := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies")
	if err := f.h.Enable("jellyfin"); err != nil {
		t.Fatal(err)
	}
	f.runner.upErr = errors.New("compose up failed")
	n := len(f.runner.Calls())
	f.h.RestartApp("jellyfin")
	f.h.Wait()
	if got := strings.Join(f.runner.Calls()[n:], ","); got != "down:portcullis-jellyfin,up:portcullis-jellyfin,down:portcullis-jellyfin" {
		t.Errorf("failed up: calls = %s", got)
	}
	if len(f.h.FolderChanges()) != 0 {
		t.Errorf("no change, recorded %+v", f.h.FolderChanges())
	}
	f.runner.upHook = func(string) {
		d.mu.Lock()
		d.symlinks["/srv/media/movies"] = true
		d.mu.Unlock()
	}
	n = len(f.runner.Calls())
	err := f.h.RestartApp("jellyfin")
	f.h.Wait()
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "changed on disk") {
		t.Errorf("swapped during a failed up: %v", err)
	}
	if got := strings.Join(f.runner.Calls()[n:], ","); !strings.HasSuffix(got, "up:portcullis-jellyfin,down:portcullis-jellyfin") {
		t.Errorf("calls = %s", got)
	}
	if ch := f.h.FolderChanges(); len(ch) != 1 {
		t.Errorf("changes = %+v", ch)
	}
}

// M1: a refused probe answers before anything is created.
func TestProbeBeforeCreate(t *testing.T) {
	f, d := jellyfinFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies")
	d.mu.Lock()
	d.symlinks["/srv/media/movies"] = true
	d.mu.Unlock()
	if err := f.h.Enable("jellyfin"); statusOf(err) != 409 {
		t.Fatalf("enable = %v", err)
	}
	if c := f.runner.Creates(); len(c) != 0 {
		t.Errorf("created: %v", c)
	}
}

// M2: a successful up clears the record even without probes, and a
// delete clears it.
func TestFolderChangeCleared(t *testing.T) {
	f, d := jellyfinFixture(t)
	simulateCompose(f, 0)
	f.h.SetGroups(&fakeGroups{})
	if err := f.h.CreateInstance("jellyfin", "jellyfin-b", nil); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"jellyfin", "jellyfin-b"} {
		setStored(f, id, "movies", "folder:media/movies")
	}
	d.mu.Lock()
	d.symlinks["/srv/media/movies"] = true
	d.mu.Unlock()
	for _, id := range []string{"jellyfin", "jellyfin-b"} {
		if err := f.h.Enable(id); statusOf(err) != 409 {
			t.Fatalf("enable %s = %v", id, err)
		}
	}
	if len(f.h.FolderChanges()) != 2 {
		t.Fatalf("changes = %+v", f.h.FolderChanges())
	}
	setStored(f, "jellyfin", "movies", "/srv/films")
	if err := f.h.Enable("jellyfin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.DeleteInstance("jellyfin-b", "jellyfin-b", "root"); err != nil {
		t.Fatal(err)
	}
	if ch := f.h.FolderChanges(); len(ch) != 0 {
		t.Errorf("changes = %+v", ch)
	}
}

// I3 (defence): a gid_env variable another service reads is refused at
// render and never carries the folder gid.
func TestGIDEnvLeakRefusedAtRender(t *testing.T) {
	f, _ := jellyfinFixture(t)
	setStored(f, "jellyfin", "library", "folder:media/lib")
	f.h.mu.Lock()
	for i := range f.h.instances {
		if f.h.instances[i].ID == "jellyfin" {
			f.h.instances[i].GIDEnvLeaks = map[string]string{"PGID": "folder.joins_group: gid_env writes the folder gid to PGID, which service samba's group_add also reads"}
		}
	}
	f.h.mu.Unlock()
	if _, err := renderOverride(t, f, "jellyfin"); statusOf(err) != 409 || !strings.Contains(err.Error(), "service samba's group_add also reads") {
		t.Errorf("render = %v", err)
	}
	if env := optionEnv(t, f, "jellyfin"); env["PGID"] == "60001" {
		t.Errorf("env = %v", env)
	}
}

// I4: the custom override can't give a service a folder gid.
func TestOverrideUserFolderGIDRefused(t *testing.T) {
	f, _ := jellyfinFixture(t)
	tm := f.h.Template("jellyfin")
	for _, u := range []string{`"1000:60001"`, `"0:60999"`, `"1000:060000"`} {
		_, err := f.h.parseUserOverride(tm, []byte("services:\n  jellyfin:\n    user: "+u+"\n"))
		if err == nil || !strings.Contains(err.Error(), "gid 60000–60999 is reserved for shared folder groups") {
			t.Errorf("user %s = %v", u, err)
		}
	}
	for _, u := range []string{`"1000:1000"`, `"60001"`, `1000`, `"1000:61000"`} {
		if _, err := f.h.parseUserOverride(tm, []byte("services:\n  jellyfin:\n    user: "+u+"\n")); err != nil {
			t.Errorf("user %s = %v", u, err)
		}
	}
}

// M3: the gid references are computed once, at discovery.
func TestGIDRefsCachedOnTemplate(t *testing.T) {
	f, _ := jellyfinFixture(t)
	tm := f.h.Template("jellyfin")
	if tm.GIDRefs["pgid"] == "" || tm.GIDRefs["media_gid"] == "" || tm.GIDEnvLeaks == nil {
		t.Errorf("refs = %v leaks = %v", tm.GIDRefs, tm.GIDEnvLeaks)
	}
	// Rendering no longer needs compose.yml for them.
	f.h.mu.RLock()
	live := f.h.findLocked("jellyfin")
	f.h.mu.RUnlock()
	if refs := gidRefsOf(&templates.Template{GIDRefs: live.GIDRefs}); refs["pgid"] == "" {
		t.Errorf("cached refs = %v", refs)
	}
}
