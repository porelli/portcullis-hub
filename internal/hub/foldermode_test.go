package hub

import (
	"strings"
	"testing"
)

// An access: read folder block is mounted read-only, on a custom host path
// too (contract §13.15; Option.EffectiveMode), and PathUsages reports it so.
func TestFolderReadMountedReadOnly(t *testing.T) {
	m := strings.Replace(immichManifest, "      mode: ro\n      needs: read\n      writes_as: {uid: puid, gid: 1001}\n",
		"      folder: {access: read, runs_as: {uid_env: IMMICH_UID, gid: 1001}}\n", 1)
	m = strings.Replace(m, "      mode: rw\n      needs: write\n", "      folder: {access: write, runs_as: {uid: 0, gid: 0}}\n", 1)
	if m == immichManifest {
		t.Fatal("fixture not rewritten")
	}
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"immich": {m, immichCompose}})
	if f.h.Template("immich") == nil {
		t.Fatal("fixture not loaded (see the log)")
	}
	people := newFakePeople()
	people.addGroup("users_immich", "alice")
	people.addGroup("admin_immich")
	f.h.SetPeople(people)
	if err := f.h.save("immich", SettingsUpdate{Values: vals("library", "/srv/photos", "uploads", "/srv/up")}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("immich"); err != nil {
		t.Fatal(err)
	}
	ov := readFile(t, f.h.overridePath("immich"))
	if !strings.Contains(ov, `"/srv/photos:/library:ro"`) || strings.Contains(ov, `"/srv/up:/uploads:ro"`) || !strings.Contains(ov, `"/srv/up:/uploads"`) {
		t.Errorf("override:\n%s", ov)
	}
	modes := map[string]string{}
	for _, u := range f.h.PathUsages() {
		modes[u.Key] = u.Mode
	}
	if modes["library"] != "ro" || modes["uploads"] != "rw" {
		t.Errorf("usage modes = %v", modes)
	}
}
