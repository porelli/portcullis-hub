package agent

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// canRead is POSIX read access on st for uid with groups (no capability):
// the owner bits for the owner, the group bits for a member of the
// file's group, the other bits otherwise.
func canRead(st os.FileInfo, uid int, groups []int, dir bool) bool {
	s := st.Sys().(*syscall.Stat_t)
	bit := os.FileMode(0o4)
	if dir {
		bit = 0o5 // read + search
	}
	perm := st.Mode().Perm()
	switch {
	case uid == int(s.Uid):
		return (perm>>6)&bit == bit
	case slices.Contains(groups, int(s.Gid)):
		return (perm>>3)&bit == bit
	}
	return perm&bit == bit
}

// TestAppfilesGroup (the primary's §13.7 layout, file by file): on a
// worker the instance's appfiles directories are 0750 and its data files
// 0640, all in the appfiles group (the Hub's 10001 in production); a
// secrets file keeps the primary's 0600. A uid other than the agent's,
// with the group (an app's group_add), reads the data file and enters its
// directories; one without the group reads neither; nobody but the owner
// reads the secrets file.
func TestAppfilesGroup(t *testing.T) {
	f := newAPI(t)
	// A supplementary group of this process other than its primary one (the
	// agent's 10001 in production): a file it creates gets it only by the
	// chgrp this checks.
	gid := -1
	gs, _ := os.Getgroups()
	for _, g := range gs {
		if g != os.Getgid() {
			gid = g
			break
		}
	}
	if gid < 0 {
		t.Skip("this process has no supplementary group to chgrp to")
	}
	f.api.cfg.AppfilesGID = gid
	b := bundleTar(t, "app", map[string]string{"data": "portcullis-app_data"}, []bundleFile{
		{name: BundleCompose, data: testCompose},
		{name: BundleEnv, data: "A=1\n", mode: 0o600},
		{name: "templates/app/app.conf", data: "x=1\n"},
		{name: "appfiles/people/people.json", data: `{"alice":1}`, mode: 0o640},
		{name: "appfiles/people/people.secrets.json", data: `{"t":"s"}`, mode: 0o600},
	})
	if c := f.code(t, "PUT", "/v1/projects/app/bundle", b); c != 204 {
		t.Fatalf("bundle: %d", c)
	}
	// A later delivery (PUT /v1/projects/{id}/appfiles/{name}) the same way.
	if c := f.code(t, "PUT", "/v1/projects/app/appfiles/settings", appFileTar(t, map[string]string{"settings.json": "{}"})); c != 204 {
		t.Fatalf("appfile: %d", c)
	}
	app := 4242                 // an app's uid: not the agent's
	paths := map[string][2]any{ // path → {mode, is dir}
		filepath.Join(f.data, "appfiles"):                                        {os.FileMode(0o750), true},
		f.api.appfilesDir("app"):                                                 {os.FileMode(0o750), true},
		filepath.Join(f.api.appfilesDir("app"), "people"):                        {os.FileMode(0o750), true},
		filepath.Join(f.api.appfilesDir("app"), "people", "people.json"):         {os.FileMode(0o640), false},
		filepath.Join(f.api.appfilesDir("app"), "people", "people.secrets.json"): {os.FileMode(0o600), false},
		filepath.Join(f.api.appfilesDir("app"), "settings", "settings.json"):     {os.FileMode(0o640), false},
	}
	for p, w := range paths {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != w[0].(os.FileMode) || int(st.Sys().(*syscall.Stat_t).Gid) != gid {
			t.Errorf("%s: %o group %d, want %o group %d", p, st.Mode().Perm(), st.Sys().(*syscall.Stat_t).Gid, w[0], gid)
		}
		secret := filepath.Base(p) == "people.secrets.json"
		if got := canRead(st, app, []int{gid}, w[1].(bool)); got == secret {
			t.Errorf("%s: an app with the group reads it = %v", p, got)
		}
		if canRead(st, app, []int{gid + 1}, w[1].(bool)) {
			t.Errorf("%s: an app without the group reads it", p)
		}
	}
}
