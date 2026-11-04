package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// Task 13: the shared folders, doctor and local networks API (contract
// §14.8).

// folderAppManifest is a header-auth app with a declared folder option
// (library), an undeclared one (extra) and a LAN-only port.
const folderAppManifest = `name: Photos
category: media
instances: multi
auth:
  method: header-auth
  group_access: true
  access_group: users_photos
  admin_group: admin_photos
urls:
  - label: Web
    url: "https://{{HOST_PHOTOS}}"
settings:
  options:
    - key: library
      label: Library
      type: path
      target: {service: server, mount: /library}
      folder: {access: read, runs_as: {uid: 0, gid: 0}}
      applies: restart
    - key: extra
      label: Extra
      type: path
      target: {service: server, mount: /extra}
      applies: restart
ports:
  - key: PHOTOS_SMB
    container: 445
    default: 4450
    service: server
    lan_only: true
`

const folderAppCompose = "services:\n  server:\n    image: photos\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.photos.rule: Host(`${PORTCULLIS_HOST_PHOTOS:-photos.portcullis.local}`)\n" +
	"      traefik.http.routers.photos.entrypoints: websecure\n" +
	"      traefik.http.routers.photos.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"      traefik.http.services.photos.loadbalancer.server.port: \"8080\"\n"

// testFixerImage is a pinned development fixer image (HUB_FIXER_IMAGE).
var testFixerImage = "registry.example.org/hub@sha256:" + strings.Repeat("e", 64)

// noImageEngine can't pull the fixer image: the Hub finds no image.
type noImageEngine struct{ *fakeEngine }

func (noImageEngine) EnsureImage(context.Context, string) error {
	return errors.New("pull access denied")
}

// mediaDev / mediaIno are /srv/media's device and inode on the fake disk.
const mediaDev, mediaIno = 2049, 101

// scriptDisk makes the fixer's probe and scan answer for one directory
// (ino) at mountRoot, the scan with a target plan (every entry changes
// group).
func scriptDisk(e *fakeEngine, ino uint64, mountRoot string) {
	pr, _ := json.Marshal(folderfix.ProbeReport{Version: 1, Mode: "probe", Root: "/broot", Rel: strings.TrimPrefix(mountRoot, "/srv/"),
		Exists: true, Dev: mediaDev, Ino: ino, MountRoot: "/", FSType: "ext4"})
	e.scriptFixer("probe", fakeFixer{Report: string(pr)})
	n := int64(100)
	sc, _ := json.Marshal(folderfix.Report{Version: 1, Mode: "scan", Root: "/folder", Dev: mediaDev, Ino: ino, MountRoot: mountRoot, FSType: "ext4",
		ACL: true, Xattr: true, Entries: n, Files: 90, Dirs: 9, Owners: []folderfix.OwnerCount{{UID: 1000, GID: 1000, N: n}},
		Plan: &folderfix.PlanCounts{Changes: n, Digest: strings.Repeat("ab", 32), ChangeGroup: folderfix.Count{N: n},
			AddSetgid: folderfix.Count{N: 10}, AddDefaultACL: folderfix.Count{N: 10}, KeepGroup: map[int]int64{1000: n}, KeepUser: map[int]int64{}},
		Expected: &folderfix.Conformance{Group: folderfix.Count{N: n}}})
	e.scriptFixer("scan", fakeFixer{Report: string(sc)})
}

// newFolderEnv: the photos app enabled, using shared folder media
// (/srv/media, gid 60001) through its undeclared option extra; the
// fixer's image is found (selfImage) or can't be pulled.
func newFolderEnv(t *testing.T, selfImage bool) *instEnv {
	t.Helper()
	e := newInstEnvOpts(t, t.TempDir(), instEnvOpts{
		extra: map[string][2]string{"photos": {folderAppManifest, folderAppCompose}},
		engine: func(f *fakeEngine) hub.Engine {
			if selfImage {
				return f
			}
			return noImageEngine{f}
		},
		cfg: func(c *hub.Config) { c.FixerImage = testFixerImage },
		seed: func(st *state.AppState) {
			st.Enabled = []string{"photos"}
			st.Folders = map[string]state.Folder{"media": {Name: "Family media", Path: "/srv/media", GID: 60001,
				CreatedAt: time.Now().UTC(), Dev: mediaDev, Ino: mediaIno, MountRoot: "/srv/media"}}
			st.FolderGIDs = []int{60001}
			if st.Settings == nil {
				st.Settings = map[string]state.InstanceSettings{}
			}
			st.Settings["photos"] = state.InstanceSettings{Values: map[string]any{"extra": "folder:media"}}
		},
	})
	if e.s.Hub.Template("photos") == nil {
		t.Fatal("photos template not loaded (see the log)")
	}
	e.s.Hub.SetPeople(e.s.Directory)
	scriptDisk(e.engine, mediaIno, "/srv/media")
	// dana is a delegate (may invite), not an admin.
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/invite", `{"group":"helpers"}`, 200)
	return e
}

type route struct{ method, path, body string }

// folderRoutes are every shared-folder and local-networks route.
var folderRoutes = []route{
	{"GET", "/api/folders", ""},
	{"POST", "/api/folders", `{"id":"docs","name":"Docs","path":"/srv/docs"}`},
	{"PUT", "/api/folders/media", `{"name":"Media","path":"/srv/media","description":""}`},
	{"DELETE", "/api/folders/media", ""},
	{"POST", "/api/folders/check", `{"path":"/srv/docs","create":false}`},
	{"POST", "/api/folders/media/assign/preview", `{"uses":[]}`},
	{"POST", "/api/folders/media/assign/apply", `{"plan_hash":"x","uses":[]}`},
	{"POST", "/api/folders/media/undo/preview", ""},
	{"POST", "/api/folders/media/undo/apply", `{"plan_hash":"x"}`},
	{"POST", "/api/folders/media/recheck/preview", ""},
	{"POST", "/api/folders/media/recheck/apply", `{"plan_hash":"x"}`},
	{"GET", "/api/folders/media/op", ""},
	{"GET", "/api/settings/local-networks", ""},
	{"PUT", "/api/settings/local-networks", `{"networks":null}`},
}

// checkAdminOnly: a delegate with every permission is 403 on each route,
// no X-Forwarded-User 401, and none of them is on the people listener.
func checkAdminOnly(t *testing.T, e *instEnv, routes []route) {
	t.Helper()
	for _, perm := range []string{"invite", "create_users", "manage_members", "edit_details", "reset_passwords"} {
		doAs(t, e.hub, "root", "PUT", "/api/directory/permissions/"+perm, `{"group":"helpers"}`)
	}
	for _, r := range routes {
		if code, b := e.do(t, "dana", r.method, r.path, r.body); code != 403 {
			t.Errorf("delegate %s %s = %d %s, want 403", r.method, r.path, code, b)
		}
		if code, b := e.do(t, "", r.method, r.path, r.body); code != 401 {
			t.Errorf("no user %s %s = %d %s, want 401", r.method, r.path, code, b)
		}
		if resp, _ := doAs(t, e.ppl, "root", r.method, r.path, r.body); resp.StatusCode != 404 && resp.StatusCode != 405 {
			t.Errorf("people %s %s = %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
}

func TestFolderRoutesAdminOnly(t *testing.T) {
	e := newFolderEnv(t, true)
	checkAdminOnly(t, e, folderRoutes)
	if a := e.auditActions(t, "folder."); len(a) != 0 {
		t.Fatalf("refused requests reached the Hub: %v", a)
	}
	if a := e.auditActions(t, "settings.local_networks"); len(a) != 0 {
		t.Fatalf("refused requests reached the Hub: %v", a)
	}
	if fs := e.s.Hub.Folders(); len(fs) != 1 || fs[0].Name != "Family media" {
		t.Fatalf("a refused request changed the folders: %+v", fs)
	}
	// CSRF: a form post is refused before the handler, on every mutating
	// route.
	for _, r := range folderRoutes {
		if r.method == "GET" {
			continue
		}
		req, _ := http.NewRequest(r.method, e.hub.URL+r.path, strings.NewReader(r.body))
		req.Header.Set(ProxySecretHeader, testSecret)
		req.Header.Set("X-Forwarded-User", "root")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("form %s %s = %d, want 415", r.method, r.path, resp.StatusCode)
		}
	}
}

// TestHubListenerRegistersFolderRoutes (ruling 40): every new route is
// registered on the Hub listener exactly once, and never on people.
func TestHubListenerRegistersFolderRoutes(t *testing.T) {
	e := newFolderEnv(t, true)
	want := []string{
		"GET /api/folders", "POST /api/folders", "PUT /api/folders/{id}", "DELETE /api/folders/{id}",
		"POST /api/folders/check", "POST /api/folders/{id}/assign/preview", "POST /api/folders/{id}/assign/apply",
		"POST /api/folders/{id}/undo/preview", "POST /api/folders/{id}/undo/apply", "GET /api/folders/{id}/op",
		"POST /api/folders/{id}/recheck/preview", "POST /api/folders/{id}/recheck/apply",
		"GET /api/doctor", "POST /api/doctor/scan", "GET /api/doctor/op",
		"POST /api/doctor/findings/{fp}/preview", "POST /api/doctor/findings/{fp}/apply",
		"POST /api/doctor/findings/{fp}/mute", "DELETE /api/doctor/findings/{fp}/mute",
		"GET /api/settings/local-networks", "PUT /api/settings/local-networks",
	}
	n := map[string]int{}
	for _, p := range e.s.hubMux().patterns {
		n[p]++
	}
	for _, p := range want {
		if n[p] != 1 {
			t.Errorf("hub listener registers %q %d times, want 1", p, n[p])
		}
	}
	for _, p := range e.s.peopleMux().patterns {
		for _, pre := range []string{"/api/folders", "/api/doctor", "/api/settings"} {
			if strings.Contains(p, pre) {
				t.Errorf("people listener registers %q", p)
			}
		}
	}
}

func TestFolderAPI(t *testing.T) {
	e := newFolderEnv(t, true)
	r, b := doAs(t, e.hub, "root", "GET", "/api/folders", "")
	var list struct {
		Folders []hub.FolderView `json:"folders"`
	}
	json.Unmarshal([]byte(b), &list)
	if r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" || len(list.Folders) != 1 || list.Folders[0].GID != 60001 ||
		len(list.Folders[0].Uses) != 1 || list.Folders[0].Uses[0].Key != "extra" {
		t.Fatalf("list = %d %s", r.StatusCode, b)
	}
	if strings.Contains(b, `"last_apply"`) {
		t.Errorf("a never-applied folder shows a last apply: %s", b)
	}
	if !strings.Contains(b, `"read_only":`) || !strings.Contains(b, `"description":`) {
		t.Errorf("FolderView not snake_case: %s", b)
	}

	// Create /srv/other (its own inode).
	scriptDisk(e.engine, 202, "/srv/other")
	b = mustDo(t, e.hub, "root", "POST", "/api/folders/check", `{"path":"/srv/other","create":false}`, 200)
	var pc hub.PathCheck
	if json.Unmarshal([]byte(b), &pc); !pc.Exists || pc.FSType != "ext4" || pc.Files != 90 {
		t.Errorf("check = %s", b)
	}
	r, b = doAs(t, e.hub, "root", "POST", "/api/folders", `{"id":"other","name":"Other","path":"/srv/other/","description":"d","gid":5000}`)
	var created struct {
		Folder   hub.FolderView `json:"folder"`
		Warnings []string       `json:"warnings"`
	}
	json.Unmarshal([]byte(b), &created)
	if r.StatusCode != 201 || created.Folder.ID != "other" || created.Folder.Path != "/srv/other" || created.Folder.GID != 5000 || !created.Folder.Adopted ||
		len(created.Warnings) == 0 || !strings.Contains(created.Warnings[0], "anything mounted with gid 5000") {
		t.Fatalf("create = %d %s", r.StatusCode, b)
	}
	// Refusals answer {error}: an existing id, a bad id, a path outside
	// the bind roots.
	for _, c := range []struct {
		body string
		code int
	}{
		{`{"id":"other","name":"Again","path":"/srv/again"}`, 409},
		{`{"id":"Bad_ID","name":"Bad","path":"/srv/bad"}`, 400},
		{`{"id":"etc","name":"Etc","path":"/etc/x"}`, 400},
	} {
		r, b := doAs(t, e.hub, "root", "POST", "/api/folders", c.body)
		var eb struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(b), &eb); r.StatusCode != c.code || eb.Error == "" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("create %s = %d %s, want %d {error}", c.body, r.StatusCode, b, c.code)
		}
	}
	b = mustDo(t, e.hub, "root", "PUT", "/api/folders/other", `{"name":"Other things","path":"/srv/other","description":"new"}`, 200)
	var upd struct {
		Folder hub.FolderView `json:"folder"`
	}
	if json.Unmarshal([]byte(b), &upd); upd.Folder.Name != "Other things" || upd.Folder.Description != "new" {
		t.Errorf("update = %s", b)
	}
	mustDo(t, e.hub, "root", "PUT", "/api/folders/nope", `{"name":"x","path":"","description":""}`, 404)
	mustDo(t, e.hub, "root", "PUT", "/api/folders/NOPE", `{"name":"x","path":"","description":""}`, 400)
	// media is used by photos: 409, naming the use.
	if b := mustDo(t, e.hub, "root", "DELETE", "/api/folders/media", "", 409); !strings.Contains(b, "photos") {
		t.Errorf("delete used = %s", b)
	}
	mustDo(t, e.hub, "root", "DELETE", "/api/folders/other", "", 204)
	mustDo(t, e.hub, "root", "DELETE", "/api/folders/other", "", 404)
	got := strings.Join(e.auditActions(t, "folder."), " ")
	for _, w := range []string{"folder.create:ok:root:other", "folder.update:ok:root:other", "folder.delete:ok:root:other", "folder.delete:refused:root:media"} {
		if !strings.Contains(got, w) {
			t.Errorf("audit lacks %s: %s", w, got)
		}
	}
	// Undo without an apply snapshot: 404.
	mustDo(t, e.hub, "root", "POST", "/api/folders/media/undo/preview", "", 404)
	mustDo(t, e.hub, "root", "POST", "/api/folders/media/undo/apply", `{"plan_hash":"x"}`, 404)
	// No operation yet: 404.
	mustDo(t, e.hub, "root", "GET", "/api/folders/media/op", "", 404)
}

func TestFolderBodyRejectsUnknownFields(t *testing.T) {
	e := newFolderEnv(t, true)
	big := `{"path":"` + strings.Repeat("a", 70<<10) + `"}`
	cases := []route{
		{"POST", "/api/folders/check", `{"path": "/srv/x", "owner": 0}`},
		{"POST", "/api/folders/check", `{"path": "/srv/x"} {}`},
		{"POST", "/api/folders/check", big},
		{"POST", "/api/folders/check", `not json`},
		{"POST", "/api/folders", `{"id":"x","name":"X","path":"/srv/x","owner":0}`},
		{"PUT", "/api/folders/media", `{"name":"X","path":"/srv/media","gid":5}`},
		{"POST", "/api/folders/media/assign/preview", `{"uses":[{"instance":"photos","key":"extra","mode":"rw"}]}`},
		{"POST", "/api/folders/media/assign/preview", `{}`},
		{"POST", "/api/folders/media/assign/apply", `{"plan_hash":"x"}`},
		{"POST", "/api/folders/media/assign/apply", `{"plan_hash":"x","uses":[],"force":true}`},
		{"POST", "/api/folders/media/undo/apply", `{"plan_hash":"x","uses":[]}`},
		{"POST", "/api/folders/media/recheck/apply", `{}`},
		{"POST", "/api/folders/media/recheck/apply", `{"plan_hash":"x","dev":1}`},
		{"PUT", "/api/settings/local-networks", `{"networks":[],"extra":1}`},
		{"PUT", "/api/settings/local-networks", `{}`},
	}
	for _, c := range cases {
		code, b := e.do(t, "root", c.method, c.path, c.body)
		if code != 400 {
			t.Errorf("%s %s %.60s = %d %s, want 400", c.method, c.path, c.body, code, b)
			continue
		}
		// A fixed usage message: never the decoder's error.
		for _, leak := range []string{"unknown field", "owner", "invalid character", "http: request body too large", "aaaa"} {
			if strings.Contains(b, leak) {
				t.Errorf("%s %s answer echoes %q: %s", c.method, c.path, leak, b)
			}
		}
	}
	if a := e.auditActions(t, "folder."); len(a) != 0 {
		t.Fatalf("refused bodies reached the Hub: %v", a)
	}
}

// waitOp polls path until the op record with opID is no longer running.
func waitOp(t *testing.T, e *instEnv, path, opID string) hub.OpRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, b := e.do(t, "root", "GET", path, "")
		var rec hub.OpRecord
		json.Unmarshal([]byte(b), &rec)
		if code == 200 && rec.OpID == opID && !rec.Running {
			return rec
		}
		if time.Now().After(deadline) {
			t.Fatalf("op %s at %s never finished: %d %s", opID, path, code, b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAssignApplyAnswers202(t *testing.T) {
	e := newFolderEnv(t, true)
	uses := `"uses":[{"instance":"photos","key":"extra"},{"instance":"photos","key":"library"}]`
	b := mustDo(t, e.hub, "root", "POST", "/api/folders/media/assign/preview", "{"+uses+"}", 200)
	var plan hub.AssignPlan
	json.Unmarshal([]byte(b), &plan)
	if plan.Hash == "" || plan.Folder != "media" || plan.Disk == nil || len(plan.Uses) != 2 {
		t.Fatalf("preview = %s", b)
	}
	// A hash mismatch: 409 {error}, no operation.
	r, b := doAs(t, e.hub, "root", "POST", "/api/folders/media/assign/apply", `{"plan_hash":"`+strings.Repeat("0", 64)+`",`+uses+`}`)
	var eb struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(b), &eb); r.StatusCode != 409 || !strings.Contains(eb.Error, "the setup changed since the preview") {
		t.Fatalf("mismatch = %d %s", r.StatusCode, b)
	}
	// The apply holds the folder while its snapshot runs.
	gate, entered := make(chan struct{}), make(chan struct{}, 1)
	e.engine.gateFixer("snapshot", gate, entered)
	r, b = doAs(t, e.hub, "root", "POST", "/api/folders/media/assign/apply", `{"plan_hash":"`+plan.Hash+`",`+uses+`}`)
	var acc map[string]string
	json.Unmarshal([]byte(b), &acc)
	if r.StatusCode != 202 || acc["op_id"] == "" || acc["op"] != hub.OpFolderAssign || acc["folder"] != "media" ||
		acc["instance"] != "_folder.media" || acc["poll"] != "/api/folders/media/op" {
		close(gate)
		t.Fatalf("apply = %d %s", r.StatusCode, b)
	}
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(gate)
		t.Fatal("the snapshot never ran")
	}
	// Busy: 409 {error}.
	r, b = doAs(t, e.hub, "root", "POST", "/api/folders/media/assign/apply", `{"plan_hash":"`+plan.Hash+`",`+uses+`}`)
	eb.Error = ""
	if json.Unmarshal([]byte(b), &eb); r.StatusCode != 409 || eb.Error == "" {
		t.Errorf("busy = %d %s", r.StatusCode, b)
	}
	b = mustDo(t, e.hub, "root", "GET", "/api/folders/media/op", "", 200)
	var rec hub.OpRecord
	if json.Unmarshal([]byte(b), &rec); !rec.Running || rec.OpID != acc["op_id"] || rec.Op != hub.OpFolderAssign {
		t.Errorf("op while running = %s", b)
	}
	close(gate)
	rec = waitOp(t, e, "/api/folders/media/op", acc["op_id"])
	if rec.Op != hub.OpFolderAssign {
		t.Errorf("op = %+v", rec)
	}
	// The poll answer is an op record: snake_case, never a secret.
	if code, b := e.do(t, "root", "GET", "/api/folders/media/op", ""); code != 200 || !strings.Contains(b, `"op_id":`) {
		t.Errorf("poll = %d %s", code, b)
	}
}

// TestStatusMeanings: the Hub's 503 (no self image) and 507 (no space)
// reach the client with their status and an {error}.
func TestStatusMeanings(t *testing.T) {
	e := newFolderEnv(t, false)
	for _, c := range []route{
		{"POST", "/api/folders/check", `{"path":"/srv/other","create":false}`},
		{"POST", "/api/folders", `{"id":"other","name":"Other","path":"/srv/other"}`},
		{"POST", "/api/folders/media/assign/preview", `{"uses":[{"instance":"photos","key":"extra"},{"instance":"photos","key":"library"}]}`},
	} {
		r, b := doAs(t, e.hub, "root", c.method, c.path, c.body)
		var eb struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(b), &eb); r.StatusCode != 503 || !strings.Contains(eb.Error, "can't find its own image") {
			t.Errorf("%s %s = %d %s, want 503 no image", c.method, c.path, r.StatusCode, b)
		}
	}
	for _, c := range []struct {
		err  error
		code int
	}{
		{&hub.StatusError{Status: 507, Err: errors.New("not enough free space on the Hub's data volume")}, 507},
		{&hub.StatusError{Status: 503, Err: errors.New("the Hub can't find its own image: x")}, 503},
		{&hub.StatusError{Status: 409, Err: hub.ErrBusy{ID: "shared folder media"}}, 409},
		{hub.ErrBusy{ID: "photos"}, 409},
		{hub.ErrNotFound, 404},
		{errors.New("boom"), 500},
	} {
		w := httptest.NewRecorder()
		writeAPIErr(w, c.err)
		var eb struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(w.Body.Bytes(), &eb); w.Code != c.code || eb.Error == "" {
			t.Errorf("%v = %d %s, want %d", c.err, w.Code, w.Body.String(), c.code)
		}
	}
	// A failed operation's record keeps its status for the poll.
	w := httptest.NewRecorder()
	writeAPIErr(w, &hub.OpError{Record: hub.OpRecord{Op: hub.OpFolderAssign, Error: "not enough free space", Status: 507}, Err: &hub.StatusError{Status: 507, Err: errors.New("x")}})
	if w.Code != 507 || !strings.Contains(w.Body.String(), `"op":"folder_assign"`) {
		t.Errorf("op error = %d %s", w.Code, w.Body.String())
	}
}

func TestLocalNetworksAPI(t *testing.T) {
	e := newFolderEnv(t, true)
	type view struct {
		Networks []string `json:"networks"`
		Default  bool     `json:"default"`
	}
	var v view
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/settings/local-networks", "", 200)), &v)
	if !v.Default || strings.Join(v.Networks, ",") != strings.Join(hub.DefaultLocalNetworks, ",") {
		t.Fatalf("defaults = %+v", v)
	}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "PUT", "/api/settings/local-networks", `{"networks":["192.168.1.0/24"]}`, 200)), &v)
	if v.Default || strings.Join(v.Networks, ",") != "192.168.1.0/24" {
		t.Fatalf("saved = %+v", v)
	}
	v = view{}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "PUT", "/api/settings/local-networks", `{"networks":[]}`, 200)), &v)
	if v.Default || v.Networks == nil || len(v.Networks) != 0 {
		t.Fatalf("loopback only = %+v", v)
	}
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "PUT", "/api/settings/local-networks", `{"networks":null}`, 200)), &v)
	if !v.Default || len(v.Networks) != len(hub.DefaultLocalNetworks) {
		t.Fatalf("back to defaults = %+v", v)
	}
	r, b := doAs(t, e.hub, "root", "PUT", "/api/settings/local-networks", `{"networks":["0.0.0.0/0"]}`)
	if r.StatusCode != 400 || !strings.Contains(b, `"error":`) {
		t.Errorf("/0 = %d %s", r.StatusCode, b)
	}
	got := strings.Join(e.auditActions(t, "settings.local_networks"), " ")
	if strings.Count(got, ":ok:root:") != 3 || !strings.Contains(got, ":refused:root:") {
		t.Errorf("audit = %s", got)
	}
}

// gateFixer blocks every later run of mode until gate closes; entered
// receives once per run that started.
func (e *fakeEngine) gateFixer(mode string, gate chan struct{}, entered chan struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fixerGates == nil {
		e.fixerGates = map[string][2]chan struct{}{}
	}
	e.fixerGates[mode] = [2]chan struct{}{gate, entered}
}

// H2: Re-check identity through the API: preview (nothing stored), apply
// with its plan_hash (a stale one 409), audited folder.update.
func TestFolderRecheckRoutes(t *testing.T) {
	e := newFolderEnv(t, true)
	b := mustDo(t, e.hub, "root", "POST", "/api/folders/media/recheck/preview", "", 200)
	var chk hub.IdentityCheck
	if err := json.Unmarshal([]byte(b), &chk); err != nil || chk.Folder != "media" || len(chk.Hash) != 64 || len(chk.Lines) == 0 || chk.New.Dev == 0 {
		t.Fatalf("preview = %s %v", b, err)
	}
	mustDo(t, e.hub, "root", "POST", "/api/folders/media/recheck/apply", `{"plan_hash":"`+strings.Repeat("0", 64)+`"}`, 409)
	b = mustDo(t, e.hub, "root", "POST", "/api/folders/media/recheck/apply", `{"plan_hash":"`+chk.Hash+`"}`, 200)
	if !strings.Contains(b, `"folder":{`) {
		t.Errorf("apply = %s", b)
	}
	mustDo(t, e.hub, "root", "POST", "/api/folders/nope/recheck/preview", "", 404)
	if got := strings.Join(e.auditActions(t, "folder.update"), " "); !strings.Contains(got, "folder.update:ok:root:media") {
		t.Errorf("audit = %s", got)
	}
}
