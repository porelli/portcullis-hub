package hub

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Task 9: the doctor's inputs, mutes and the folder_changed record
// (contract §14.5).

// doctorFixture: jellyfin (shared folder media, gid 60001, on a fake
// disk) and tmfixture (per-person size_limit) side by side, a fake
// directory (alice, bob, carol in users_tmfixture; alice in tm_small;
// nobody with access in tm_empty).
func doctorFixture(t *testing.T) (*fixture, *fakePeople, *fakeAudit) {
	t.Helper()
	tm := mustRead(t, filepath.Join("testdata", "settings", "tmfixture", "manifest.yaml"))
	tc := mustRead(t, filepath.Join("testdata", "settings", "tmfixture", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{
		"jellyfin": {jellyfinManifest, jellyfinCompose},
		tmID:       {string(tm), string(tc)},
	})
	if f.h.Template("jellyfin") == nil || f.h.Template(tmID) == nil {
		t.Fatal("fixture templates not loaded (see the log)")
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	fx := f.engine.fx()
	fx.inspect = map[string]docker.ContainerInfo{testSelfID: {ID: testSelfID, Image: testSelfImage, Labels: selfLabels}}
	f.h.mountinfo = func() ([]byte, error) { return []byte(testMountinfo), nil }
	d := &fakeDisk{paths: map[string]*diskPath{}, symlinks: map[string]bool{}}
	fx.run = d.run
	addFolder(t, f, d, "media", "Family media", "/srv/media", 60001)
	people := newFakePeople("erin")
	people.addGroup("users_tmfixture", "alice", "bob", "carol")
	people.addGroup("tm_small", "alice")
	people.addGroup("tm_empty", "erin")
	f.h.SetPeople(people)
	return f, people, audit
}

// enableQuiet marks ids enabled in state (no compose run).
func enableQuiet(f *fixture, ids ...string) {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	for _, id := range ids {
		f.h.st.SetEnabled(id, true)
	}
}

func TestDoctorInputsGather(t *testing.T) {
	f, people, _ := doctorFixture(t)
	setStored(f, "jellyfin", "movies", "folder:media/movies", "tv", "/srv/tv")
	writeFile(t, f.h.userOverridePath("jellyfin"), "services:\n  jellyfin:\n    volumes:\n      - /srv/media:/extra:ro\n")
	small, empty := people.groups["tm_small"], people.groups["tm_empty"]
	f.h.mu.Lock()
	s := f.h.st.Settings[tmID].Clone()
	s.Person = map[string]state.PersonSetting{"size_limit": {Default: int64(1 << 30), Rows: []state.GroupValue{
		{Group: "tm_small", GroupID: small, Value: int64(10 << 30)},
		{Group: "tm_empty", GroupID: empty, Value: int64(20 << 30)},
		{Group: "tm_gone", GroupID: 999, Value: int64(30 << 30)},
		{Group: "{{ACCESS_GROUP}}", GroupID: 0, Value: int64(1 << 30)}, // unbound: left out
	}}}
	f.h.st.Settings[tmID] = s
	f.h.mu.Unlock()
	enableQuiet(f, "jellyfin", tmID)

	in, err := f.h.doctorInputs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in.BindRoots, []string{"/srv", "/mnt", "/media"}) {
		t.Errorf("bind roots = %v", in.BindRoots)
	}
	movies := doctor.PathIn{Instance: "jellyfin", Key: "movies", Label: "Movies", HostPath: "/srv/media/movies", Service: "jellyfin",
		Mount: "/data/movies", Access: "read", Source: "folder", Folder: "media", Subpath: "movies", JoinsGroup: "group_add",
		GIDs: []int{60001}, OwnerKnown: true, ReadOnly: true, Declared: true,
		Checks: []templates.Check{{Kind: "free_space", Min: "1GiB", Reason: "room for posters"}}}
	tv := doctor.PathIn{Instance: "jellyfin", Key: "tv", Label: "TV", HostPath: "/srv/tv", Service: "jellyfin", Mount: "/data/tv",
		Access: "write", Source: "setting", Writes: true, GIDs: []int{60001}}
	extra := doctor.PathIn{Instance: "jellyfin", HostPath: "/srv/media", Service: "jellyfin", Mount: "/extra", Source: "custom_override", ReadOnly: true}
	if want := []doctor.PathIn{movies, tv, extra}; !reflect.DeepEqual(in.Paths, want) {
		t.Errorf("paths = %+v\nwant    %+v", in.Paths, want)
	}
	if len(in.Folders) != 1 {
		t.Fatalf("folders = %+v", in.Folders)
	}
	if fo := in.Folders[0]; fo.ID != "media" || fo.Name != "Family media" || fo.Path != "/srv/media" || fo.GID != 60001 ||
		!reflect.DeepEqual(fo.Uses, []doctor.PathIn{movies}) || fo.LastApply != nil {
		t.Errorf("folder = %+v", fo)
	}
	want := []doctor.PersonIn{{Instance: tmID, Key: "size_limit", Label: "Backup size limit", DefaultDisplay: "1 GiB", Rows: []doctor.RowIn{
		{Group: "tm_small", GroupID: small, Exists: true, Members: 1},
		{Group: "tm_empty", GroupID: empty, Exists: true, Members: 0},
		{Group: "tm_gone", GroupID: 999, Exists: false, Members: 0},
	}}}
	if !reflect.DeepEqual(in.Person, want) {
		t.Errorf("person = %+v\nwant     %+v", in.Person, want)
	}

	// The report: the shared_path / custom-override mount / person
	// findings of these inputs.
	r, err := f.h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, fd := range r.Findings {
		kinds[fd.Kind]++
	}
	if kinds["custom_override_mount"] != 1 || kinds["person_option"] != 2 {
		t.Errorf("kinds = %v (%+v)", kinds, r.Findings)
	}

	// The directory down: rows aren't judged by membership.
	f.h.SetPeople(nil)
	in, _ = f.h.doctorInputs(context.Background())
	for _, r := range in.Person[0].Rows {
		if r.Members != -1 || !r.Exists {
			t.Errorf("without a directory: %+v", r)
		}
	}
}

// Every PathIn field comes from the same-named PathUsage field (P12).
func TestPathInCopiesEveryField(t *testing.T) {
	var u PathUsage
	v := reflect.ValueOf(&u).Elem()
	for i := 0; i < v.NumField(); i++ {
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString("s-" + v.Type().Field(i).Name)
		case reflect.Int:
			fv.SetInt(int64(i + 1))
		case reflect.Bool:
			fv.SetBool(true)
		case reflect.Slice:
			if fv.Type().Elem().Kind() == reflect.Int {
				fv.Set(reflect.ValueOf([]int{i}))
			} else {
				fv.Set(reflect.ValueOf([]templates.Check{{Kind: "exclusive"}}))
			}
		default:
			t.Fatalf("PathUsage.%s: unhandled kind %s", v.Type().Field(i).Name, fv.Kind())
		}
	}
	p := pathIn(u)
	pv := reflect.ValueOf(p)
	for i := 0; i < pv.NumField(); i++ {
		name := pv.Type().Field(i).Name
		src := v.FieldByName(name)
		if !src.IsValid() {
			t.Errorf("PathIn.%s has no PathUsage field", name)
			continue
		}
		if !reflect.DeepEqual(pv.Field(i).Interface(), src.Interface()) {
			t.Errorf("PathIn.%s = %v, want %v", name, pv.Field(i).Interface(), src.Interface())
		}
	}
	// Left out on purpose: the option's type, the mount mode (ReadOnly
	// says it) and needs (Access says it).
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if _, ok := pv.Type().FieldByName(name); !ok && name != "Type" && name != "Mode" && name != "Needs" {
			t.Errorf("PathUsage.%s isn't copied", name)
		}
	}
}

func TestMuteAudited(t *testing.T) {
	f, _, audit := doctorFixture(t)
	setStored(f, "jellyfin", "tv", "/srv/media")
	writeFile(t, f.h.userOverridePath("jellyfin"), "services:\n  jellyfin:\n    volumes:\n      - /srv/media:/extra:ro\n")
	enableQuiet(f, "jellyfin")
	ctx := context.Background()
	r, err := f.h.Doctor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fp string
	for _, fd := range r.Findings {
		if fd.Kind == "custom_override_mount" {
			fp = fd.FP
		}
	}
	if fp == "" {
		t.Fatalf("no custom_override_mount finding: %+v", r.Findings)
	}
	before := r.Counts[doctor.Warning]

	if err := f.h.MuteFinding(ctx, fp, "  ", "root"); statusOf(err) != 400 {
		t.Errorf("empty reason = %v", err)
	}
	if err := f.h.MuteFinding(ctx, fp, strings.Repeat("x", 201), "root"); statusOf(err) != 400 {
		t.Errorf("long reason = %v", err)
	}
	if err := f.h.MuteFinding(ctx, "0123456789abcdef", "known", "root"); statusOf(err) != 404 {
		t.Errorf("unknown fp = %v", err)
	}
	reason := strings.Repeat("é", 200)
	if err := f.h.MuteFinding(ctx, fp, reason, "root"); err != nil {
		t.Fatal(err)
	}
	e := audit.last()
	if e.Action != "doctor.mute" || e.Target != fp || e.Actor != "root" || e.Result != "ok" || e.Detail != reason ||
		utf8.RuneCountInString(e.Detail) > 200 {
		t.Errorf("audit = %+v", e)
	}
	r, _ = f.h.Doctor(ctx)
	if r.Muted != 1 || r.Counts[doctor.Warning] != before-1 {
		t.Errorf("after mute: muted %d, counts %v", r.Muted, r.Counts)
	}
	// The mute survives a Hub restart.
	h2 := reopen(t, f)
	if m := h2.st.DoctorMutes[fp]; m.Reason != reason || m.Actor != "root" || m.Inputs == "" || m.At.IsZero() {
		t.Errorf("after restart: mute %+v", m)
	}
	// Inputs change (the override mounts it rw now): the finding is back.
	writeFile(t, f.h.userOverridePath("jellyfin"), "services:\n  jellyfin:\n    volumes:\n      - /srv/media:/extra\n")
	if r, _ = f.h.Doctor(ctx); r.Muted != 0 {
		t.Errorf("changed inputs: muted %d", r.Muted)
	}

	if err := f.h.UnmuteFinding(fp, "root"); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "doctor.unmute" || e.Target != fp || e.Result != "ok" {
		t.Errorf("audit = %+v", e)
	}
	if err := f.h.UnmuteFinding(fp, "root"); statusOf(err) != 404 {
		t.Errorf("unmute again = %v", err)
	}
	f.h.mu.RLock()
	n := len(f.h.st.DoctorMutes)
	f.h.mu.RUnlock()
	if n != 0 {
		t.Errorf("mutes left: %d", n)
	}
}

// folder_changed survives a Hub restart and is the doctor's Problem.
func TestFolderChangedPersisted(t *testing.T) {
	f, d := jellyfinFixture(t)
	simulateCompose(f, 0)
	f.h.SetPeople(newFakePeople())
	setStored(f, "jellyfin", "movies", "folder:media/movies")
	d.mu.Lock()
	d.symlinks["/srv/media/movies"] = true
	d.mu.Unlock()
	if err := f.h.Enable("jellyfin"); statusOf(err) != 409 {
		t.Fatalf("enable = %v", err)
	}
	h2 := reopen(t, f)
	h2.SetPeople(newFakePeople())
	if ch := h2.FolderChanges(); len(ch) != 1 || ch[0].Instance != "jellyfin" || ch[0].Folder != "media" {
		t.Fatalf("after restart: %+v", ch)
	}
	r, err := h2.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, fd := range r.Findings {
		if fd.Kind == "folder_changed" && fd.Severity == doctor.Problem && fd.Class == doctor.FixExplain {
			found = true
		}
	}
	if !found {
		t.Errorf("no folder_changed Problem: %+v", r.Findings)
	}
}

func TestDoctorNeedsDirectory(t *testing.T) {
	f, _, _ := doctorFixture(t)
	f.h.SetPeople(nil)
	if _, err := f.h.Doctor(context.Background()); statusOf(err) != 503 {
		t.Errorf("doctor without users & groups = %v", err)
	}
}
