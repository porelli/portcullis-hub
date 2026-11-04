package doctor

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

var roots = []string{"/srv", "/mnt", "/media"}

func setting(inst, key, host string, writes bool) PathIn {
	access := "read"
	if writes {
		access = "write"
	}
	return PathIn{Instance: inst, Key: key, Label: strings.ToUpper(key[:1]) + key[1:], HostPath: host, Service: inst, Mount: "/" + key,
		Access: access, Source: "setting", Writes: writes, ReadOnly: !writes}
}

func custom(inst, host string) PathIn {
	return PathIn{Instance: inst, HostPath: host, Service: inst, Mount: "/x", Source: "custom_override", Writes: true, Access: "write"}
}

func folderUse(inst, key, folder, host string, writes, declared bool) PathIn {
	u := setting(inst, key, host, writes)
	u.Source, u.Folder, u.Declared = "folder", folder, declared
	return u
}

// of runs the one check of kind on in.
func of(t *testing.T, kind string, in *Inputs) []Finding {
	t.Helper()
	in.BindRoots = roots
	var out []Finding
	for _, c := range checks() {
		if c.Kind() == kind {
			out = append(out, c.Run(in)...)
		}
	}
	for _, f := range out {
		if f.FP == "" || f.Kind != kind || f.Title == "" || f.Why == "" || f.Inputs == "" {
			t.Errorf("incomplete finding %+v", f)
		}
	}
	return out
}

func TestSharedPathSameAndNested(t *testing.T) {
	same := of(t, "shared_path", &Inputs{Paths: []PathIn{
		setting("jellyfin", "media", "/srv/media", false),
		setting("samba", "share", "/srv/media", true),
	}})
	if len(same) != 1 {
		t.Fatalf("same = %+v", same)
	}
	f := same[0]
	if f.Severity != Warning || f.Class != FixOneClick || f.FixKind != "manage_as_folder" {
		t.Errorf("same path = %+v", f)
	}
	if !strings.HasPrefix(f.Title, "jellyfin and samba both use `/srv/media`.") {
		t.Errorf("title = %q", f.Title)
	}
	if strings.Join(f.Instances, ",") != "jellyfin,samba" || strings.Join(f.Paths, ",") != "/srv/media" {
		t.Errorf("subjects = %v %v", f.Instances, f.Paths)
	}

	nested := of(t, "shared_path", &Inputs{Paths: []PathIn{
		setting("jellyfin", "media", "/srv/media", false),
		setting("sonarr", "tv", "/srv/media/tv", true),
	}})
	if len(nested) != 1 || nested[0].Severity != Warning || nested[0].Class != FixExplain || nested[0].FixKind != "" || len(nested[0].Steps) == 0 {
		t.Fatalf("nested = %+v", nested)
	}
	if strings.Join(nested[0].Paths, ",") != "/srv/media,/srv/media/tv" {
		t.Errorf("paths = %v", nested[0].Paths)
	}

	withCustom := of(t, "shared_path", &Inputs{Paths: []PathIn{
		setting("jellyfin", "media", "/srv/media", false),
		custom("samba", "/srv/media"),
	}})
	if len(withCustom) != 1 || withCustom[0].Class != FixExplain {
		t.Fatalf("with a custom override mount = %+v", withCustom)
	}

	// Outside the bind roots: not one-click either.
	outside := of(t, "shared_path", &Inputs{Paths: []PathIn{
		setting("jellyfin", "media", "/data/media", false),
		setting("samba", "share", "/data/media", true),
	}})
	if len(outside) != 1 || outside[0].Class != FixExplain {
		t.Fatalf("outside = %+v", outside)
	}

	// Folder uses and unrelated paths are no shared_path.
	none := of(t, "shared_path", &Inputs{Paths: []PathIn{
		folderUse("jellyfin", "media", "media", "/srv/media", false, true),
		folderUse("samba", "share", "media", "/srv/media", true, true),
		setting("a", "x", "/srv/media2", true),
		setting("b", "y", "/srv/other", true),
	}})
	if len(none) != 0 {
		t.Fatalf("none = %+v", none)
	}
	// The fingerprint doesn't depend on the order of the uses.
	again := of(t, "shared_path", &Inputs{Paths: []PathIn{
		setting("samba", "share", "/srv/media", true),
		setting("jellyfin", "media", "/srv/media", false),
	}})
	if again[0].FP != f.FP || again[0].Inputs != f.Inputs {
		t.Error("fingerprint or digest depends on order")
	}
}

func TestUndeclaredTemplateInfo(t *testing.T) {
	got := of(t, "undeclared_template", &Inputs{
		Folders: []FolderIn{{ID: "media", Name: "Family media", Path: "/srv/media", GID: 60001}},
		Paths: []PathIn{
			folderUse("plex", "library", "media", "/srv/media", false, false),
			folderUse("jellyfin", "movies", "media", "/srv/media", false, true),
			setting("other", "x", "/srv/x", true),
		}})
	if len(got) != 1 || got[0].Severity != Info || !strings.Contains(got[0].Title, "this template doesn't say how it writes") ||
		strings.Join(got[0].Instances, ",") != "plex" || strings.Join(got[0].Folders, ",") != "media" {
		t.Fatalf("got %+v", got)
	}
	if !strings.Contains(got[0].Title, "Family media") {
		t.Errorf("title doesn't name the folder: %q", got[0].Title)
	}
}

func TestPrimaryGIDConflict(t *testing.T) {
	a := folderUse("arr", "library", "media", "/srv/media/lib", true, true)
	a.Service, a.GIDEnv, a.JoinsGroup, a.GID, a.OwnerKnown = "arr", "PGID", "gid_env", 60001, true
	b := setting("arr", "downloads", "/srv/downloads", true)
	b.Service, b.GIDEnv, b.JoinsGroup, b.GID, b.OwnerKnown = "arr", "PGID", "gid_env", 1000, true
	in := &Inputs{Folders: []FolderIn{{ID: "media", Name: "Media", Path: "/srv/media", GID: 60001}}, Paths: []PathIn{a, b}}
	got := of(t, "primary_gid_conflict", in)
	if len(got) != 1 || got[0].Severity != Problem || got[0].Class != FixExplain ||
		strings.Join(got[0].Instances, ",") != "arr" || !strings.Contains(got[0].Title, "PGID") {
		t.Fatalf("got %+v", got)
	}
	// One gid: no conflict.
	b.GID = 60001
	in.Paths = []PathIn{a, b}
	if got := of(t, "primary_gid_conflict", in); len(got) != 0 {
		t.Fatalf("same gid = %+v", got)
	}
	// Another service: no conflict.
	b.GID, b.Service = 1000, "other"
	in.Paths = []PathIn{a, b}
	if got := of(t, "primary_gid_conflict", in); len(got) != 0 {
		t.Fatalf("other service = %+v", got)
	}
}

func TestMustOwnConflict(t *testing.T) {
	a := folderUse("samba", "share", "media", "/srv/media", true, true)
	b := folderUse("nextcloud", "data", "media", "/srv/media/nc", true, true)
	a.MustOwn, b.MustOwn = true, true
	c := setting("x", "a", "/srv/own", true)
	d := setting("y", "b", "/srv/own", true)
	c.MustOwn, d.MustOwn = true, true
	e := setting("z", "c", "/srv/own", true) // not must_own
	got := of(t, "must_own_conflict", &Inputs{Folders: []FolderIn{{ID: "media", Name: "Media", Path: "/srv/media", GID: 60001}},
		Paths: []PathIn{a, b, c, d, e}})
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	for _, f := range got {
		if f.Severity != Problem || f.Class != FixExplain || len(f.Instances) != 2 {
			t.Errorf("finding %+v", f)
		}
	}
}

func TestExclusiveConflict(t *testing.T) {
	excl := []templates.Check{{Kind: templates.CheckExclusive, Reason: "Time Machine bundles break with two writers"}}
	a := folderUse("timemachine", "backups", "tm", "/srv/tm", true, true)
	a.Checks = excl
	b := folderUse("timemachine-b", "backups", "tm", "/srv/tm", true, true)
	b.Checks = excl
	r := folderUse("reader", "x", "tm", "/srv/tm", false, true)
	got := of(t, "exclusive", &Inputs{Folders: []FolderIn{{ID: "tm", Name: "Time Machine", Path: "/srv/tm", GID: 60002}},
		Paths: []PathIn{a, b, r}})
	if len(got) == 0 {
		t.Fatal("no finding")
	}
	for _, f := range got {
		if f.Severity != Problem || f.Class != FixExplain || !strings.Contains(f.Why, "Time Machine bundles break") {
			t.Errorf("finding %+v", f)
		}
		for _, i := range f.Instances {
			if i == "reader" {
				t.Errorf("a reader is no conflict: %+v", f)
			}
		}
	}
	// A hand-typed path: the same rule.
	c := setting("timemachine", "backups", "/srv/tm2", true)
	c.Checks = excl
	d := setting("rsync", "dst", "/srv/tm2/sub", true)
	if got := of(t, "exclusive", &Inputs{Paths: []PathIn{c, d}}); len(got) != 1 || strings.Join(got[0].Instances, ",") != "rsync,timemachine" {
		t.Fatalf("path = %+v", got)
	}
	// Alone: nothing.
	if got := of(t, "exclusive", &Inputs{Paths: []PathIn{c}}); len(got) != 0 {
		t.Fatalf("alone = %+v", got)
	}
}

func TestPathOutsideRoots(t *testing.T) {
	got := of(t, "path_outside_roots", &Inputs{Paths: []PathIn{
		setting("a", "x", "/data/stuff", true),
		setting("b", "y", "/srv/ok", true),
		setting("c", "z", "/srvx/no", true),
	}})
	if len(got) != 2 || got[0].Severity != Warning || got[0].Class != FixExplain {
		t.Fatalf("got %+v", got)
	}
}

func TestCustomOverrideMount(t *testing.T) {
	got := of(t, "custom_override_mount", &Inputs{Paths: []PathIn{
		custom("samba", "/srv/media"),
		folderUse("jellyfin", "movies", "media", "/srv/media/movies", false, true),
		custom("alone", "/srv/alone"),
	}})
	if len(got) != 1 || got[0].Severity != Warning || got[0].Class != FixExplain || len(got[0].Steps) == 0 ||
		strings.Join(got[0].Instances, ",") != "jellyfin,samba" {
		t.Fatalf("got %+v", got)
	}
}

func TestGIDCollision(t *testing.T) {
	u := setting("app", "data", "/srv/data", true)
	u.GID, u.OwnerKnown = 5000, true
	in := &Inputs{Folders: []FolderIn{{ID: "adopted", Name: "Adopted", Path: "/srv/adopted", GID: 5000}}, Paths: []PathIn{u}}
	got := of(t, "gid_collision", in)
	if len(got) != 1 || got[0].Severity != Problem || got[0].Class != FixExplain || strings.Join(got[0].Folders, ",") != "adopted" {
		t.Fatalf("got %+v", got)
	}
	// Assigned to that folder: no collision.
	in.Paths = append(in.Paths, folderUse("app", "x", "adopted", "/srv/adopted", false, true))
	if got := of(t, "gid_collision", in); len(got) != 0 {
		t.Fatalf("assigned = %+v", got)
	}
}

func TestFolderChanged(t *testing.T) {
	got := of(t, "folder_changed", &Inputs{
		Folders: []FolderIn{{ID: "media", Name: "Family media", Path: "/srv/media", GID: 60001}},
		Changes: []ChangeIn{{Instance: "jellyfin", Key: "movies", Folder: "media", Subpath: "movies", Detail: "movies is a symlink"}},
	})
	if len(got) != 1 || got[0].Severity != Problem || got[0].Class != FixExplain || len(got[0].Steps) == 0 ||
		!strings.Contains(got[0].Why, "movies is a symlink") || strings.Join(got[0].Paths, ",") != "/srv/media/movies" {
		t.Fatalf("got %+v", got)
	}
	// H2: a root with another device or inode points at the re-check.
	got = of(t, "folder_changed", &Inputs{
		Folders: []FolderIn{{ID: "media", Name: "Family media", Path: "/srv/media", GID: 60001}},
		Changes: []ChangeIn{{Instance: "jellyfin", Key: "movies", Folder: "media", Detail: "the folder's device number changed (device 50, stored 49; inode 256)"}},
	})
	if len(got) != 1 || !strings.Contains(got[0].Steps[0], "Re-check identity") {
		t.Fatalf("identity steps = %+v", got)
	}
	// Follow-up (b): another inode is another directory: no reboot hint.
	got = of(t, "folder_changed", &Inputs{
		Folders: []FolderIn{{ID: "media", Name: "Family media", Path: "/srv/media", GID: 60001}},
		Changes: []ChangeIn{{Instance: "jellyfin", Key: "movies", Folder: "media", Detail: "the folder is another directory (device 49 inode 300, stored 49 256)"}},
	})
	if len(got) != 1 || !strings.Contains(got[0].Steps[0], "someone may have swapped it") || strings.Contains(strings.Join(got[0].Steps, " "), "reboot") {
		t.Fatalf("swapped steps = %+v", got)
	}
}

// H4: a service that holds a folder's gid and also mounts a path at or
// above the folder reaches every folder directory through that mount.
func TestFolderReachableAbove(t *testing.T) {
	media := FolderIn{ID: "media", Name: "Family media", Path: "/srv/media", GID: 60001}
	use := folderUse("immich", "library", "media", "/srv/media/photos", false, true)
	other := folderUse("jellyfin", "movies", "media", "/srv/media/movies", false, true)
	above := setting("immich", "extra", "/srv", true)
	at := custom("immich", "/srv/media")
	elsewhere := setting("immich", "cache", "/srv/cache", true)
	below := setting("immich", "inside", "/srv/media/photos/x", true)
	otherSvc := setting("immich", "db", "/srv", true)
	otherSvc.Service = "db"
	media.Uses = []PathIn{use, other}
	got := of(t, "folder_reachable_above", &Inputs{Folders: []FolderIn{media},
		Paths: []PathIn{use, other, above, at, elsewhere, below, otherSvc}})
	if len(got) != 1 {
		t.Fatalf("findings = %+v", got)
	}
	f := got[0]
	if f.Severity != Problem || f.Class != FixExplain || len(f.Steps) == 0 || f.FixKind != "" ||
		strings.Join(f.Instances, ",") != "immich" || strings.Join(f.Folders, ",") != "media" ||
		strings.Join(f.Paths, ",") != "/srv,/srv/media" || !strings.Contains(f.Title, "Family media") {
		t.Errorf("finding = %+v", f)
	}
	if f.FP != Fingerprint("folder_reachable_above", "immich", "immich", "media") {
		t.Errorf("fp = %s", f.FP)
	}
	reach := ReachedAbove(media, []PathIn{use, other, above, at, elsewhere, below, otherSvc})
	if len(reach) != 2 || reach[0].Above.HostPath != "/srv" || reach[1].Above.HostPath != "/srv/media" || reach[0].Use.Key != "library" {
		t.Errorf("reach = %+v", reach)
	}
	// Nothing at or above: no finding.
	if got := of(t, "folder_reachable_above", &Inputs{Folders: []FolderIn{media}, Paths: []PathIn{use, other, elsewhere, below, otherSvc}}); len(got) != 0 {
		t.Errorf("findings = %+v", got)
	}
}
