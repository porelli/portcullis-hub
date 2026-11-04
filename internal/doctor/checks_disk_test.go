package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/templates"
)

// Task 11: the disk checks (contract §14.5) judge cached scans.

func scanAt(target, folder string, rep *folderfix.Report, ps ...folderfix.Principal) ScanIn {
	return ScanIn{At: time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC), Target: target, Folder: folder, Report: rep, Principals: ps}
}

func okReport() *folderfix.Report {
	return &folderfix.Report{Version: 1, Mode: "scan", FSType: "ext4", ACL: true, Xattr: true, Entries: 100, FreeBytes: 1 << 40}
}

func byKind(fs []Finding, kind string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestDiskFindings(t *testing.T) {
	jelly := folderUse("jellyfin", "media", "media", "/srv/media/movies", false, true)
	jelly.UID, jelly.GID, jelly.OwnerKnown = 1000, 1000, true
	samba := folderUse("samba", "share", "media", "/srv/media", true, true)
	samba.UID, samba.GID, samba.OwnerKnown = 10001, 10001, true
	samba.Checks = []templates.Check{
		{Kind: templates.CheckFilesystem, Reason: "Samba stores DOS attributes in xattrs", Needs: []string{"xattr", "acl"}, Not: []string{"nfs"}},
		{Kind: templates.CheckFreeSpace, Reason: "uploads need room", Min: "2TiB"},
	}
	// Hand-typed /srv/shared: radarr writes, sonarr reads (a shared_path).
	radarr := setting("radarr", "movies", "/srv/shared", true)
	radarr.UID, radarr.GID, radarr.OwnerKnown = 1001, 1001, true
	sonarr := setting("sonarr", "tv", "/srv/shared", false)
	sonarr.UID, sonarr.GID, sonarr.OwnerKnown = 1002, 1002, true

	drift := okReport()
	drift.ACL = false
	drift.Expected = &folderfix.Conformance{Group: folderfix.Count{N: 3, Sample: []string{"a"}}, Setgid: folderfix.Count{N: 1}}
	drift.Principals = []folderfix.PrincipalAccess{
		{Name: "jellyfin", UID: 1000, CantRead: folderfix.Count{N: 412, Sample: []string{"movies/new.mkv"}}},
		{Name: "samba", UID: 10001},
	}
	drift.HardLinks = folderfix.Count{N: 2, Sample: []string{"x/link"}}
	drift.Races = folderfix.Count{N: 1, Sample: []string{"y"}}
	drift.Skipped.FileCaps = folderfix.Count{N: 1, Sample: []string{"bin/ping"}}
	drift.Partial, drift.PartialReason, drift.Entries = true, "entries", 2000000

	shared := okReport()
	shared.Principals = []folderfix.PrincipalAccess{
		{Name: "radarr", UID: 1001, CantWrite: folderfix.Count{N: 7}},
		{Name: "sonarr", UID: 1002, CantRead: folderfix.Count{N: 412}},
	}
	in := &Inputs{
		Folders: []FolderIn{{ID: "media", Name: "Family media", Path: "/srv/media", GID: 60001, Uses: []PathIn{jelly, samba}}},
		Paths:   []PathIn{jelly, samba, radarr, sonarr},
		Scans: map[string]ScanIn{
			"/srv/media": scanAt("/srv/media", "media", drift,
				folderfix.Principal{Name: "jellyfin", UID: 1000, GIDs: []int{1000, 60001}},
				folderfix.Principal{Name: "samba", UID: 10001, GIDs: []int{10001, 60001}, Write: true}),
			"/srv/shared": scanAt("/srv/shared", "", shared,
				folderfix.Principal{Name: "radarr", UID: 1001, GIDs: []int{1001}, Write: true},
				folderfix.Principal{Name: "sonarr", UID: 1002, GIDs: []int{1002}}),
			"/srv/gone": {At: time.Now(), Target: "/srv/gone", Err: "/srv/gone/x is a symlink; give the real path"},
		},
	}
	in.BindRoots = roots
	r := Run(in, nil)
	all := r.Findings

	// folder_owner: drift (Warning) and a reader that can't read → Problem.
	fo := byKind(all, KindFolderOwner)
	if len(fo) != 1 || fo[0].Severity != Problem || fo[0].FixKind != FixReapplyFolder || fo[0].Class != FixOneClick {
		t.Fatalf("folder_owner = %+v", fo)
	}
	if !strings.Contains(fo[0].Why, "jellyfin") || !strings.Contains(fo[0].Why, "can't read 412") || !strings.Contains(fo[0].Why, "drifted since the last apply") {
		t.Errorf("folder_owner why = %q", fo[0].Why)
	}
	if strings.Contains(fo[0].Why, "samba") && strings.Contains(fo[0].Why, "samba reads") {
		t.Errorf("samba can do everything: %q", fo[0].Why)
	}
	if fo[0].Instances == nil || fo[0].Instances[0] != "jellyfin" || fo[0].Folders[0] != "media" {
		t.Errorf("folder_owner subjects = %v %v", fo[0].Instances, fo[0].Folders)
	}
	// Partial propagated, with the text.
	for _, k := range []string{KindFolderOwner, KindNoACL, KindSkippedEntries, KindFilesystem} {
		for _, f := range byKind(all, k) {
			if !f.Partial || !strings.Contains(f.Why, "(partial scan: stopped after 2000000 entries)") {
				t.Errorf("%s from a partial scan: partial=%t why=%q", k, f.Partial, f.Why)
			}
		}
	}

	// Drift only (nobody blocked): a Warning.
	only := okReport()
	only.Expected = &folderfix.Conformance{Mode: folderfix.Count{N: 5}}
	in2 := &Inputs{Folders: in.Folders, Paths: in.Paths, Scans: map[string]ScanIn{"/srv/media": scanAt("/srv/media", "media", only)}}
	if fo := of(t, KindFolderOwner, in2); len(fo) != 1 || fo[0].Severity != Warning || !strings.Contains(fo[0].Title, "drifted since the last apply") {
		t.Errorf("drift only = %+v", fo)
	}
	// A writer that can't write → Problem.
	cw := okReport()
	cw.Principals = []folderfix.PrincipalAccess{{Name: "samba", UID: 10001, CantWrite: folderfix.Count{N: 9}}}
	in3 := &Inputs{Folders: in.Folders, Paths: in.Paths, Scans: map[string]ScanIn{"/srv/media": scanAt("/srv/media", "media", cw,
		folderfix.Principal{Name: "samba", UID: 10001, GIDs: []int{10001}, Write: true})}}
	if fo := of(t, KindFolderOwner, in3); len(fo) != 1 || fo[0].Severity != Problem || !strings.Contains(fo[0].Why, "can't write 9") {
		t.Errorf("writer = %+v", fo)
	}
	// Conforming: no finding.
	in4 := &Inputs{Folders: in.Folders, Paths: in.Paths, Scans: map[string]ScanIn{"/srv/media": scanAt("/srv/media", "media", okReport())}}
	if fo := of(t, KindFolderOwner, in4); len(fo) != 0 {
		t.Errorf("conforming = %+v", fo)
	}

	// shared_path: the disk part upgrades the config finding (same fp,
	// its one-click fix kept) to a Problem with the counts.
	sp := byKind(all, KindSharedPath)
	if len(sp) != 1 {
		t.Fatalf("shared_path = %+v", sp)
	}
	cfg := of(t, KindSharedPath, &Inputs{Paths: in.Paths})
	if len(cfg) < 1 || sp[0].FP != cfg[0].FP {
		t.Fatalf("shared_path fp %s, config %+v", sp[0].FP, cfg)
	}
	if sp[0].Severity != Problem || sp[0].FixKind != FixManageAsFolder ||
		!strings.Contains(sp[0].Why, "sonarr's Tv reads as uid 1002 (group 1002) and can't read 412 entries") ||
		!strings.Contains(sp[0].Why, "radarr's Movies writes as uid 1001 (group 1001) and can't write 7 entries") {
		t.Errorf("shared_path = %+v", sp[0])
	}
	if sp[0].Instances[0] != "radarr" || sp[0].Instances[1] != "sonarr" {
		t.Errorf("shared_path instances = %v", sp[0].Instances)
	}

	// filesystem: needs acl, the scan says none → Problem naming samba.
	fsf := byKind(all, KindFilesystem)
	if len(fsf) != 1 || fsf[0].Severity != Problem || fsf[0].Class != FixExplain || !strings.Contains(fsf[0].Why, "Samba stores DOS attributes") ||
		fsf[0].Instances[0] != "samba" {
		t.Errorf("filesystem = %+v", fsf)
	}
	nfs := okReport()
	nfs.FSType = "nfs"
	if f := of(t, KindFilesystem, &Inputs{Folders: in.Folders, Paths: in.Paths, Scans: map[string]ScanIn{"/srv/media": scanAt("/srv/media", "media", nfs)}}); len(f) != 1 || !strings.Contains(f[0].Why, "nfs") {
		t.Errorf("filesystem nfs = %+v", f)
	}
	// free_space: 1 TiB free, 2 TiB wanted → Warning.
	free := byKind(all, KindFreeSpace)
	if len(free) != 1 || free[0].Severity != Warning || !strings.Contains(free[0].Why, "uploads need room") {
		t.Errorf("free_space = %+v", free)
	}
	// no_acl → Warning on the folder.
	na := byKind(all, KindNoACL)
	if len(na) != 1 || na[0].Severity != Warning || na[0].Folders[0] != "media" {
		t.Errorf("no_acl = %+v", na)
	}
	// skipped_entries: hard links, races, filecaps with counts and samples.
	sk := byKind(all, KindSkippedEntries)
	if len(sk) != 1 || sk[0].Severity != Warning || sk[0].Class != FixExplain {
		t.Fatalf("skipped_entries = %+v", sk)
	}
	for _, want := range []string{"2 files with more than one link (x/link)", "1 entries changed while the scan ran (y)", "1 files with file capabilities (bin/ping)"} {
		if !strings.Contains(sk[0].Why, want) {
			t.Errorf("skipped_entries why %q lacks %q", sk[0].Why, want)
		}
	}
	// scan_failed → Warning naming why.
	sf := byKind(all, KindScanFailed)
	if len(sf) != 1 || sf[0].Severity != Warning || !strings.Contains(sf[0].Why, "is a symlink") || sf[0].Paths[0] != "/srv/gone" {
		t.Errorf("scan_failed = %+v", sf)
	}
	// The report lists the scans.
	if len(r.Scans) != 3 || r.Scans[0].Target != "/srv/gone" || !r.Scans[1].Partial || r.Scans[1].Entries != 2000000 {
		t.Errorf("scans = %+v", r.Scans)
	}
}

// The runtime gid check (moved here from T9): a running container whose
// processes hold a folder-range gid it has no assignment for.
func TestRuntimeGIDFindings(t *testing.T) {
	jelly := folderUse("jellyfin", "media", "media", "/srv/media", false, true)
	jelly.GIDs = []int{60001}
	in := &Inputs{
		Folders: []FolderIn{{ID: "media", Name: "Family media", Path: "/srv/media", GID: 60001}, {ID: "docs", Name: "Docs", Path: "/srv/docs", GID: 60002}},
		Paths:   []PathIn{jelly},
		Runtime: []RuntimeIn{
			{Instance: "jellyfin", Service: "jellyfin", Container: "c1", GIDs: []int{1000, 60001}},          // assigned: fine
			{Instance: "jellyfin", Service: "transcoder", Container: "c2", GIDs: []int{60001}},              // other service: not given it
			{Instance: "plex", Service: "plex", Container: "c3", GIDs: []int{0, 60002, 60500, 70000, 1000}}, // docs + an unallocated one
		},
	}
	got := of(t, KindGIDCollision, in)
	var titles []string
	for _, f := range got {
		if f.Severity != Problem || f.Class != FixExplain {
			t.Errorf("%+v", f)
		}
		titles = append(titles, f.Title)
	}
	want := []string{
		"jellyfin runs with gid 60001, the group of shared folder Family media.",
		"plex runs with gid 60002, the group of shared folder Docs.",
		"plex runs with gid 60500, in the range reserved for shared folder groups.",
	}
	if strings.Join(titles, "\n") != strings.Join(want, "\n") {
		t.Errorf("titles:\n%s", strings.Join(titles, "\n"))
	}
	// Same fp as the static check's finding for the same instance and folder.
	if got[1].FP != Fingerprint(KindGIDCollision, "plex", "docs") {
		t.Errorf("fp %s", got[1].FP)
	}
	if !strings.Contains(got[0].Why, "transcoder") {
		t.Errorf("why = %q", got[0].Why)
	}
}
