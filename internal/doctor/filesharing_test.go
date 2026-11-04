package doctor

import (
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/settings"
)

// Plan 3 Task 11: the file-sharing checks (contract §14.5 "File sharing").

func i64(n int64) *int64 { return &n }

func smbIn() FileSharingIn {
	return FileSharingIn{Instance: "samba", Label: "Samba"}
}

func TestCanaryFindsUnrevokedHolder(t *testing.T) {
	fs := smbIn()
	fs.Holders = []HolderIn{{Key: "share_password", User: "alice", HasAccess: true}, {Key: "share_password", User: "bob"}}
	got := of(t, KindCredentialWithoutAccess, &Inputs{FileSharing: []FileSharingIn{fs}})
	if len(got) != 1 {
		t.Fatalf("findings = %+v", got)
	}
	f := got[0]
	if f.Severity != Problem || f.FP != CredentialFP("samba", "share_password", "bob") || f.Class != FixOneClick || f.FixKind != FixRevokeLeaver ||
		len(f.Instances) != 1 || f.Instances[0] != "samba" || !strings.Contains(f.Title, "bob") || !strings.Contains(f.Title, "Samba") {
		t.Errorf("canary = %+v", f)
	}
	// Without the directory there are no holders: nothing judged.
	fs.Holders = nil
	if got := of(t, KindCredentialWithoutAccess, &Inputs{FileSharing: []FileSharingIn{fs}}); len(got) != 0 {
		t.Errorf("without holders = %+v", got)
	}
}

// treeIn: alice (10000) and bob (10001) have folders in /srv/homes.
func treeIn() TreeIn {
	return TreeIn{Instance: "samba", Key: "homes", Label: "Homes", HostPath: "/srv/homes", People: map[string]int{"alice": 10000, "bob": 10001}}
}

func treeInputs(fs FileSharingIn, at time.Time, children ...folderfix.ChildOwner) *Inputs {
	in := &Inputs{FileSharing: []FileSharingIn{fs}, Scans: map[string]ScanIn{}}
	if children != nil {
		in.Scans["/srv/homes"] = ScanIn{Target: "/srv/homes", Tree: true, At: at, Report: &folderfix.Report{Children: children}}
	}
	return in
}

func TestFormerAccountFinding(t *testing.T) {
	fs := smbIn()
	fs.Trees = []TreeIn{treeIn()}
	now := time.Now()
	in := treeInputs(fs, now,
		folderfix.ChildOwner{Name: "alice", UID: 10023, GID: 10023, Mode: 0o700, Dir: true},
		folderfix.ChildOwner{Name: "bob", UID: 10001, GID: 10001, Mode: 0o700, Dir: true})
	got := of(t, KindFormerAccountFolder, in)
	if len(got) != 1 {
		t.Fatalf("findings = %+v", got)
	}
	f := got[0]
	if f.Severity != Warning || f.Class != FixExplain || f.FixKind != "" || len(f.Steps) == 0 ||
		f.Title != "alice's Samba folder belongs to a former account (uid 10023)." ||
		len(f.Paths) != 1 || f.Paths[0] != "/srv/homes/alice" {
		t.Errorf("former = %+v", f)
	}
	if n := len(of(t, KindPersonTreeOwner, in)); n != 0 {
		t.Errorf("%d person_tree_owner findings for a former account's folder / a correct one", n)
	}

	// The same subject from the hook report alone (no scan yet): the same
	// fingerprint.
	rfs := smbIn()
	rfs.Trees = []TreeIn{treeIn()}
	rfs.ReportAt = now
	rfs.Report = &settings.HookReport{Version: 1, Findings: []settings.HookFinding{
		{Code: "former_account", Severity: "warning", Subject: "alice", Message: "alice's folder belongs to uid 10023", Option: "homes", UID: i64(10023)},
	}}
	rep := of(t, KindFormerAccountFolder, treeInputs(rfs, time.Time{}))
	if len(rep) != 1 || rep[0].FP != f.FP || rep[0].Title != f.Title || rep[0].Class != FixExplain {
		t.Errorf("from the report = %+v, want fp %s", rep, f.FP)
	}
	// A scan newer than the report wins (here: alice's folder is fine now).
	newer := treeInputs(rfs, now.Add(time.Minute), folderfix.ChildOwner{Name: "alice", UID: 10000, GID: 10000, Mode: 0o700, Dir: true})
	if got := of(t, KindFormerAccountFolder, newer); len(got) != 0 {
		t.Errorf("a newer scan still shows %+v", got)
	}
	// Without the directory (People nil) the tree isn't judged.
	rfs.Trees[0].People = nil
	if got := of(t, KindFormerAccountFolder, treeInputs(rfs, time.Time{})); len(got) != 0 {
		t.Errorf("unknown people: %+v", got)
	}
}

func TestPersonTreeOwnerFinding(t *testing.T) {
	fs := smbIn()
	fs.Trees = []TreeIn{treeIn()}
	in := treeInputs(fs, time.Now(),
		folderfix.ChildOwner{Name: "alice", UID: 10000, GID: 100, Mode: 0o700, Dir: true},
		folderfix.ChildOwner{Name: "bob", UID: 10001, GID: 10001, Mode: 0o755, Dir: true},
		folderfix.ChildOwner{Name: "carol", UID: 10002, GID: 10002, Mode: 0o700, Dir: true},
		folderfix.ChildOwner{Name: "notes.txt", UID: 0, GID: 0, Mode: 0o644})
	got := of(t, KindPersonTreeOwner, in)
	var warns, infos []Finding
	for _, f := range got {
		switch f.Severity {
		case Warning:
			warns = append(warns, f)
		case Info:
			infos = append(infos, f)
		}
	}
	if len(warns) != 2 || len(infos) != 1 {
		t.Fatalf("findings = %+v", got)
	}
	a := warns[0]
	if a.FP != TreeFP(KindPersonTreeOwner, "samba", "homes", "alice") || a.Class != FixOneClick || a.FixKind != FixPersonTreeOwner ||
		!strings.Contains(a.Fix, "chown 10000:10000 + chmod 0700 /srv/homes/alice (not recursive") || !strings.Contains(a.Why, "group 100") {
		t.Errorf("alice = %+v", a)
	}
	if !strings.Contains(warns[1].Why, "mode 0755") {
		t.Errorf("bob = %+v", warns[1])
	}
	// Anything else at the top: one Info naming them (carol: no access
	// any more; a file).
	if i := infos[0]; i.Class != FixNone || !strings.Contains(i.Why, "`carol`") || !strings.Contains(i.Why, "`notes.txt`") || !strings.Contains(i.Title, "2 entries") {
		t.Errorf("info = %+v", i)
	}
	// The hook report's wrong_owner gives the same one-click finding.
	rfs := smbIn()
	rfs.Trees = []TreeIn{treeIn()}
	rfs.Report = &settings.HookReport{Version: 1, Findings: []settings.HookFinding{{Code: "wrong_owner", Severity: "warning", Subject: "alice", Message: "wrong", UID: i64(10000)}}}
	rfs.ReportAt = time.Now()
	// Fix round 1: the report alone is explain-only (no scan has shown
	// alice's own uid owning it) — same fingerprint.
	rep := of(t, KindPersonTreeOwner, treeInputs(rfs, time.Time{}))
	if len(rep) != 1 || rep[0].FP != a.FP || rep[0].Class != FixExplain || rep[0].FixKind != "" || len(rep[0].Steps) == 0 {
		t.Errorf("from the report alone = %+v", rep)
	}
	// An older scan showing another owner: still explain-only.
	other := treeInputs(rfs, rfs.ReportAt.Add(-time.Hour), folderfix.ChildOwner{Name: "alice", UID: 10023, GID: 10023, Mode: 0o700, Dir: true})
	if rep := of(t, KindPersonTreeOwner, other); len(rep) != 1 || rep[0].Class != FixExplain {
		t.Errorf("report + scan of another owner = %+v", rep)
	}
	// An older scan showing alice's own uid: one-click.
	own := treeInputs(rfs, rfs.ReportAt.Add(-time.Hour), folderfix.ChildOwner{Name: "alice", UID: 10000, GID: 10000, Mode: 0o700, Dir: true})
	if rep := of(t, KindPersonTreeOwner, own); len(rep) != 1 || rep[0].FP != a.FP || rep[0].Class != FixOneClick || rep[0].FixKind != FixPersonTreeOwner {
		t.Errorf("report + scan of alice's uid = %+v", rep)
	}
	// Generic disk checks leave a tree scan alone.
	in.Scans["/srv/homes"] = ScanIn{Target: "/srv/homes", Tree: true, Report: &folderfix.Report{Symlinks: folderfix.Count{N: 3}, HardLinks: folderfix.Count{N: 1}}}
	if got := of(t, KindSkippedEntries, in); len(got) != 0 {
		t.Errorf("skipped_entries on a tree: %+v", got)
	}
	if got := of(t, KindNoACL, in); len(got) != 0 {
		t.Errorf("no_acl on a tree: %+v", got)
	}
}

func TestHookReportFindings(t *testing.T) {
	fs := smbIn()
	fs.Report = &settings.HookReport{Version: 1, Findings: []settings.HookFinding{
		{Code: "name_refused", Severity: "info", Subject: "homes", Message: "share name homes is reserved ‮gnp.exe"},
		{Code: "owner_unwritable", Severity: "problem", Subject: "alice", Message: "can't write /homes/alice", Option: "homes"},
		{Code: "former_account", Severity: "warning", Subject: "bob", Message: "x"},
	}}
	in := &Inputs{FileSharing: []FileSharingIn{fs}}
	nr := of(t, KindNameRefused, in)
	if len(nr) != 1 || nr[0].Severity != Info || nr[0].Class != FixExplain || strings.ContainsRune(nr[0].Title, '‮') ||
		!strings.Contains(nr[0].Title, "share name homes is reserved") {
		t.Errorf("name_refused = %+v", nr)
	}
	ou := of(t, KindOwnerUnwritable, in)
	if len(ou) != 1 || ou[0].Severity != Problem || !strings.Contains(ou[0].Title, "can't write /homes/alice") {
		t.Errorf("owner_unwritable = %+v", ou)
	}
	if got := reportText(strings.Repeat("é", 300)); len([]rune(got)) != 200 {
		t.Errorf("clipped to %d runes", len([]rune(got)))
	}
}

func TestLocalNetworksEmptyProblem(t *testing.T) {
	a, b := smbIn(), FileSharingIn{Instance: "timemachine", Label: "Time Machine"}
	a.LocalNetworksEmpty, b.LocalNetworksEmpty = true, true
	got := of(t, KindLocalNetworksEmpty, &Inputs{FileSharing: []FileSharingIn{a, b, {Instance: "other"}}})
	if len(got) != 1 || got[0].Severity != Problem || got[0].Title != "Local networks is empty; file sharing is off." ||
		strings.Join(got[0].Instances, ",") != "samba,timemachine" || !strings.Contains(strings.Join(got[0].Steps, " "), "Settings → Local networks") {
		t.Errorf("local_networks_empty = %+v", got)
	}
	if got := of(t, KindLocalNetworksEmpty, &Inputs{FileSharing: []FileSharingIn{smbIn()}}); len(got) != 0 {
		t.Errorf("not empty: %+v", got)
	}
}

func TestUnverifiableAccount(t *testing.T) {
	got := of(t, KindUnverifiableAccount, &Inputs{FileSharing: []FileSharingIn{smbIn()},
		Unverifiable: []UnverifiableIn{{Instance: "samba", Key: "share_password", User: "carol"}}})
	if len(got) != 1 || got[0].Severity != Problem || got[0].Title != "Samba: can't verify carol's account." || got[0].Class != FixExplain {
		t.Errorf("unverifiable = %+v", got)
	}
}

func TestServedToNobody(t *testing.T) {
	fs := smbIn()
	fs.Unserved = []UnservedIn{{Key: "share1_folder", Label: "Share 1 folder", Requires: []string{"share1_readers", "share1_writers"},
		RequiresLabels: []string{"Share 1 readers", "Share 1 writers"}}}
	got := of(t, KindServedToNobody, &Inputs{FileSharing: []FileSharingIn{fs}})
	if len(got) != 1 || got[0].Severity != Warning || got[0].Title != "Share 1 folder of Samba is served to nobody." ||
		got[0].Link == nil || got[0].Link.Option != "share1_readers" {
		t.Errorf("served_to_nobody = %+v", got)
	}
}
