package doctor

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	units "github.com/docker/go-units"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/templates"
)

// The disk checks (contract §14.5, Task 11): they judge the cached fixer
// scans (Inputs.Scans, by target host path) and the running containers'
// gids (Inputs.Runtime). Cheap: the scans ran earlier (on demand, after
// every folder apply, daily); a check here never runs anything. Every
// finding from a partial scan carries Partial and says so.

func init() {
	Register(folderOwnerCheck{})
	Register(sharedPathDiskCheck{})
	Register(filesystemCheck{})
	Register(freeSpaceCheck{})
	Register(noACLCheck{})
	Register(skippedEntriesCheck{})
	Register(scanFailedCheck{})
	Register(runtimeGIDCheck{})
}

// Finding kinds and fixes of this file.
const (
	KindFolderOwner    = "folder_owner"
	KindFilesystem     = "filesystem"
	KindFreeSpace      = "free_space"
	KindNoACL          = "no_acl"
	KindSkippedEntries = "skipped_entries"
	KindScanFailed     = "scan_failed"

	// FixReapplyFolder is folder_owner's one-click fix (Task 12).
	FixReapplyFolder = "reapply_folder"
)

// sortedScans is in.Scans by target.
func sortedScans(in *Inputs) []ScanIn {
	out := make([]ScanIn, 0, len(in.Scans))
	for _, s := range in.Scans {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// scanFor is the successful scan whose target is at or above p (the
// deepest one).
func scanFor(in *Inputs, p string) (ScanIn, bool) {
	p = path.Clean(p)
	var best ScanIn
	found := false
	for _, s := range in.Scans {
		if s.Report == nil || !under(p, path.Clean(s.Target)) {
			continue
		}
		if !found || len(s.Target) > len(best.Target) {
			best, found = s, true
		}
	}
	return best, found
}

// partial marks f as coming from s: Partial and the text when s stopped
// at a cap.
func partial(f *Finding, s ScanIn) {
	if s.Report != nil && s.Report.Partial {
		f.Partial = true
		f.Why += fmt.Sprintf(" (partial scan: stopped after %d entries)", s.Report.Entries)
	}
}

// principalInstance is the instance a principal name stands for
// ("<instance>" or "<instance>.<n>"; instance ids have no dot).
func principalInstance(name string) string {
	inst, _, _ := strings.Cut(name, ".")
	return inst
}

// scanFolders is [s.Folder], or nil for a hand-typed path.
func scanFolders(s ScanIn) []string {
	if s.Folder == "" {
		return nil
	}
	return []string{s.Folder}
}

// what names a scan's target for the admin.
func what(in *Inputs, s ScanIn) string {
	if s.Folder != "" {
		return "shared folder " + folderName(folderByID(in), s.Folder)
	}
	return "`" + s.Target + "`"
}

// blocked is one principal that can't reach what it needs.
type blocked struct {
	Instance    string `json:"instance"`
	Read, Write int64
	text        string
}

// blockedOf lists the scan's principals that can't read (or, writers,
// write) entries, each described through its use (uses: the target's
// uses), sorted by instance.
func blockedOf(s ScanIn, uses []PathIn) []blocked {
	if s.Report == nil {
		return nil
	}
	byName := map[string]folderfix.Principal{}
	for _, p := range s.Principals {
		byName[p.Name] = p
	}
	var out []blocked
	for _, pa := range s.Report.Principals {
		p, ok := byName[pa.Name]
		if !ok {
			continue
		}
		b := blocked{Instance: principalInstance(pa.Name), Read: pa.CantRead.N}
		if p.Write {
			b.Write = pa.CantWrite.N
		}
		if b.Read == 0 && b.Write == 0 {
			continue
		}
		who := ""
		for _, u := range sortedUses(uses) {
			if u.Instance == b.Instance && u.OwnerKnown && u.UID == p.UID {
				who = how(u)
				break
			}
		}
		if who == "" {
			verb, gid := "reads", ""
			if p.Write {
				verb = "writes"
			}
			if len(p.GIDs) > 0 {
				gid = fmt.Sprintf(" (group %d)", p.GIDs[0])
			}
			who = fmt.Sprintf("%s %s as uid %d%s", b.Instance, verb, p.UID, gid)
		}
		var cant []string
		if b.Read > 0 {
			cant = append(cant, fmt.Sprintf("can't read %d entries%s", b.Read, samples(pa.CantRead)))
		}
		if b.Write > 0 {
			cant = append(cant, fmt.Sprintf("can't write %d entries%s", b.Write, samples(pa.CantWrite)))
		}
		b.text = who + " and " + strings.Join(cant, " and ")
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

// samples is " (a, b, c)": up to three of c's sample paths.
func samples(c folderfix.Count) string {
	if len(c.Sample) == 0 {
		return ""
	}
	return " (" + strings.Join(c.Sample[:min(len(c.Sample), 3)], ", ") + ")"
}

func blockedInstances(bs []blocked) []string {
	var s []string
	for _, b := range bs {
		s = append(s, b.Instance)
	}
	return uniq(s...)
}

func blockedTexts(bs []blocked) []string {
	var s []string
	for _, b := range bs {
		s = append(s, b.text)
	}
	return s
}

// ── folder_owner ────────────────────────────────────────

type folderOwnerCheck struct{}

func (folderOwnerCheck) Kind() string { return KindFolderOwner }

func (folderOwnerCheck) Run(in *Inputs) []Finding {
	fs := folderByID(in)
	var out []Finding
	for _, s := range sortedScans(in) {
		if s.Folder == "" || s.Report == nil {
			continue
		}
		fo, ok := fs[s.Folder]
		if !ok {
			continue
		}
		var drift, driftKeys []string
		if e := s.Report.Expected; e != nil {
			for _, d := range []struct {
				key, text string
				c         folderfix.Count
			}{
				{"group", "%d entries with another group%s", e.Group},
				{"setgid", "%d directories without setgid%s", e.Setgid},
				{"default_acl", "%d directories without the default ACL%s", e.DefaultACL},
				{"mode", "%d entries with other permissions%s", e.Mode},
				{"owner", "%d entries with another owner%s", e.Owner},
			} {
				if d.c.N > 0 {
					drift = append(drift, fmt.Sprintf(d.text, d.c.N, samples(d.c)))
					driftKeys = append(driftKeys, d.key)
				}
			}
		}
		bs := blockedOf(s, fo.Uses)
		if len(drift) == 0 && len(bs) == 0 {
			continue
		}
		f := Finding{
			FP: Fingerprint(KindFolderOwner, "folder:"+s.Folder), Kind: KindFolderOwner, Severity: Warning,
			Title: fmt.Sprintf("Shared folder %s drifted since the last apply.", fo.Name),
			Class: FixOneClick, FixKind: FixReapplyFolder,
			Fix:     fmt.Sprintf("Apply shared folder %s's consistent ownership%s: its group, setgid directories and default ACLs (previewed first; a permissions snapshot is saved before anything changes).", fo.Name, again(fo)),
			Folders: []string{s.Folder}, Paths: []string{s.Target}, Instances: instancesOf(fo.Uses),
		}
		var why []string
		if len(bs) > 0 {
			f.Severity, f.Instances = Problem, blockedInstances(bs)
			f.Title = fmt.Sprintf("Shared folder %s: %s can't reach all of its files.", fo.Name, joinAnd(f.Instances))
			why = append(why, "An app that can't read or write its files fails: "+strings.Join(blockedTexts(bs), "; ")+".")
		}
		if len(drift) > 0 {
			why = append(why, "It drifted since the last apply: "+strings.Join(drift, ", ")+".")
		}
		f.Why = strings.Join(why, " ")
		f.Inputs = Digest([]any{driftKeys, blockedInstances(bs)})
		partial(&f, s)
		out = append(out, f)
	}
	return out
}

// again is " again" once the folder was applied (M9).
func again(fo FolderIn) string {
	if fo.LastApply != nil {
		return " again"
	}
	return ""
}

// ── shared_path (the disk part) ─────────────────────────

// sharedPathDiskCheck adds the disk part of shared_path (P16: a separate
// check with the same kind and fingerprint as the config one, which Run
// replaces with this more severe finding): with a scan of a hand-typed
// path, a writer that can't write or a reader that can't read → Problem
// with the counts.
type sharedPathDiskCheck struct{}

func (sharedPathDiskCheck) Kind() string { return KindSharedPath }

func (sharedPathDiskCheck) Run(in *Inputs) []Finding {
	var base []Finding
	var out []Finding
	for _, s := range sortedScans(in) {
		if s.Folder != "" || s.Report == nil {
			continue
		}
		var uses []PathIn
		for _, u := range in.Paths {
			if u.Folder == "" && path.Clean(u.HostPath) == s.Target {
				uses = append(uses, u)
			}
		}
		bs := blockedOf(s, uses)
		if len(bs) == 0 {
			continue
		}
		if base == nil {
			base = sharedPathCheck{}.Run(in)
		}
		var f Finding
		found := false
		for _, b := range base {
			for _, p := range b.Paths {
				if p == s.Target {
					f, found = b, true
				}
			}
		}
		if !found {
			f = Finding{
				FP: Fingerprint(KindSharedPath, s.Target), Kind: KindSharedPath,
				Title:     fmt.Sprintf("%s can't reach all of `%s`.", joinAnd(blockedInstances(bs)), s.Target),
				Class:     FixExplain,
				Steps:     []string{"Give the files to the uid and group the app runs as, or manage the directory as a shared folder (Settings → Shared folders): one group for every app that uses it."},
				Instances: blockedInstances(bs), Paths: []string{s.Target},
			}
		} else {
			f.Steps = append([]string(nil), f.Steps...)
		}
		f.Severity = Problem
		f.Why = strings.TrimSpace(f.Why + " On disk: " + strings.Join(blockedTexts(bs), "; ") + ".")
		f.Inputs = Digest([]any{f.Inputs, bs})
		partial(&f, s)
		out = append(out, f)
	}
	return out
}

// ── filesystem / free_space (template checks) ───────────

type filesystemCheck struct{}

func (filesystemCheck) Kind() string { return KindFilesystem }

func (filesystemCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, u := range sortedUses(in.Paths) {
		for _, c := range u.Checks {
			if c.Kind != templates.CheckFilesystem {
				continue
			}
			s, ok := scanFor(in, u.HostPath)
			if !ok {
				continue
			}
			r := s.Report
			var bad []string
			for _, n := range c.Needs {
				switch {
				case n == "acl" && !r.ACL:
					bad = append(bad, "has no ACL support")
				case n == "xattr" && !r.Xattr:
					bad = append(bad, "has no extended attributes")
				}
			}
			for _, n := range c.Not {
				if r.FSType == n {
					bad = append(bad, "is on "+n)
				}
			}
			if len(bad) == 0 {
				continue
			}
			f := Finding{
				FP: Fingerprint(KindFilesystem, useID(u)), Kind: KindFilesystem, Severity: Problem,
				Title:     fmt.Sprintf("%s needs another filesystem for `%s`.", useName(u), path.Clean(u.HostPath)),
				Why:       fmt.Sprintf("%s: %s (%s) %s.", c.Reason, what(in, s), r.FSType, joinAnd(bad)),
				Class:     FixExplain,
				Steps:     []string{fmt.Sprintf("Move the data to a filesystem that has what %s needs (ext4, xfs, btrfs or zfs with ACLs and extended attributes), or remount it with them, then run the disk check again.", u.Instance)},
				Instances: []string{u.Instance}, Folders: uniq(u.Folder), Paths: []string{path.Clean(u.HostPath)},
				Inputs: Digest([]any{useID(u), c, bad}),
			}
			partial(&f, s)
			out = append(out, f)
		}
	}
	return out
}

type freeSpaceCheck struct{}

func (freeSpaceCheck) Kind() string { return KindFreeSpace }

func (freeSpaceCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, u := range sortedUses(in.Paths) {
		for _, c := range u.Checks {
			if c.Kind != templates.CheckFreeSpace || c.Min == "" {
				continue
			}
			// min was checked exactly at template load (binary units).
			want, err := units.RAMInBytes(c.Min)
			if err != nil || want <= 0 {
				continue
			}
			s, ok := scanFor(in, u.HostPath)
			if !ok || s.Report.FreeBytes >= uint64(want) {
				continue
			}
			f := Finding{
				FP: Fingerprint(KindFreeSpace, useID(u)), Kind: KindFreeSpace, Severity: Warning,
				Title: fmt.Sprintf("%s is low on space at `%s`.", useName(u), path.Clean(u.HostPath)),
				Why: fmt.Sprintf("%s: %s has %s free, %s wants at least %s.", c.Reason, what(in, s),
					units.BytesSize(float64(s.Report.FreeBytes)), u.Instance, units.BytesSize(float64(want))),
				Class:     FixExplain,
				Steps:     []string{"Free some space on that filesystem, or move the data to a larger one."},
				Instances: []string{u.Instance}, Folders: uniq(u.Folder), Paths: []string{path.Clean(u.HostPath)},
				Inputs: Digest([]any{useID(u), c.Min}),
			}
			partial(&f, s)
			out = append(out, f)
		}
	}
	return out
}

// ── no_acl ──────────────────────────────────────────────

type noACLCheck struct{}

func (noACLCheck) Kind() string { return KindNoACL }

func (noACLCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, s := range sortedScans(in) {
		if s.Report == nil || s.Report.ACL {
			continue
		}
		f := Finding{
			FP: Fingerprint(KindNoACL, s.Target), Kind: KindNoACL, Severity: Warning,
			Title: fmt.Sprintf("%s has no ACL support.", strings.ToUpper(what(in, s)[:1])+what(in, s)[1:]),
			Why: fmt.Sprintf("`%s` (%s) can't hold ACLs: the Hub can set the group, setgid and modes only, so new files don't inherit group access from a default ACL and previous groups can't keep their access through named entries.",
				s.Target, s.Report.FSType),
			Class:   FixExplain,
			Steps:   []string{"Mount the filesystem with ACL support (ext4 / xfs have it by default unless mounted noacl; zfs: acltype=posixacl), then run the disk check again."},
			Folders: scanFolders(s), Paths: []string{s.Target},
			Inputs: Digest([]any{s.Target, s.Report.FSType}),
		}
		partial(&f, s)
		out = append(out, f)
	}
	return out
}

// ── skipped_entries ─────────────────────────────────────

type skippedEntriesCheck struct{}

func (skippedEntriesCheck) Kind() string { return KindSkippedEntries }

func (skippedEntriesCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, s := range sortedScans(in) {
		r := s.Report
		if r == nil {
			continue
		}
		var parts, keys []string
		for _, k := range []struct {
			key, text string
			c         folderfix.Count
		}{
			{"hard_links", "files with more than one link", r.HardLinks},
			{"mount_points", "other mounts inside", r.MountPoints},
			{"specials", "devices, sockets or FIFOs", r.Specials},
			{"setid", "files with setuid or setgid", r.SetID},
			{"filecaps", "files with file capabilities", r.Skipped.FileCaps},
			{"path_too_long", "entries with a path over 4096 bytes", r.Skipped.PathTooLong},
			{"acl_too_large", "entries with ACLs too large to record", r.Skipped.ACLTooLarge},
			{"bad_acl", "entries whose ACL can't be kept exactly", r.BadACL},
			{"races", "entries changed while the scan ran", r.Races},
		} {
			if k.c.N > 0 {
				parts = append(parts, fmt.Sprintf("%d %s%s", k.c.N, k.text, samples(k.c)))
				keys = append(keys, k.key)
			}
		}
		if len(parts) == 0 {
			continue
		}
		f := Finding{
			FP: Fingerprint(KindSkippedEntries, s.Target), Kind: KindSkippedEntries, Severity: Warning,
			Title: fmt.Sprintf("Some entries of %s are left alone.", what(in, s)),
			Why:   "The fixer never changes these, so apps may not reach them: " + strings.Join(parts, "; ") + ".",
			Class: FixExplain,
			Steps: []string{
				"Hard links: changing one name would change the others, wherever they are: copy the file instead (cp, then remove the link).",
				"Other mounts, devices, sockets and FIFOs are never entered or changed: set their ownership by hand where an app needs them.",
				"Setuid / setgid files and files with file capabilities keep their owner and group (changing them would hand those privileges to the folder's apps or drop the capabilities): set them by hand if an app needs them.",
				"Entries that changed while the check ran: run the disk check again.",
			},
			Folders: scanFolders(s), Paths: []string{s.Target},
			Inputs: Digest([]any{s.Target, keys}),
		}
		partial(&f, s)
		out = append(out, f)
	}
	return out
}

// ── scan_failed ─────────────────────────────────────────

type scanFailedCheck struct{}

func (scanFailedCheck) Kind() string { return KindScanFailed }

func (scanFailedCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, s := range sortedScans(in) {
		if s.Err == "" {
			continue
		}
		out = append(out, Finding{
			FP: Fingerprint(KindScanFailed, s.Target), Kind: KindScanFailed, Severity: Warning,
			Title:   fmt.Sprintf("The disk check of %s failed.", what(in, s)),
			Why:     s.Err,
			Class:   FixExplain,
			Steps:   []string{"Fix what the message names, then run the disk check again (Doctor → Check disks)."},
			Folders: scanFolders(s), Paths: []string{s.Target},
			Inputs: Digest(s.Err),
		})
	}
	return out
}

// ── gid_collision (runtime) ─────────────────────────────

// runtimeGIDCheck is gid_collision's runtime part (T9 carry): a running
// container whose processes hold a gid in 60000–60999 that no folder
// assignment gives its service — through a root container, an image
// USER, a PGID-style env or anything the static check can't see. A gid
// of a folder shares the static finding's fingerprint (instance +
// folder).
type runtimeGIDCheck struct{}

func (runtimeGIDCheck) Kind() string { return KindGIDCollision }

func (runtimeGIDCheck) Run(in *Inputs) []Finding {
	fs := folderByID(in)
	gidOwner := map[int]FolderIn{}
	for _, f := range in.Folders {
		gidOwner[f.GID] = f
	}
	allowed := map[string]map[int]bool{} // instance \x00 service → gids
	for _, u := range in.Paths {
		k := u.Instance + "\x00" + u.Service
		if allowed[k] == nil {
			allowed[k] = map[int]bool{}
		}
		if f, ok := fs[u.Folder]; ok && u.Folder != "" {
			allowed[k][f.GID] = true
		}
		for _, g := range u.GIDs {
			allowed[k][g] = true
		}
	}
	type hit struct {
		inst     string
		gid      int
		services []string
	}
	hits := map[string]*hit{}
	var out []Finding
	var unread []RuntimeIn
	for _, r := range in.Runtime {
		if r.Err != "" {
			unread = append(unread, r)
			continue
		}
		for _, g := range r.GIDs {
			if !templates.InFolderGIDRange(int64(g)) || allowed[r.Instance+"\x00"+r.Service][g] {
				continue
			}
			k := r.Instance + "\x00" + strconv.Itoa(g)
			h := hits[k]
			if h == nil {
				h = &hit{inst: r.Instance, gid: g}
				hits[k] = h
			}
			h.services = append(h.services, r.Service)
		}
	}
	list := make([]*hit, 0, len(hits))
	for _, h := range hits {
		list = append(list, h)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].inst != list[j].inst {
			return list[i].inst < list[j].inst
		}
		return list[i].gid < list[j].gid
	})
	for _, h := range list {
		svcs := uniq(h.services...)
		held := fmt.Sprintf("The processes of %s's %s service hold gid %d (read from the running container, not from its configuration).",
			h.inst, joinAnd(svcs), h.gid)
		f := Finding{
			Kind: KindGIDCollision, Severity: Problem, Class: FixExplain, Instances: []string{h.inst},
			Inputs: Digest([]any{h.gid, svcs}),
		}
		if fo, ok := gidOwner[h.gid]; ok {
			f.FP = Fingerprint(KindGIDCollision, h.inst, fo.ID)
			f.Title = fmt.Sprintf("%s runs with gid %d, the group of shared folder %s.", h.inst, h.gid, fo.Name)
			f.Why = held + fmt.Sprintf(" Anything mounted with gid %d is reachable through that group: %s reaches shared folder %s's files without being assigned to it.", h.gid, h.inst, fo.Name)
			f.Folders, f.Paths = []string{fo.ID}, []string{fo.Path}
			f.Steps = []string{fmt.Sprintf("Change %s's group (its group or PGID setting, or the image's user) to a gid outside 60000–60999.", h.inst),
				fmt.Sprintf("Or assign %s to shared folder %s (Settings → Shared folders), if it should use it.", h.inst, fo.Name)}
		} else {
			f.FP = Fingerprint(KindGIDCollision, h.inst, "gid:"+strconv.Itoa(h.gid))
			f.Title = fmt.Sprintf("%s runs with gid %d, in the range reserved for shared folder groups.", h.inst, h.gid)
			f.Why = held + fmt.Sprintf(" Gids 60000–60999 belong to shared folders: once the Hub gives gid %d to a folder, %s reaches its files without being assigned to it.", h.gid, h.inst)
			f.Steps = []string{fmt.Sprintf("Change %s's group (its group or PGID setting, or the image's user) to a gid outside 60000–60999.", h.inst)}
		}
		out = append(out, f)
	}
	// I4: a container the check couldn't read (no cat, a failed or hung
	// exec, a pid: host container) is said, never silent: Info, one per
	// instance and service.
	sort.SliceStable(unread, func(i, j int) bool {
		if unread[i].Instance != unread[j].Instance {
			return unread[i].Instance < unread[j].Instance
		}
		return unread[i].Service < unread[j].Service
	})
	seen := map[string]bool{}
	for _, r := range unread {
		k := r.Instance + "\x00" + r.Service
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, Finding{
			FP: Fingerprint(KindGIDCollision, r.Instance, "unreadable:"+r.Service), Kind: KindGIDCollision, Severity: Info,
			Title: fmt.Sprintf("Group check skipped for %s (service %s).", r.Instance, r.Service),
			Why: fmt.Sprintf("The doctor couldn't read which groups the processes of %s's %s container hold: %s. It can't tell whether they hold a shared folder's gid without being assigned to it.",
				r.Instance, r.Service, r.Err),
			Class:     FixExplain,
			Steps:     []string{fmt.Sprintf("Check %s's group settings (PGID, the image's user) by hand: no gid in 60000–60999 unless it is assigned to that shared folder.", r.Instance)},
			Instances: []string{r.Instance},
			Inputs:    Digest([]any{r.Instance, r.Service}),
		})
	}
	return out
}
