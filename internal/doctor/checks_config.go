package doctor

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/templates"
)

// The config checks (contract §14.5): state, manifests, overrides and
// settings values. Cheap: they run on every doctor view.

func init() {
	Register(sharedPathCheck{})
	Register(pathOutsideRootsCheck{})
	Register(undeclaredTemplateCheck{})
	Register(primaryGIDConflictCheck{})
	Register(customOverrideMountCheck{})
	Register(mustOwnConflictCheck{})
	Register(exclusiveCheck{})
	Register(gidCollisionCheck{})
	Register(folderChangedCheck{})
	Register(folderReachableAboveCheck{})
}

// Finding kinds of this file.
const (
	KindSharedPath          = "shared_path"
	KindPathOutsideRoots    = "path_outside_roots"
	KindUndeclaredTemplate  = "undeclared_template"
	KindPrimaryGIDConflict  = "primary_gid_conflict"
	KindCustomOverrideMount = "custom_override_mount"
	KindMustOwnConflict     = "must_own_conflict"
	KindExclusive           = "exclusive"
	KindGIDCollision        = "gid_collision"
	KindFolderChanged       = "folder_changed"
	KindFolderReachAbove    = "folder_reachable_above"

	// FixManageAsFolder is shared_path's one-click fix (Task 12).
	FixManageAsFolder = "manage_as_folder"
)

// Steps shared by several findings.
const (
	stepCustomOverride = "Remove the mount from the custom override (the app's Expert tab) and use the template's folder setting with a shared folder, where it has one (Settings → Shared folders)."
	stepOneFolder      = "Define a shared folder at the outermost path and assign each app the subpath it needs (Settings → Shared folders), or point the settings at separate directories."
)

// under: p is at or below root (both clean).
func under(p, root string) bool {
	return p == root || root == "/" || strings.HasPrefix(p, root+"/")
}

// near: a and b are the same path or one is below the other.
func near(a, b string) bool {
	a, b = path.Clean(a), path.Clean(b)
	return under(a, b) || under(b, a)
}

// underRoots: p is under one of roots.
func underRoots(p string, roots []string) bool {
	p = path.Clean(p)
	for _, r := range roots {
		if under(p, path.Clean(r)) {
			return true
		}
	}
	return false
}

// useID names a use: "<instance>/<key>", or for a custom-override mount
// "<instance>/custom:<service>:<mount>".
func useID(u PathIn) string {
	if u.Source == SourceCustomOverride {
		return u.Instance + "/custom:" + u.Service + ":" + u.Mount
	}
	return u.Instance + "/" + u.Key
}

// useName is a use as the admin reads it.
func useName(u PathIn) string {
	if u.Source == SourceCustomOverride {
		return u.Instance + "'s custom override (" + u.Service + ":" + u.Mount + ")"
	}
	l := u.Label
	if l == "" {
		l = u.Key
	}
	return u.Instance + "'s " + l
}

// sortedUses is a copy of us sorted by useID (stable digests).
func sortedUses(us []PathIn) []PathIn {
	out := append([]PathIn(nil), us...)
	sort.SliceStable(out, func(i, j int) bool { return useID(out[i]) < useID(out[j]) })
	return out
}

// uniq is the sorted distinct non-empty strings of ss.
func uniq(ss ...string) []string {
	m := map[string]bool{}
	for _, s := range ss {
		if s != "" {
			m[s] = true
		}
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// instancesOf / pathsOf are the sorted distinct instances / host paths.
func instancesOf(us []PathIn) []string {
	var s []string
	for _, u := range us {
		s = append(s, u.Instance)
	}
	return uniq(s...)
}

func pathsOf(us []PathIn) []string {
	var s []string
	for _, u := range us {
		s = append(s, path.Clean(u.HostPath))
	}
	return uniq(s...)
}

// joinAnd is "a", "a and b", "a, b and c".
func joinAnd(ss []string) string {
	switch len(ss) {
	case 0:
		return ""
	case 1:
		return ss[0]
	}
	return strings.Join(ss[:len(ss)-1], ", ") + " and " + ss[len(ss)-1]
}

// quoted is each p in backticks.
func quoted(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = "`" + p + "`"
	}
	return out
}

// how describes how a use reads or writes ("samba writes as uid 10001
// (group 10001)").
func how(u PathIn) string {
	verb := "reads"
	if u.Writes {
		verb = "writes"
	}
	if !u.OwnerKnown {
		return fmt.Sprintf("%s %s (as an undeclared uid)", useName(u), verb)
	}
	return fmt.Sprintf("%s %s as uid %d (group %d)", useName(u), verb, u.UID, u.GID)
}

// folderByID indexes in.Folders.
func folderByID(in *Inputs) map[string]FolderIn {
	m := make(map[string]FolderIn, len(in.Folders))
	for _, f := range in.Folders {
		m[f.ID] = f
	}
	return m
}

// folderName is folder id's name (the id when unknown).
func folderName(fs map[string]FolderIn, id string) string {
	if f, ok := fs[id]; ok && f.Name != "" {
		return f.Name
	}
	return id
}

// ── shared_path ─────────────────────────────────────────

type sharedPathCheck struct{}

func (sharedPathCheck) Kind() string { return KindSharedPath }

// clusters groups the hand-typed uses (settings and custom-override
// mounts) whose host paths are the same or nested; only groups of two or
// more.
func clusters(paths []PathIn) [][]PathIn {
	var us []PathIn
	for _, u := range paths {
		if (u.Source == SourceSetting || u.Source == SourceCustomOverride) && u.HostPath != "" {
			us = append(us, u)
		}
	}
	us = sortedUses(us)
	parent := make([]int, len(us))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	for i := range us {
		for j := i + 1; j < len(us); j++ {
			if near(us[i].HostPath, us[j].HostPath) {
				parent[find(i)] = find(j)
			}
		}
	}
	groups := map[int][]PathIn{}
	var order []int
	for i := range us {
		r := find(i)
		if _, ok := groups[r]; !ok {
			order = append(order, r)
		}
		groups[r] = append(groups[r], us[i])
	}
	var out [][]PathIn
	for _, r := range order {
		if len(groups[r]) >= 2 {
			out = append(out, groups[r])
		}
	}
	return out
}

func (sharedPathCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, cl := range clusters(in.Paths) {
		insts, paths := instancesOf(cl), pathsOf(cl)
		custom := false
		inRoots := true
		for _, u := range cl {
			custom = custom || u.Source == SourceCustomOverride
			inRoots = inRoots && underRoots(u.HostPath, in.BindRoots)
		}
		var title string
		switch {
		case len(insts) == 1:
			title = fmt.Sprintf("%s uses %s in %d places.", insts[0], joinAnd(quoted(paths)), len(cl))
		case len(paths) == 1 && len(insts) == 2:
			title = fmt.Sprintf("%s both use `%s`.", joinAnd(insts), paths[0])
		case len(paths) == 1:
			title = fmt.Sprintf("%s all use `%s`.", joinAnd(insts), paths[0])
		default:
			title = fmt.Sprintf("%s use nested paths: %s.", joinAnd(insts), joinAnd(quoted(paths)))
		}
		var hows []string
		for _, u := range cl {
			hows = append(hows, how(u))
		}
		f := Finding{
			FP: Fingerprint(KindSharedPath, paths...), Kind: KindSharedPath, Severity: Warning, Title: title,
			Why: "Apps that share a directory but disagree on ownership can't read or write each other's files: " +
				strings.Join(hows, "; ") + ".",
			Instances: insts, Paths: paths, Inputs: Digest(cl),
		}
		if len(paths) == 1 && inRoots && !custom {
			f.Class, f.FixKind = FixOneClick, FixManageAsFolder
			f.Fix = fmt.Sprintf("Manage `%s` as a shared folder: one group for every app that uses it, setgid directories and default ACLs, so new files stay readable and writable for all of them (previewed first).", paths[0])
		} else {
			f.Class = FixExplain
			switch {
			case len(paths) > 1:
				f.Steps = append(f.Steps, stepOneFolder)
			case !inRoots:
				f.Steps = append(f.Steps, "Move the data under one of the Hub's bind roots ("+strings.Join(in.BindRoots, ", ")+"), then manage it as a shared folder.")
			}
			if custom {
				f.Steps = append(f.Steps, stepCustomOverride)
			}
			if len(f.Steps) == 0 {
				f.Steps = append(f.Steps, stepOneFolder)
			}
		}
		out = append(out, f)
	}
	return out
}

// ── path_outside_roots ──────────────────────────────────

type pathOutsideRootsCheck struct{}

func (pathOutsideRootsCheck) Kind() string { return KindPathOutsideRoots }

func (pathOutsideRootsCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, u := range sortedUses(in.Paths) {
		if u.Source != SourceSetting || u.HostPath == "" || underRoots(u.HostPath, in.BindRoots) {
			continue
		}
		p := path.Clean(u.HostPath)
		out = append(out, Finding{
			FP: Fingerprint(KindPathOutsideRoots, useID(u)), Kind: KindPathOutsideRoots, Severity: Warning,
			Title:     fmt.Sprintf("%s (`%s`) is outside the bind roots.", useName(u), p),
			Why:       "The Hub manages and scans only host paths under its bind roots (" + strings.Join(in.BindRoots, ", ") + "): it can't check or fix the ownership of this one.",
			Class:     FixExplain,
			Steps:     []string{"Move the data under one of the bind roots and point the setting at it, or add its parent to HUB_OVERRIDE_BIND_ROOTS in core's configuration."},
			Instances: []string{u.Instance}, Paths: []string{p}, Inputs: Digest([]string{u.HostPath, u.Access}),
		})
	}
	return out
}

// ── undeclared_template ─────────────────────────────────

type undeclaredTemplateCheck struct{}

func (undeclaredTemplateCheck) Kind() string { return KindUndeclaredTemplate }

func (undeclaredTemplateCheck) Run(in *Inputs) []Finding {
	fs := folderByID(in)
	var out []Finding
	for _, u := range sortedUses(in.Paths) {
		if u.Source != SourceFolder || u.Declared {
			continue
		}
		out = append(out, Finding{
			FP: Fingerprint(KindUndeclaredTemplate, useID(u), u.Folder), Kind: KindUndeclaredTemplate, Severity: Info,
			Title:     fmt.Sprintf("%s uses shared folder %s; this template doesn't say how it writes.", useName(u), folderName(fs, u.Folder)),
			Why:       "Without a folder block the Hub mounts the folder read-only unless you confirmed writes, and can't tell which uid the app runs as; the folder's group still makes new files shared.",
			Instances: []string{u.Instance}, Folders: []string{u.Folder}, Paths: []string{path.Clean(u.HostPath)},
			Inputs: Digest([]string{u.Folder, u.Subpath, u.Access}),
		})
	}
	return out
}

// ── primary_gid_conflict ────────────────────────────────

type primaryGIDConflictCheck struct{}

func (primaryGIDConflictCheck) Kind() string { return KindPrimaryGIDConflict }

func (primaryGIDConflictCheck) Run(in *Inputs) []Finding {
	fs := folderByID(in)
	type svc struct{ inst, service, env string }
	groups := map[svc][]PathIn{}
	var order []svc
	for _, u := range sortedUses(in.Paths) {
		if u.GIDEnv == "" || u.Source == SourceCustomOverride {
			continue
		}
		k := svc{u.Instance, u.Service, u.GIDEnv}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], u)
	}
	var out []Finding
	for _, k := range order {
		us := groups[k]
		needs := map[int]bool{}
		var parts []string
		for _, u := range us {
			gid, ok := u.GID, u.OwnerKnown
			if u.Source == SourceFolder && u.JoinsGroup == templates.JoinGIDEnv {
				if f, found := fs[u.Folder]; found {
					gid, ok = f.GID, true
				}
			}
			if !ok {
				continue
			}
			needs[gid] = true
			where := "`" + path.Clean(u.HostPath) + "`"
			if u.Source == SourceFolder {
				where = "shared folder " + folderName(fs, u.Folder)
			}
			parts = append(parts, fmt.Sprintf("%s (%s, gid %d)", useName(u), where, gid))
		}
		if len(needs) < 2 {
			continue
		}
		var gids []string
		for g := range needs {
			gids = append(gids, fmt.Sprint(g))
		}
		sort.Strings(gids)
		var folders []string
		for _, u := range us {
			folders = append(folders, u.Folder)
		}
		out = append(out, Finding{
			FP: Fingerprint(KindPrimaryGIDConflict, k.inst, k.service, k.env), Kind: KindPrimaryGIDConflict, Severity: Problem,
			Title: fmt.Sprintf("%s: service %s's %s would need gids %s.", k.inst, k.service, k.env, joinAnd(gids)),
			Why:   "A process has one primary gid, and " + k.env + " sets it for every path of the service: " + joinAnd(parts) + " can't all get theirs, so one of them can't write.",
			Class: FixExplain,
			Steps: []string{"Point these settings at the same shared folder (each with its own subpath), so one gid serves them all (Settings → Shared folders).",
				"Or move the hand-typed directories' group to the same gid on the host."},
			Instances: []string{k.inst}, Folders: uniq(folders...), Paths: pathsOf(us), Inputs: Digest(us),
		})
	}
	return out
}

// ── custom_override_mount ───────────────────────────────

type customOverrideMountCheck struct{}

func (customOverrideMountCheck) Kind() string { return KindCustomOverrideMount }

func (customOverrideMountCheck) Run(in *Inputs) []Finding {
	us := sortedUses(in.Paths)
	var out []Finding
	for _, u := range us {
		if u.Source != SourceCustomOverride || u.HostPath == "" {
			continue
		}
		var others []PathIn
		for _, o := range us {
			if useID(o) != useID(u) && o.HostPath != "" && near(u.HostPath, o.HostPath) {
				others = append(others, o)
			}
		}
		if len(others) == 0 {
			continue
		}
		var names, folders []string
		for _, o := range others {
			names = append(names, useName(o))
			folders = append(folders, o.Folder)
		}
		all := append([]PathIn{u}, others...)
		p := path.Clean(u.HostPath)
		out = append(out, Finding{
			FP: Fingerprint(KindCustomOverrideMount, useID(u), p), Kind: KindCustomOverrideMount, Severity: Warning,
			Title:     fmt.Sprintf("%s's custom override mounts `%s`, which %s also uses.", u.Instance, p, joinAnd(names)),
			Why:       "The Hub never changes the custom override: it can't add the folder's group to that mount, so the app there writes files the others may not read or write.",
			Class:     FixExplain,
			Steps:     []string{stepCustomOverride, "Apply the shared folder's assignment, so every app joins its group."},
			Instances: instancesOf(all), Folders: uniq(folders...), Paths: pathsOf(all), Inputs: Digest(all),
		})
	}
	return out
}

// ── must_own_conflict ───────────────────────────────────

type mustOwnConflictCheck struct{}

func (mustOwnConflictCheck) Kind() string { return KindMustOwnConflict }

func (mustOwnConflictCheck) Run(in *Inputs) []Finding {
	fs := folderByID(in)
	groups := map[string][]PathIn{}
	var order []string
	for _, u := range sortedUses(in.Paths) {
		if !u.MustOwn {
			continue
		}
		k := "path:" + path.Clean(u.HostPath)
		if u.Folder != "" {
			k = "folder:" + u.Folder
		}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], u)
	}
	var out []Finding
	for _, k := range order {
		us := groups[k]
		if len(us) < 2 {
			continue
		}
		what, folders := "`"+strings.TrimPrefix(k, "path:")+"`", []string(nil)
		if strings.HasPrefix(k, "folder:") {
			id := strings.TrimPrefix(k, "folder:")
			what, folders = "shared folder "+folderName(fs, id), []string{id}
		}
		var names []string
		for _, u := range us {
			names = append(names, useName(u))
		}
		out = append(out, Finding{
			FP: Fingerprint(KindMustOwnConflict, k), Kind: KindMustOwnConflict, Severity: Problem,
			Title:     fmt.Sprintf("%s both must own %s.", joinAnd(names), what),
			Why:       "Each of these apps needs to own every file it writes there; only one owner is possible, so one of them breaks.",
			Class:     FixExplain,
			Steps:     []string{"Give each app its own directory (another shared folder, or a separate subpath it alone uses)."},
			Instances: instancesOf(us), Folders: folders, Paths: pathsOf(us), Inputs: Digest(us),
		})
	}
	return out
}

// ── exclusive ───────────────────────────────────────────

type exclusiveCheck struct{}

func (exclusiveCheck) Kind() string { return KindExclusive }

// exclusiveReason is u's exclusive check reason (ok false: none).
func exclusiveReason(u PathIn) (string, bool) {
	for _, c := range u.Checks {
		if c.Kind == templates.CheckExclusive {
			return c.Reason, true
		}
	}
	return "", false
}

func (exclusiveCheck) Run(in *Inputs) []Finding {
	fs := folderByID(in)
	us := sortedUses(in.Paths)
	var out []Finding
	for _, u := range us {
		reason, ok := exclusiveReason(u)
		if !ok || !u.Writes {
			continue
		}
		var others []PathIn
		for _, o := range us {
			if o.Instance == u.Instance || !o.Writes || o.HostPath == "" {
				continue
			}
			if (u.Folder != "" && o.Folder == u.Folder) || near(u.HostPath, o.HostPath) {
				others = append(others, o)
			}
		}
		if len(others) == 0 {
			continue
		}
		target, what := "path:"+path.Clean(u.HostPath), "`"+path.Clean(u.HostPath)+"`"
		var folders []string
		if u.Folder != "" {
			target, what, folders = "folder:"+u.Folder, "shared folder "+folderName(fs, u.Folder), []string{u.Folder}
		}
		var names []string
		for _, o := range others {
			names = append(names, useName(o))
			folders = append(folders, o.Folder)
		}
		all := append([]PathIn{u}, others...)
		why := useName(u) + " must be the only writer there"
		if reason != "" {
			why += ": " + reason
		}
		out = append(out, Finding{
			FP: Fingerprint(KindExclusive, useID(u), target), Kind: KindExclusive, Severity: Problem,
			Title:     fmt.Sprintf("%s also writes %s, which %s needs for itself.", joinAnd(names), what, useName(u)),
			Why:       why + ".",
			Class:     FixExplain,
			Steps:     []string{"Give " + u.Instance + " its own directory (another shared folder or a subpath nobody else writes), or make the other apps read only."},
			Instances: instancesOf(all), Folders: uniq(folders...), Paths: pathsOf(all), Inputs: Digest(all),
		})
	}
	return out
}

// ── gid_collision ───────────────────────────────────────

type gidCollisionCheck struct{}

func (gidCollisionCheck) Kind() string { return KindGIDCollision }

// Run judges the gids the Hub resolves statically (runs_as / writes_as,
// the folder gids it group_adds). Root containers, an image's USER and
// PGID-style env images are outside it: the runtime check (the Groups:
// line of a running container's /proc/1/status) is Task 11's.
func (gidCollisionCheck) Run(in *Inputs) []Finding {
	gidOwner := map[int]FolderIn{}
	for _, f := range in.Folders {
		gidOwner[f.GID] = f
	}
	type st struct {
		gids     map[int]bool
		assigned map[string]bool
		uses     []PathIn
	}
	per := map[string]*st{}
	var order []string
	for _, u := range sortedUses(in.Paths) {
		s := per[u.Instance]
		if s == nil {
			s = &st{gids: map[int]bool{}, assigned: map[string]bool{}}
			per[u.Instance] = s
			order = append(order, u.Instance)
		}
		s.uses = append(s.uses, u)
		if u.Folder != "" {
			s.assigned[u.Folder] = true
		}
		if u.OwnerKnown {
			s.gids[u.GID] = true
		}
		for _, g := range u.GIDs {
			s.gids[g] = true
		}
	}
	sort.Strings(order)
	var out []Finding
	for _, inst := range order {
		s := per[inst]
		var gids []int
		for g := range s.gids {
			gids = append(gids, g)
		}
		sort.Ints(gids)
		for _, g := range gids {
			f, ok := gidOwner[g]
			if !ok || s.assigned[f.ID] {
				continue
			}
			out = append(out, Finding{
				FP: Fingerprint(KindGIDCollision, inst, f.ID), Kind: KindGIDCollision, Severity: Problem,
				Title: fmt.Sprintf("%s runs with gid %d, the group of shared folder %s.", inst, g, f.Name),
				Why:   fmt.Sprintf("Anything mounted with gid %d is reachable through that group: %s reaches shared folder %s's files without being assigned to it.", g, inst, f.Name),
				Class: FixExplain,
				Steps: []string{fmt.Sprintf("Change %s's group setting to another gid.", inst),
					fmt.Sprintf("Or assign %s to shared folder %s (Settings → Shared folders), if it should use it.", inst, f.Name)},
				Instances: []string{inst}, Folders: []string{f.ID}, Paths: []string{f.Path},
				Inputs: Digest([]any{g, f.ID, s.uses}),
			})
		}
	}
	return out
}

// ── folder_changed ──────────────────────────────────────

type folderChangedCheck struct{}

func (folderChangedCheck) Kind() string { return KindFolderChanged }

func (folderChangedCheck) Run(in *Inputs) []Finding {
	fs := folderByID(in)
	cs := append([]ChangeIn(nil), in.Changes...)
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Instance != cs[j].Instance {
			return cs[i].Instance < cs[j].Instance
		}
		return cs[i].Key < cs[j].Key
	})
	var out []Finding
	for _, c := range cs {
		name := folderName(fs, c.Folder)
		var paths []string
		if f, ok := fs[c.Folder]; ok {
			paths = []string{path.Join(f.Path, c.Subpath)}
		}
		where := name
		if len(paths) == 1 {
			where = "`" + paths[0] + "`"
		}
		out = append(out, Finding{
			FP: Fingerprint(KindFolderChanged, c.Instance, c.Key, c.Folder), Kind: KindFolderChanged, Severity: Problem,
			Title: fmt.Sprintf("%s: shared folder %s changed on disk.", c.Instance, name),
			Why:   fmt.Sprintf("The probe around %s's last start found: %s. A directory swapped for a symlink would let an app reach other host paths, so the Hub keeps %s down until the folder is right again.", c.Instance, c.Detail, c.Instance),
			Class: FixExplain,
			Steps: []string{"On the host, check what replaced " + where + " and put the real directory back (no symlink).",
				"Re-apply the folder's assignment (Settings → Shared folders), then enable " + c.Instance + " again."},
			Instances: []string{c.Instance}, Folders: []string{c.Folder}, Paths: paths,
			Inputs: Digest(c),
		})
	}
	return out
}

// ── folder_reachable_above (H4) ─────────────────────────

// Reach is a service that holds folder f's gid (Use: one of its uses of
// f) and also mounts Above, a host path at or above f's path.
type Reach struct {
	Use, Above PathIn
}

// ReachedAbove lists, for every service with a use of folder f in
// paths, that service's other mounts (a setting's host path, a custom
// override's bind, another folder's value) at or above f's path: the
// service gets the folder's gid, and directories are group-writable
// (contract §14.2), so through that mount it creates, renames and
// deletes in every folder directory whatever its own use declares.
// Sorted by instance, service, then the mount's host path.
func ReachedAbove(f FolderIn, paths []PathIn) []Reach {
	root := path.Clean(f.Path)
	type svc struct{ inst, name string }
	uses := map[svc]PathIn{}
	for _, u := range sortedUses(paths) {
		k := svc{u.Instance, u.Service}
		if _, seen := uses[k]; u.Folder == f.ID && u.Source == SourceFolder && !seen {
			uses[k] = u
		}
	}
	var out []Reach
	for _, o := range sortedUses(paths) {
		u, ok := uses[svc{o.Instance, o.Service}]
		if !ok || o.HostPath == "" || (o.Source == SourceFolder && o.Folder == f.ID) || !strings.HasPrefix(o.HostPath, "/") {
			continue
		}
		if under(root, path.Clean(o.HostPath)) {
			out = append(out, Reach{Use: u, Above: o})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Use.Instance != b.Use.Instance {
			return a.Use.Instance < b.Use.Instance
		}
		if a.Use.Service != b.Use.Service {
			return a.Use.Service < b.Use.Service
		}
		return path.Clean(a.Above.HostPath) < path.Clean(b.Above.HostPath)
	})
	return out
}

// ReachName is how a mount above a folder is named: "`/srv` (immich's
// Extra)".
func ReachName(o PathIn) string {
	return "`" + path.Clean(o.HostPath) + "` (" + useName(o) + ")"
}

type folderReachableAboveCheck struct{}

func (folderReachableAboveCheck) Kind() string { return KindFolderReachAbove }

func (folderReachableAboveCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, f := range in.Folders {
		reach := ReachedAbove(f, in.Paths)
		for i := 0; i < len(reach); {
			j := i
			for j < len(reach) && reach[j].Use.Instance == reach[i].Use.Instance && reach[j].Use.Service == reach[i].Use.Service {
				j++
			}
			grp := reach[i:j]
			i = j
			u := grp[0].Use
			var names []string
			all := []PathIn{u}
			for _, r := range grp {
				names = append(names, ReachName(r.Above))
				all = append(all, r.Above)
			}
			var paths []string
			for _, r := range grp {
				paths = append(paths, path.Clean(r.Above.HostPath))
			}
			out = append(out, Finding{
				FP: Fingerprint(KindFolderReachAbove, u.Instance, u.Service, f.ID), Kind: KindFolderReachAbove, Severity: Problem,
				Title: fmt.Sprintf("%s's service %s reaches all of shared folder %s through %s.", u.Instance, u.Service, f.Name, joinAnd(names)),
				Why: fmt.Sprintf("%s holds the folder's group (gid %d) for %s, and also mounts a directory at or above `%s`. Folder directories are group-writable, so through that mount it can create, rename and delete anywhere in the folder, whatever access its own use declares.",
					u.Service, f.GID, useName(u), path.Clean(f.Path)),
				Class: FixExplain,
				Steps: []string{
					fmt.Sprintf("Remove the mount of %s from %s, or point it at a directory outside the shared folder (Settings, or the custom override in the Expert tab).", joinAnd(names), u.Instance),
					fmt.Sprintf("Or unassign %s from shared folder %s (Settings → Shared folders).", u.Instance, f.Name),
				},
				Instances: []string{u.Instance}, Folders: []string{f.ID}, Paths: uniq(paths...),
				Inputs: Digest([]any{f.ID, f.Path, f.GID, all}),
			})
		}
	}
	return out
}
