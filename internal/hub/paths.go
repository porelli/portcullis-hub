package hub

import (
	"log"
	"sort"

	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// PathUsage sources.
const (
	PathSourceSetting        = "setting"         // a host path typed in Settings
	PathSourceFolder         = "folder"          // a shared folder value (folder:<id>[/<sub>])
	PathSourceCustomOverride = "custom_override" // a bind mount of the custom override (Expert)
)

// PathUsage is one host directory an enabled instance mounts: through a
// path option (a host path or a shared folder) or the custom override.
// Where, into which service and mount, how (mode, needs, access) and as
// whom it writes: a folder block's runs_as (an _env resolved through its
// option, settings.ResolveRunsAs), else writes_as (settings.ResolveOwner);
// OwnerKnown false = not declared or not resolvable.
type PathUsage struct {
	Instance string `json:"instance"`
	Key      string `json:"key"`   // "" for a custom-override mount
	Label    string `json:"label"` // the option's label
	Type     string `json:"type"`  // the option's type; "bind" for the custom override
	HostPath string `json:"host_path"`
	Service  string `json:"service"`
	Mount    string `json:"mount"`
	Mode     string `json:"mode"` // ro | rw: how it is mounted
	Needs    string `json:"needs,omitempty"`
	// Access is what the app does there: the folder block's access; for a
	// folder value without a block "read" unless the write was confirmed;
	// for a host path needs, else write when mounted rw.
	Access   string `json:"access,omitempty"`
	ReadOnly bool   `json:"read_only"`
	Writes   bool   `json:"writes"` // Access write and mounted rw
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	// UIDEnv / GIDEnv: the folder block's runs_as env names.
	UIDEnv     string `json:"uid_env,omitempty"`
	GIDEnv     string `json:"gid_env,omitempty"`
	OwnerKnown bool   `json:"owner_known"`
	// Folder / Subpath: the shared folder a folder value names.
	Folder  string `json:"folder,omitempty"`
	Subpath string `json:"subpath,omitempty"`
	// JoinsGroup: how the app joins the folder's group (the block's, or
	// group_add for a folder value without one).
	JoinsGroup string `json:"joins_group,omitempty"`
	Source     string `json:"source"` // PathSource*
	MustOwn    bool   `json:"must_own"`
	Declared   bool   `json:"declared"` // the option has a folder block
	// GIDs: the supplementary gids the Hub gives the service (folder gids
	// under group_add).
	GIDs   []int             `json:"gids,omitempty"`
	Checks []templates.Check `json:"checks,omitempty"`
	// PersonTree: a per-person tree (folder.runs_as gid_from, F34): each
	// person's directory has their own owner (OwnerKnown false); never a
	// shared folder, no folder gid, never a shared_path or folder_owner
	// subject; the doctor scans its top level (doctorscan.go).
	PersonTree bool `json:"person_tree,omitempty"`
}

// PathUsages lists every enabled instance's mounted host directories:
// each path option with a value (the template's option order), then the
// custom override's bind mounts; sorted by instance. A value that no
// longer resolves is left out (logged).
func (h *Hub) PathUsages() []PathUsage {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pathUsagesLocked()
}

// pathUsagesLocked is PathUsages for a caller holding mu (read or write).
func (h *Hub) pathUsagesLocked() []PathUsage { return h.pathUsagesIn(h.liveView()) }

// pathUsagesIn is PathUsages over view v (its settings and folders; the
// live state or a planned copy, folderrender.go renderView): it reads v,
// the templates, enabled flags and custom overrides, never changes
// anything. Caller holds mu (read).
func (h *Hub) pathUsagesIn(v renderView) []PathUsage {
	out := []PathUsage{}
	for i := range h.instances {
		t := &h.instances[i]
		if !h.st.IsEnabled(t.ID) {
			continue
		}
		out = append(out, h.instanceUsagesIn(v, t)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

// instanceUsagesIn are instance t's usages over view v, enabled or not:
// each path option with a value (option order), then the custom
// override's bind mounts. Caller holds mu (read).
func (h *Hub) instanceUsagesIn(v renderView, t *templates.Template) []PathUsage {
	s := v.settings[t.ID]
	var values map[string]settings.Value
	valuesOf := func() map[string]settings.Value {
		if values == nil {
			values = h.instanceValuesLocked(t, s)
		}
		return values
	}
	var mounts []*folderMount
	gidEnv := h.folderGIDEnvIn(v, t, s)
	var used []PathUsage
	for _, o := range mountOptions(t) {
		val, ok := h.effectiveValue(t, o, s)
		if !ok {
			continue
		}
		u, fm, err := h.pathUsageIn(v, t, o, val, valuesOf, gidEnv)
		if err != nil {
			log.Printf("settings: %s: %s: %v", t.ID, o.Key, err)
			continue
		}
		if fm != nil {
			mounts = append(mounts, fm)
		}
		used = append(used, u)
	}
	groups := folderGroupAdd(mounts)
	for j := range used {
		if g := groups[used[j].Service]; len(g) > 0 {
			used[j].GIDs = append([]int(nil), g...)
		}
	}
	return append(used, h.customMountsLocked(t)...)
}

// pathUsageIn is option o's usage with value v over view rv (fm: its
// folder mount, nil for a host path). Caller must hold mu.
func (h *Hub) pathUsageIn(rv renderView, t *templates.Template, o *templates.Option, v any, values func() map[string]settings.Value, gidEnv map[string]int) (PathUsage, *folderMount, error) {
	u := PathUsage{Instance: t.ID, Key: o.Key, Label: o.Label, Type: o.Type, Service: o.Target.Service, Mount: o.Target.Mount,
		Needs: o.Needs, Source: PathSourceSetting, Declared: o.Folder != nil, Checks: o.Checks, PersonTree: settings.PerPersonTree(o)}
	fm, err := h.folderMountIn(rv, t, o, v)
	if err != nil {
		return u, nil, err
	}
	if fm != nil {
		u.HostPath, u.Folder, u.Subpath, u.Source, u.ReadOnly = fm.host, fm.id, fm.sub, PathSourceFolder, fm.readOnly
		u.JoinsGroup, u.Access = templates.JoinGroupAdd, templates.FolderRead
		if !fm.readOnly {
			u.Access = templates.FolderWrite
		}
	} else {
		host, err := h.mountSourceLocked(o, v)
		if err != nil {
			return u, nil, err
		}
		u.HostPath, u.ReadOnly = host, o.EffectiveMode() == "ro"
		switch {
		case o.Needs != "":
			u.Access = o.Needs
		case u.ReadOnly:
			u.Access = templates.FolderRead
		default:
			u.Access = templates.FolderWrite
		}
	}
	if f := o.Folder; f != nil {
		u.Access, u.Needs, u.JoinsGroup, u.MustOwn = f.Access, f.Access, f.Join(), f.MustOwn
		if f.RunsAs != nil {
			u.UIDEnv, u.GIDEnv = f.RunsAs.UIDEnv, f.RunsAs.GIDEnv
		}
		if uid, gid, err := settings.ResolveRunsAs(o, t.Manifest.Options(), values()); err == nil {
			u.UID, u.GID, u.OwnerKnown = uid, gid, true
			// A gid_env join: the process's primary gid is the folder's.
			if fm != nil && f.Join() == templates.JoinGIDEnv {
				if g, ok := gidEnv[f.RunsAs.GIDEnv]; ok {
					u.GID = g
				}
			}
		}
	} else if o.WritesAs != nil {
		if uid, gid, err := settings.ResolveOwner(o, values()); err == nil {
			u.UID, u.GID, u.OwnerKnown = uid, gid, true
		}
	}
	u.Mode = "rw"
	if u.ReadOnly {
		u.Mode = "ro"
	}
	u.Writes = u.Access == templates.FolderWrite && !u.ReadOnly
	return u, fm, nil
}
