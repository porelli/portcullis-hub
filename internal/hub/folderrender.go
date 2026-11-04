package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Shared folders in an instance's rendering (contract §13.15, §14.2;
// Task 7): the bind mounts of folder values, the folder's group, the
// folder variables, the settings-save refusals and the probes around an
// up.

// folderRefOf parses v as a folder value (ok false: not one).
func folderRefOf(v any) (id, sub string, ok bool, err error) {
	str, isStr := v.(string)
	if !isStr {
		return "", "", false, nil
	}
	return settings.ParseFolderRef(str)
}

// folderReadOnly: o's mount of folder f is read-only in instance's
// option key — always for folder.access read (and a mode: ro), and for
// a template without a folder block unless the admin confirmed write for
// exactly this instance and option (WriteConfirmed["<instance>/<key>"]).
func folderReadOnly(o *templates.Option, f *state.Folder, instance, key string) bool {
	if o.Folder != nil {
		return o.Folder.Access != templates.FolderWrite
	}
	if o.Mode == "ro" {
		return true
	}
	return f == nil || !f.WriteConfirmed[instance+"/"+key]
}

// joinsByGroupAdd: the Hub adds the folder gid to o's target service
// (joins_group group_add, the default, and options without a folder
// block).
func joinsByGroupAdd(o *templates.Option) bool {
	return o.Folder == nil || o.Folder.Join() == templates.JoinGroupAdd
}

// folderMount is one folder value of an instance's path option.
type folderMount struct {
	o        *templates.Option
	id, sub  string
	folder   state.Folder
	host     string // the folder's path (+ /sub)
	readOnly bool
}

// folderMountLocked resolves o's folder value v for instance t: the
// folder must be defined (state) and its host path resolve through
// h.folders. Caller must hold mu.
func (h *Hub) folderMountLocked(t *templates.Template, o *templates.Option, v any) (*folderMount, error) {
	id, sub, ok, err := folderRefOf(v)
	if !ok {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f, defined := h.st.Folders[id]
	if !defined {
		return nil, fmt.Errorf("no shared folder %q", id)
	}
	host, err := folderHostPath(h.folders, v.(string))
	if err != nil {
		return nil, err
	}
	return &folderMount{o: o, id: id, sub: sub, folder: f, host: host, readOnly: folderReadOnly(o, &f, t.ID, o.Key)}, nil
}

// mountOptions are t's options the override mounts (instance-scope paths
// with a target).
func mountOptions(t *templates.Template) []*templates.Option {
	var out []*templates.Option
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.Type == templates.TypePath && o.EffectiveScope() == templates.ScopeInstance && o.Target != nil && o.Target.Mount != "" {
			out = append(out, o)
		}
	}
	return out
}

// folderMountsLocked are t's folder values (in option order). A value
// that doesn't resolve is an error naming the option. Caller must hold
// mu.
func (h *Hub) folderMountsLocked(t *templates.Template, s state.InstanceSettings) ([]*folderMount, error) {
	var out []*folderMount
	for _, o := range mountOptions(t) {
		v, ok := h.effectiveValue(t, o, s)
		if !ok {
			continue
		}
		fm, err := h.folderMountLocked(t, o, v)
		if err != nil {
			return nil, fmt.Errorf("setting %s: %w", o.Key, err)
		}
		if fm != nil {
			out = append(out, fm)
		}
	}
	return out, nil
}

// folderGroupAdd is, per service, the folder gids the Hub adds as
// supplementary groups (sorted, once each): only the folders the
// instance mounts, through options that join by group_add.
func folderGroupAdd(mounts []*folderMount) map[string][]int {
	out := map[string][]int{}
	for _, fm := range mounts {
		if !joinsByGroupAdd(fm.o) {
			continue
		}
		svc := fm.o.Target.Service
		if !slices.Contains(out[svc], fm.folder.GID) {
			out[svc] = append(out[svc], fm.folder.GID)
		}
	}
	for svc := range out {
		slices.Sort(out[svc])
	}
	return out
}

// folderBindEntry is a folder mount in compose's long syntax (the lines
// after "- "; continuation lines indented for a service's volumes list):
// a missing source fails the up instead of Docker creating it.
func folderBindEntry(fm *folderMount) string {
	return "type: bind\n" +
		"        source: " + yamlQuote(composeLiteral(fm.host)) + "\n" +
		"        target: " + yamlQuote(fm.o.Target.Mount) + "\n" +
		"        read_only: " + strconv.FormatBool(fm.readOnly) + "\n" +
		"        bind:\n" +
		"          create_host_path: false"
}

// folderGIDEnvLocked are the env variables a gid_env join sets to the
// folder gid (env name → gid) for t's folder values. Caller must hold mu.
func (h *Hub) folderGIDEnvLocked(t *templates.Template, s state.InstanceSettings) map[string]int {
	out := map[string]int{}
	for _, o := range mountOptions(t) {
		if o.Folder == nil || o.Folder.Join() != templates.JoinGIDEnv || o.Folder.RunsAs == nil || o.Folder.RunsAs.GIDEnv == "" {
			continue
		}
		v, ok := h.effectiveValue(t, o, s)
		if !ok {
			continue
		}
		if id, _, isRef, err := folderRefOf(v); isRef && err == nil {
			if f, defined := h.st.Folders[id]; defined {
				out[o.Folder.RunsAs.GIDEnv] = f.GID
			}
		}
	}
	return out
}

// mustOwnUIDLocked is the uid of folder id's must_own use (an instance
// whose option with must_own names the folder, its runs_as uid resolved),
// the first by instance id; ok false: none. Caller must hold mu.
func (h *Hub) mustOwnUIDLocked(id string) (int, bool) {
	insts := make([]string, 0, len(h.st.Settings))
	for inst := range h.st.Settings {
		insts = append(insts, inst)
	}
	sort.Strings(insts)
	for _, inst := range insts {
		t := h.findLocked(inst)
		if t == nil {
			continue
		}
		s := h.st.Settings[inst]
		var values map[string]settings.Value
		for _, o := range mountOptions(t) {
			if o.Folder == nil || !o.Folder.MustOwn {
				continue
			}
			v, ok := h.effectiveValue(t, o, s)
			if !ok {
				continue
			}
			if ref, _, isRef, err := folderRefOf(v); !isRef || err != nil || ref != id {
				continue
			}
			if values == nil {
				values = h.instanceValuesLocked(t, s)
			}
			uid, _, err := settings.ResolveRunsAs(o, t.Manifest.Options(), values)
			if err != nil {
				log.Printf("settings: %s: %s: must_own uid: %v", inst, o.Key, err)
				continue
			}
			return uid, true
		}
	}
	return 0, false
}

// folderEnvLocked is what the folders write into t's .env (contract
// §13.15): for every path option PORTCULLIS_FOLDER_GID_<KEY> (the folder
// gid when the value is a folder value, else empty) and
// PORTCULLIS_FOLDER_UID_<KEY> (the folder's must_own uid, else empty),
// plus each gid_env join's variable set to the folder gid. optionEnvLocked
// adds it last, so every .env writer carries it and gid_env wins over
// the option's stored value. Caller must hold mu.
func (h *Hub) folderEnvLocked(t *templates.Template) map[string]string {
	s := h.st.Settings[t.ID]
	out := map[string]string{}
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.Type != templates.TypePath || o.EffectiveScope() != templates.ScopeInstance {
			continue
		}
		gidVar, uidVar := templates.FolderGIDVar(o.Key), templates.FolderUIDVar(o.Key)
		out[gidVar], out[uidVar] = "", ""
		v, ok := h.effectiveValue(t, o, s)
		if !ok {
			continue
		}
		id, _, isRef, err := folderRefOf(v)
		if !isRef || err != nil {
			continue
		}
		f, defined := h.st.Folders[id]
		if !defined {
			continue
		}
		out[gidVar] = strconv.Itoa(f.GID)
		if uid, ok := h.mustOwnUIDLocked(id); ok {
			out[uidVar] = strconv.Itoa(uid)
		}
	}
	for name, gid := range h.folderGIDEnvLocked(t, s) {
		out[name] = strconv.Itoa(gid)
	}
	return out
}

// ── the folder gid range (preflight ruling 30) ───────────

// errGIDReserved is the refusal of a folder-range gid.
const errGIDReserved = "gid 60000–60999 is reserved for shared folder groups"

// idNumber reads a canonical value as a whole number (an int, or a
// string holding one: writes_as may name a string option).
func idNumber(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		return int64(x), x == float64(int64(x))
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// gidRefsOf is templates.GIDRefs for t (nil when its compose doesn't
// parse: Discover refused such a template already).
func gidRefsOf(t *templates.Template) map[string]string {
	refs, err := templates.GIDRefs(&t.Manifest, t.ReadCompose())
	if err != nil {
		log.Printf("settings: %s: gid references: %v", t.ID, err)
		return nil
	}
	return refs
}

// gidOverridden: option o's env is written with a folder gid (a gid_env
// join), so its own value never reaches the app.
func gidOverridden(o *templates.Option, overrides map[string]int) bool {
	for _, n := range o.EnvNames() {
		if _, ok := overrides[n]; ok {
			return true
		}
	}
	return false
}

// gidRangeProblemsLocked are t's options a gid reference names whose
// effective value is in 60000–60999 and isn't replaced by a folder
// assignment (render time: a restore or an edited state.yaml put it
// there). Sorted by key. Caller must hold mu.
func (h *Hub) gidRangeProblemsLocked(t *templates.Template, s state.InstanceSettings) []string {
	refs := gidRefsOf(t)
	if len(refs) == 0 {
		return nil
	}
	overrides := h.folderGIDEnvLocked(t, s)
	var out []string
	for key := range refs {
		o := optionByKey(t, key)
		if o == nil || gidOverridden(o, overrides) {
			continue
		}
		v, ok := h.effectiveValue(t, o, s)
		if !ok {
			continue
		}
		if n, ok := idNumber(v); ok && templates.InFolderGIDRange(n) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// gidRangeRenderErr refuses (409) rendering t while a gid reference's
// value is in the folder range. Caller must hold mu.
func (h *Hub) gidRangeRenderErr(t *templates.Template, s state.InstanceSettings) error {
	keys := h.gidRangeProblemsLocked(t, s)
	if len(keys) == 0 {
		return nil
	}
	refs := gidRefsOf(t)
	return statusErr(http.StatusConflict, "setting %s (%s): %s — change it in Settings", keys[0], refs[keys[0]], errGIDReserved)
}

// ── settings saves (contract §13.15 "Settings saves") ────

// folderSaveCheck refuses (409) what a settings save or its preview may
// not change (preflight ruling 18; restores don't call it): a folder
// value, replacing or clearing one, and an option a folder writes through
// gid_env. cur is the instance's stored settings, folders the folder
// definitions (a copy, or state under mu).
func folderSaveCheck(t *templates.Template, cur state.InstanceSettings, folders map[string]state.Folder, u SettingsUpdate) error {
	keys := make([]string, 0, len(u.Values))
	for k := range u.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		o := optionByKey(t, k)
		if o == nil || o.Type != templates.TypePath {
			continue
		}
		raw, err := decodeRaw(u.Values[k])
		if err != nil {
			continue // parseSettings refuses it
		}
		if _, _, isRef, _ := folderRefOf(raw); isRef {
			return statusErr(http.StatusConflict, "setting %s: a shared folder value can't be set here: assign through Settings → Shared folders", k)
		}
		if id, _, isRef, _ := folderRefOf(cur.Values[k]); isRef {
			return statusErr(http.StatusConflict, "setting %s uses shared folder %s: assign through Settings → Shared folders", k, id)
		}
	}
	opts := t.Manifest.Options()
	for i := range opts {
		o := &opts[i]
		if o.Folder == nil || o.Folder.Join() != templates.JoinGIDEnv || o.Folder.RunsAs == nil {
			continue
		}
		id, _, isRef, err := folderRefOf(cur.Values[o.Key])
		if !isRef || err != nil {
			continue
		}
		f, defined := folders[id]
		owner := settings.EnvOption(opts, o.Folder.RunsAs.GIDEnv)
		if !defined || owner == nil {
			continue
		}
		if _, changed := u.Values[owner.Key]; changed {
			return statusErr(http.StatusConflict, "setting %s: set by shared folder %s (gid %d)", owner.Key, f.Name, f.GID)
		}
	}
	return nil
}

// gidRangeSaveCheck refuses (409) an admin-entered value in 60000–60999
// for an option a gid reference names (ruling 30; uid sources aren't).
func gidRangeSaveCheck(t *templates.Template, parsed *parsedSettings) error {
	if parsed == nil || len(parsed.values) == 0 {
		return nil
	}
	refs := gidRefsOf(t)
	keys := make([]string, 0, len(parsed.values))
	for k := range parsed.values {
		if _, ok := refs[k]; ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if n, ok := idNumber(parsed.values[k]); ok && templates.InFolderGIDRange(n) {
			return statusErr(http.StatusConflict, "setting %s (%s): %s (such values come only from a folder assignment)", k, refs[k], errGIDReserved)
		}
	}
	return nil
}

// ── restores ─────────────────────────────────────────────

// dropMissingFolderRefs clears c's values naming a shared folder that
// isn't defined (contract §11.6: restores don't refuse folder values,
// they clear those whose folder is gone) and returns one warning per
// cleared value. Runs before configProblem in both restore paths.
func dropMissingFolderRefs(c *instanceConfig, folders map[string]state.Folder) []string {
	if c.Settings == nil {
		return nil
	}
	missing := func(v any) (string, bool) {
		id, _, isRef, err := folderRefOf(v)
		if !isRef || err != nil {
			return "", false
		}
		_, defined := folders[id]
		return id, !defined
	}
	var out []string
	keys := make([]string, 0, len(c.Settings.Values))
	for k := range c.Settings.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if id, gone := missing(c.Settings.Values[k]); gone {
			delete(c.Settings.Values, k)
			delete(c.Settings.Types, k)
			out = append(out, fmt.Sprintf("setting %s named shared folder %s, which doesn't exist; cleared", k, id))
		}
	}
	return out
}

// isFolderValue: v is a folder value (folder:…).
func isFolderValue(v any) bool {
	_, _, ok, _ := folderRefOf(v)
	return ok
}

// folderDefs is a copy of the folder definitions (for callers outside mu).
func (h *Hub) folderDefs() map[string]state.Folder {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return maps.Clone(h.st.Folders)
}

// restoredFolderWarnings: per folder value a restore into a new id keeps,
// "instance X now uses shared folder Y (setting k, read-only | write as
// declared)" (S12: no assignment preview ran; a write confirmation is
// never copied).
func restoredFolderWarnings(t *templates.Template, newID string, c *instanceConfig, folders map[string]state.Folder) []string {
	if c.Settings == nil {
		return nil
	}
	var out []string
	for _, o := range mountOptions(t) {
		id, _, isRef, err := folderRefOf(c.Settings.Values[o.Key])
		if !isRef || err != nil {
			continue
		}
		f, defined := folders[id]
		if !defined {
			continue
		}
		how := "read-only"
		if o.Folder != nil && o.Folder.Access == templates.FolderWrite {
			how = "write as declared"
		}
		out = append(out, fmt.Sprintf("instance %s now uses shared folder %s (setting %s, %s)", newID, f.Name, o.Key, how))
	}
	return out
}

// ── the probes around an up (ruling 24, R44) ─────────────

// FolderChange is a folder value whose subpath changed on disk while
// its instance started (doctor finding folder_changed, Problem,
// explain-only: Task 9 shows it). Kept in memory until the instance's
// next up passes both probes.
type FolderChange struct {
	Instance string    `json:"instance"`
	Key      string    `json:"key"`
	Folder   string    `json:"folder"`
	Subpath  string    `json:"subpath"`
	At       time.Time `json:"at"`
	Detail   string    `json:"detail"`
}

// FolderChanges lists the recorded folder_changed states (sorted by
// instance, then key).
func (h *Hub) FolderChanges() []FolderChange {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []FolderChange{}
	for _, l := range h.folderChanged {
		out = append(out, l...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Instance != out[j].Instance {
			return out[i].Instance < out[j].Instance
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// folderProbe is one folder value with a subpath to probe around an up.
type folderProbe struct {
	key, folder, name, sub string
	root, rel              string // the bind root and the folder's path below it
	dev, ino               uint64 // the folder root's, as stored
	subDev, subIno         uint64 // the subpath's, from the probe before the up
}

// folderProbesLocked are t's folder values with a subpath (in option
// order). A value that doesn't resolve is an error. Caller must hold mu.
func (h *Hub) folderProbesLocked(t *templates.Template) ([]folderProbe, error) {
	mounts, err := h.folderMountsLocked(t, h.st.Settings[t.ID])
	if err != nil {
		return nil, statusErr(http.StatusConflict, "%v", err)
	}
	var out []folderProbe
	for _, fm := range mounts {
		if fm.sub == "" {
			continue
		}
		root, rel := h.bindRootOf(fm.folder.Path)
		if root == "" || rel == "" {
			return nil, statusErr(http.StatusConflict, "shared folder %s: %s is not under a bind root", fm.folder.Name, fm.folder.Path)
		}
		out = append(out, folderProbe{key: fm.o.Key, folder: fm.id, name: fm.folder.Name, sub: fm.sub,
			root: root, rel: rel, dev: fm.folder.Dev, ino: fm.folder.Ino})
	}
	return out, nil
}

// folderChangedError: a folder changed on disk around an up.
type folderChangedError struct{ name string }

func (e folderChangedError) Error() string {
	return "shared folder " + e.name + " changed on disk: re-apply it"
}

// errFolderChanged is the up's refusal (409) for a folder that changed
// on disk.
func errFolderChanged(name string) error {
	return &StatusError{Status: http.StatusConflict, Err: folderChangedError{name}}
}

// isFolderChanged: err is errFolderChanged's.
func isFolderChanged(err error) bool {
	var fc folderChangedError
	return errors.As(err, &fc)
}

// probeFolders probes each of ps (never under mu): the folder root must
// be the stored device and inode with no symlink on its path, the
// subpath must exist with no symlink component; after the start (after)
// the subpath must also be the device and inode the first probe saw. It
// returns the probe that failed (nil: all passed) and its refusal, with
// what changed as detail.
func (h *Hub) probeFolders(ctx context.Context, ps []folderProbe, after bool) (*folderProbe, string, error) {
	for i := range ps {
		p := &ps[i]
		run := func(rel string) (*folderfix.ProbeReport, error) {
			rep, err := h.runProbe(ctx, fixerRun{Mode: "probe", Folder: p.folder, Source: p.root, Extra: folderfix.ArgsExtra{Rel: rel}})
			var se *StatusError
			if err != nil && errors.As(err, &se) && se.Status == http.StatusConflict {
				return nil, errFolderChanged(p.name)
			}
			return rep, err
		}
		rootRep, err := run(p.rel)
		if err != nil {
			return p, err.Error(), err
		}
		switch {
		case rootRep.Symlink != "":
			return p, rootRep.Symlink + " is a symlink", errFolderChanged(p.name)
		case !rootRep.Exists:
			return p, "the folder is missing", errFolderChanged(p.name)
		case rootRep.Dev != p.dev || rootRep.Ino != p.ino:
			return p, fmt.Sprintf("the folder is another directory (device %d inode %d, stored %d %d)", rootRep.Dev, rootRep.Ino, p.dev, p.ino), errFolderChanged(p.name)
		}
		subRep, err := run(path.Join(p.rel, p.sub))
		if err != nil {
			return p, err.Error(), err
		}
		switch {
		case subRep.Symlink != "":
			return p, subRep.Symlink + " is a symlink", errFolderChanged(p.name)
		case !subRep.Exists && after:
			return p, p.sub + " is gone", errFolderChanged(p.name)
		case !subRep.Exists:
			return p, p.sub + " doesn't exist", statusErr(http.StatusConflict, "shared folder %s: %s doesn't exist yet: apply the folder assignment (Settings → Shared folders)", p.name, p.sub)
		case after && (subRep.Dev != p.subDev || subRep.Ino != p.subIno):
			return p, p.sub + " is another directory than at the start", errFolderChanged(p.name)
		}
		p.subDev, p.subIno = subRep.Dev, subRep.Ino
	}
	return nil, "", nil
}

// recordFolderChange records (or, p nil, clears) instance id's
// folder_changed state.
func (h *Hub) recordFolderChange(id string, p *folderProbe, detail string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p == nil {
		delete(h.folderChanged, id)
		return
	}
	if h.folderChanged == nil {
		h.folderChanged = map[string][]FolderChange{}
	}
	h.folderChanged[id] = []FolderChange{{Instance: id, Key: p.key, Folder: p.folder, Subpath: p.sub, At: time.Now().UTC(), Detail: detail}}
}

// ── path usages ──────────────────────────────────────────

// customMountsLocked are the bind mounts of t's custom override (Expert)
// with an absolute host path, Source "custom_override". An override that
// doesn't validate lists nothing (the up refuses it). Caller must hold mu.
func (h *Hub) customMountsLocked(t *templates.Template) []PathUsage {
	po := h.parsedUserOverride(t)
	if po == nil {
		return nil
	}
	var out []PathUsage
	for _, b := range po.binds {
		mode := "rw"
		if b.ReadOnly {
			mode = "ro"
		}
		out = append(out, PathUsage{Instance: t.ID, Type: "bind", HostPath: b.Source, Service: b.Service, Mount: b.Target,
			Mode: mode, ReadOnly: b.ReadOnly, Source: PathSourceCustomOverride})
	}
	return out
}

// dropWriteConfirmed removes instance id's write confirmations
// ("<id>/<key>") from every folder of folders (in place). Caller must hold
// mu.
func dropWriteConfirmed(folders map[string]state.Folder, id string) {
	for fid, f := range folders {
		changed := false
		for k := range f.WriteConfirmed {
			if strings.HasPrefix(k, id+"/") {
				if !changed {
					f.WriteConfirmed = maps.Clone(f.WriteConfirmed)
					changed = true
				}
				delete(f.WriteConfirmed, k)
			}
		}
		if changed {
			if len(f.WriteConfirmed) == 0 {
				f.WriteConfirmed = nil
			}
			folders[fid] = f
		}
	}
}
