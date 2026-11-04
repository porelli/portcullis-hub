package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/folderfix"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Assigning a shared folder to app instances (contract §14.3) and
// undoing its last fix (§14.4): a preview that changes nothing and
// answers a plan hash, then an asynchronous operation (op key
// _folder.<id>) holding the folder lock, every affected instance's lock
// (all or none, sorted) and the "applying" mark (pendingLocked: 409).
// Order inside it: dry-run render → marker → stop → snapshot → apply →
// verify → state → regenerate → start → marker removed → deliveries and
// audit. The fixer never runs under mu; the marker
// <data>/folders/<id>.applying.json records the phase, and
// RecoverFolderApplies (Init) starts what an interrupted operation
// stopped with what state.yaml holds — it never runs the fixer again, so
// it never applies over newer state.

// downtimeRate is the entries per second each fixer run is estimated at.
const downtimeRate = 5000

// FolderUse is one use the admin wants: an instance's path option set to
// the folder (or a subpath). Write is the admin's write confirmation for
// an option without a folder block (call 3).
type FolderUse struct {
	Instance string `json:"instance"`
	Key      string `json:"key"`
	Subpath  string `json:"subpath,omitempty"`
	Write    bool   `json:"write,omitempty"`
}

// AssignRequest is the full desired set of a folder's uses.
type AssignRequest struct {
	Uses []FolderUse `json:"uses"`
}

// UsePlan is one use as the apply would leave it.
type UsePlan struct {
	FolderUse
	Label      string            `json:"label"`
	Access     string            `json:"access"`
	ReadOnly   bool              `json:"read_only"`
	Declared   bool              `json:"declared"`
	JoinsGroup string            `json:"joins_group"`
	Env        map[string]string `json:"env"`
	Change     string            `json:"change"` // add | remove | keep
}

// DiskPlan is what the fixer would do to the folder.
type DiskPlan struct {
	Files    string                `json:"files"`
	OwnerUID *int                  `json:"owner_uid,omitempty"`
	Mkdir    []string              `json:"mkdir,omitempty"`
	Counts   *folderfix.PlanCounts `json:"counts,omitempty"`
	Entries  int64                 `json:"entries"`
	Partial  bool                  `json:"partial"`
	Dev      uint64                `json:"dev"`
	Ino      uint64                `json:"ino"`
}

// AssignPlan is a preview's answer (assignment or undo).
type AssignPlan struct {
	Folder   string    `json:"folder"`
	GID      int       `json:"gid"`
	Path     string    `json:"path"`
	Uses     []UsePlan `json:"uses"`
	Disk     *DiskPlan `json:"disk,omitempty"` // nil: only removals, nothing on disk
	Restarts []string  `json:"restarts"`       // running instances stopped and started
	Downtime string    `json:"downtime"`
	Lines    []string  `json:"lines"`
	Warnings []string  `json:"warnings,omitempty"`
	Hash     string    `json:"plan_hash"`
	// Snapshot (undo): the apply snapshot the undo restores.
	Snapshot string `json:"snapshot,omitempty"`
}

// valueEdit is one setting value an apply writes (Value "" = deleted:
// back to the default).
type valueEdit struct {
	Instance, Key, Value string
	label                string
	before               string
}

// assignCalc is a computed plan plus what the apply needs.
type assignCalc struct {
	plan     *AssignPlan
	folder   state.Folder
	affected []string // every instance locked (sorted)
	edits    []valueEdit
	wc       map[string]bool // the folder's WriteConfirmed after the apply
	enabled  map[string]bool
	running  map[string]bool
	names    map[string]string
	adds     int
	removes  int
	inputs   map[string]hashInputs
	scan     *folderfix.Report
	mustOwn  map[string]bool // "<instance>/<key>" of the must_own use
	// renderChanged: affected instances whose override or env the apply
	// changes (dryRunAssign, M8), whether or not their own values change.
	renderChanged map[string]bool
}

// hashInputs are an affected instance's current values and ports, and
// its template's source hash (M1: a source sync between the preview and
// the apply changes it), which the plan hash covers: any change since the
// preview is a 409.
type hashInputs struct {
	Values  map[string]any    `json:"values"`
	Ports   map[string]string `json:"ports"`
	Enabled bool              `json:"enabled"`
	Source  string            `json:"source"`
}

// fillSources sets each input's template source hash (file reads,
// outside mu; a template that can't be hashed hashes as its error).
func (h *Hub) fillSources(inputs map[string]hashInputs) {
	for inst, in := range inputs {
		if t := h.Template(inst); t != nil {
			sum, err := templates.SourceHash(t)
			if err != nil {
				sum = "error: " + err.Error()
			}
			in.Source = sum
			inputs[inst] = in
		}
	}
}

// applyMarker is <data>/folders/<id>.applying.json (contract §14.3).
type applyMarker struct {
	Kind      string    `json:"kind"` // apply | undo
	Folder    string    `json:"folder"`
	Instances []string  `json:"instances"` // the ones stopped: started again
	Phase     string    `json:"phase"`     // disk | state
	Snapshot  string    `json:"snapshot,omitempty"`
	Undo      string    `json:"undo_snapshot,omitempty"`
	Files     string    `json:"files,omitempty"`
	OwnerUID  *int      `json:"owner_uid,omitempty"`
	Values    []mvalue  `json:"values,omitempty"` // the apply's planned values
	At        time.Time `json:"at"`
}

type mvalue struct {
	Instance string `json:"instance"`
	Key      string `json:"key"`
	Value    string `json:"value"` // "" = deleted
}

func (h *Hub) foldersDir() string { return filepath.Join(h.cfg.DataDir, "folders") }
func (h *Hub) markerPath(id string) string {
	return filepath.Join(h.foldersDir(), id+".applying.json")
}

// testMarkerWrite, if set, runs before every marker write and may fail
// it (tests: I1).
var testMarkerWrite func(m *applyMarker) error

func (h *Hub) writeMarker(id string, m *applyMarker) error {
	if testMarkerWrite != nil {
		if err := testMarkerWrite(m); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(h.foldersDir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(h.markerPath(id), data, 0o600)
}

func (h *Hub) removeMarker(id string) {
	if err := os.Remove(h.markerPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("shared folders: ERROR: %s: removing the apply marker: %v", id, err)
	}
}

// storeScan keeps a verify scan as the folder's doctor scan (P13: Task 11
// fills it).
func (h *Hub) storeScan(folder string, rep *folderfix.Report) {}

// lockApps takes every id's lifecycle lock, sorted, all or none (ruling
// 4, D33): the first busy one releases those taken (409).
func (h *Hub) lockApps(ids []string) (func(), error) {
	ids = slices.Sorted(slices.Values(ids))
	var unlocks []func()
	release := func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}
	for _, id := range ids {
		u, err := h.lockApp(id)
		if err != nil {
			release()
			return nil, &StatusError{Status: http.StatusConflict, Err: err}
		}
		unlocks = append(unlocks, u)
	}
	return release, nil
}

// markApplying sets the "applying" mark of ids for folder (ruling 6)
// and returns its removal.
func (h *Hub) markApplying(folder string, ids []string) func() {
	h.mu.Lock()
	if h.folderApplying == nil {
		h.folderApplying = map[string]string{}
	}
	for _, id := range ids {
		h.folderApplying[id] = folder
	}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		for _, id := range ids {
			if h.folderApplying[id] == folder {
				delete(h.folderApplying, id)
			}
		}
		h.mu.Unlock()
	}
}

// appName is how a line names instance t ("Immich", "Immich (photos2)").
func appName(t *templates.Template) string {
	name := t.Manifest.Name
	if name == "" {
		name = t.ID
	}
	if !t.IsDefault() {
		name += " (" + t.ID + ")"
	}
	return name
}

// appNames are ids as lines name them (appName; the id when the
// template is gone).
func (h *Hub) appNames(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if t := h.Template(id); t != nil {
			out = append(out, appName(t))
		} else {
			out = append(out, id)
		}
	}
	return out
}

// joinNames: "A", "A and B", "A, B and C".
func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// downtimeText estimates the stop: entries at downtimeRate a second for
// each of runs fixer runs.
func downtimeText(entries int64, runs int) string {
	secs := entries * int64(runs) / downtimeRate
	if secs < 60 {
		return "under a minute"
	}
	mins := (secs + 30) / 60
	if mins == 1 {
		return "about 1 minute"
	}
	return fmt.Sprintf("about %d minutes", mins)
}

// folderValue is the stored value of a use.
func folderValue(id, sub string) string {
	if sub == "" {
		return settings.FolderRefPrefix + id
	}
	return settings.FolderRefPrefix + id + "/" + sub
}

// assignAffectedLocked is every instance a request on folder id touches:
// the requested ones and those using the folder now. Caller holds mu.
func (h *Hub) assignAffectedLocked(id string, req AssignRequest) []string {
	set := map[string]bool{}
	for _, u := range req.Uses {
		if templates.ValidID(u.Instance) {
			set[u.Instance] = true
		}
	}
	for _, u := range h.folderUsesLocked(id) {
		set[u.Instance] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// planAssignLocked validates req against state and computes the uses,
// value edits and write confirmations (no I/O). Caller holds mu.
func (h *Hub) planAssignLocked(id string, req AssignRequest) (*assignCalc, error) {
	f, ok := h.st.Folders[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := &assignCalc{folder: f, wc: maps.Clone(f.WriteConfirmed), enabled: map[string]bool{}, running: map[string]bool{},
		names: map[string]string{}, inputs: map[string]hashInputs{}, mustOwn: map[string]bool{}}
	if c.wc == nil {
		c.wc = map[string]bool{}
	}
	c.plan = &AssignPlan{Folder: id, GID: f.GID, Path: f.Path, Uses: []UsePlan{}, Restarts: []string{}}
	cur := map[string]FolderUseView{}
	for _, u := range h.folderUsesLocked(id) {
		cur[u.Instance+"/"+u.Key] = u
	}
	type want struct {
		u FolderUse
		t *templates.Template
		o *templates.Option
	}
	var wants []want
	seen := map[string]bool{}
	for _, u := range req.Uses {
		k := u.Instance + "/" + u.Key
		if seen[k] {
			return nil, statusErr(http.StatusBadRequest, "setting %s of %s is listed twice", u.Key, u.Instance)
		}
		seen[k] = true
		t := h.findLocked(u.Instance)
		if t == nil {
			return nil, statusErr(http.StatusBadRequest, "unknown app instance %q", clipRunes(u.Instance, 64))
		}
		o := optionByKey(t, u.Key)
		if o == nil {
			return nil, statusErr(http.StatusBadRequest, "%s has no setting %q", u.Instance, clipRunes(u.Key, 64))
		}
		if o.Type != templates.TypePath || o.EffectiveScope() != templates.ScopeInstance || o.Target == nil || o.Target.Mount == "" {
			return nil, statusErr(http.StatusBadRequest, "setting %s of %s is not a folder the app mounts: only path settings can use a shared folder", u.Key, u.Instance)
		}
		if _, _, _, err := settings.ParseFolderRef(folderValue(id, u.Subpath)); err != nil {
			return nil, statusErr(http.StatusBadRequest, "setting %s of %s: %v", u.Key, u.Instance, err)
		}
		if u.Write && o.Folder != nil {
			return nil, statusErr(http.StatusBadRequest, "setting %s of %s: the template declares how it uses the folder (%s): write applies only to settings without a folder block", u.Key, u.Instance, o.Folder.Access)
		}
		if u.Write && o.Mode == "ro" {
			return nil, statusErr(http.StatusBadRequest, "setting %s of %s: the template mounts it read-only", u.Key, u.Instance)
		}
		if ref, _, isRef, _ := folderRefOf(h.st.Settings[u.Instance].Values[u.Key]); isRef && ref != id {
			name := ref
			if of, ok := h.st.Folders[ref]; ok {
				name = of.Name
			}
			return nil, statusErr(http.StatusConflict, "setting %s of %s uses shared folder %s: unassign it from %s first", u.Key, u.Instance, name, name)
		}
		wants = append(wants, want{u, t, o})
	}
	for _, inst := range h.assignAffectedLocked(id, req) {
		s := h.st.Settings[inst]
		c.affected = append(c.affected, inst)
		c.enabled[inst] = h.st.IsEnabled(inst)
		c.inputs[inst] = hashInputs{Values: maps.Clone(s.Values), Ports: maps.Clone(s.Ports), Enabled: c.enabled[inst]}
		if t := h.findLocked(inst); t != nil {
			c.names[inst] = appName(t)
		} else {
			c.names[inst] = inst
		}
	}

	// The planned settings of every instance (for runs_as and the checks).
	planned := map[string]state.InstanceSettings{}
	plannedOf := func(inst string) state.InstanceSettings {
		if s, ok := planned[inst]; ok {
			return s
		}
		s := h.st.Settings[inst].Clone()
		planned[inst] = s
		return s
	}
	setPlanned := func(inst, key, v string) {
		s := plannedOf(inst)
		if s.Values == nil {
			s.Values = map[string]any{}
		}
		if s.Types == nil {
			s.Types = map[string]string{}
		}
		if v == "" {
			delete(s.Values, key)
			delete(s.Types, key)
		} else {
			s.Values[key] = v
			s.Types[key] = templates.TypePath
		}
		planned[inst] = s
	}
	showBefore := func(inst, key string) string {
		v, ok := h.st.Settings[inst].Values[key]
		if !ok || v == nil {
			return "unset"
		}
		return fmt.Sprint(v)
	}
	for _, w := range wants {
		k := w.u.Instance + "/" + w.u.Key
		v := folderValue(id, w.u.Subpath)
		prev, had := cur[k]
		change := "add"
		if had && prev.Subpath == w.u.Subpath && fmt.Sprint(h.st.Settings[w.u.Instance].Values[w.u.Key]) == v &&
			(w.o.Folder != nil || f.WriteConfirmed[k] == w.u.Write) {
			change = "keep"
		}
		if change == "add" {
			c.adds++
			if fmt.Sprint(h.st.Settings[w.u.Instance].Values[w.u.Key]) != v {
				c.edits = append(c.edits, valueEdit{Instance: w.u.Instance, Key: w.u.Key, Value: v, label: w.o.Label, before: showBefore(w.u.Instance, w.u.Key)})
			}
			setPlanned(w.u.Instance, w.u.Key, v)
		}
		if w.o.Folder == nil {
			if w.u.Write {
				c.wc[k] = true
			} else {
				delete(c.wc, k)
			}
		}
		up := UsePlan{FolderUse: w.u, Label: w.o.Label, Change: change, Access: templates.FolderRead, JoinsGroup: templates.JoinGroupAdd}
		if w.o.Folder != nil {
			up.Declared, up.Access, up.JoinsGroup = true, w.o.Folder.Access, w.o.Folder.Join()
		} else if w.u.Write {
			up.Access = templates.FolderWrite
		}
		up.ReadOnly = folderReadOnly(w.o, &state.Folder{WriteConfirmed: c.wc}, w.u.Instance, w.u.Key)
		c.plan.Uses = append(c.plan.Uses, up)
	}
	for _, k := range slices.Sorted(maps.Keys(cur)) {
		if seen[k] {
			continue
		}
		u := cur[k]
		if ref, _, isRef, _ := folderRefOf(h.st.Settings[u.Instance].Values[u.Key]); !isRef || ref != id {
			return nil, statusErr(http.StatusConflict, "%s uses shared folder %s outside its instance values (setting %s): it can't be unassigned here", u.Instance, f.Name, u.Key)
		}
		c.removes++
		c.edits = append(c.edits, valueEdit{Instance: u.Instance, Key: u.Key, label: u.Label, before: showBefore(u.Instance, u.Key)})
		setPlanned(u.Instance, u.Key, "")
		delete(c.wc, k)
		c.plan.Uses = append(c.plan.Uses, UsePlan{FolderUse: FolderUse{Instance: u.Instance, Key: u.Key, Subpath: u.Subpath},
			Label: u.Label, Access: u.Access, ReadOnly: u.ReadOnly, Declared: u.Declared, JoinsGroup: templates.JoinGroupAdd, Change: "remove"})
	}
	sort.SliceStable(c.plan.Uses, func(i, j int) bool {
		a, b := c.plan.Uses[i], c.plan.Uses[j]
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		return a.Key < b.Key
	})

	// must_own: at most one; its uid from the planned values.
	var owners []string
	var ownerUID *int
	for _, w := range wants {
		if w.o.Folder == nil || !w.o.Folder.MustOwn {
			continue
		}
		owners = append(owners, w.u.Instance+" ("+w.u.Key+")")
		c.mustOwn[w.u.Instance+"/"+w.u.Key] = true
		uid, _, err := settings.ResolveRunsAs(w.o, w.t.Manifest.Options(), h.instanceValuesLocked(w.t, plannedOf(w.u.Instance)))
		if err != nil {
			return nil, statusErr(http.StatusConflict, "setting %s of %s: the owner's uid can't be resolved: %v", w.u.Key, w.u.Instance, err)
		}
		ownerUID = &uid
	}
	if len(owners) > 1 {
		return nil, statusErr(http.StatusConflict, "%s would both own shared folder %s (must_own): only one use may own it", joinNames(owners), f.Name)
	}

	// Call 23 / T2 carry: options of one service that share a gid_env
	// variable get one value, so they must name the same folder.
	for _, w := range wants {
		if w.o.Folder == nil || w.o.Folder.Join() != templates.JoinGIDEnv || w.o.Folder.RunsAs == nil || w.o.Folder.RunsAs.GIDEnv == "" {
			continue
		}
		s := plannedOf(w.u.Instance)
		for _, o2 := range mountOptions(w.t) {
			if o2.Key == w.o.Key || o2.Target.Service != w.o.Target.Service || o2.Folder == nil || o2.Folder.RunsAs == nil ||
				o2.Folder.RunsAs.GIDEnv != w.o.Folder.RunsAs.GIDEnv {
				continue
			}
			v, ok := h.effectiveValue(w.t, o2, s)
			if !ok || v == nil || v == "" {
				continue
			}
			if ref, _, isRef, _ := folderRefOf(v); isRef && ref == id {
				continue
			}
			return nil, statusErr(http.StatusConflict, "settings %s and %s of %s both set %s for service %s, so they can't use different folders: point both settings at the same shared folder",
				w.o.Key, o2.Key, w.u.Instance, w.o.Folder.RunsAs.GIDEnv, w.o.Target.Service)
		}
	}

	// Env per use (what the apply writes; removed uses: empty).
	gid := strconv.Itoa(f.GID)
	for i := range c.plan.Uses {
		up := &c.plan.Uses[i]
		env := map[string]string{templates.FolderGIDVar(up.Key): gid, templates.FolderUIDVar(up.Key): ""}
		if ownerUID != nil {
			env[templates.FolderUIDVar(up.Key)] = strconv.Itoa(*ownerUID)
		}
		if up.Change == "remove" {
			env[templates.FolderGIDVar(up.Key)] = ""
			env[templates.FolderUIDVar(up.Key)] = ""
		} else if t := h.findLocked(up.Instance); t != nil {
			if o := optionByKey(t, up.Key); o != nil && o.Folder != nil && o.Folder.Join() == templates.JoinGIDEnv && o.Folder.RunsAs != nil {
				env[o.Folder.RunsAs.GIDEnv] = gid
			}
		}
		up.Env = env
	}

	if c.adds > 0 {
		files := "r"
		for _, up := range c.plan.Uses {
			if up.Change != "remove" && up.Access == templates.FolderWrite {
				files = "rw"
			}
		}
		c.plan.Disk = &DiskPlan{Files: files, OwnerUID: ownerUID, Dev: f.Dev, Ino: f.Ino}
	}
	return c, nil
}

// changedInstances are the instances whose values the apply edits.
func (c *assignCalc) changedInstances() []string {
	set := map[string]bool{}
	for _, e := range c.edits {
		set[e.Instance] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// touchedInstances are the instances whose files the apply changes: their
// values change, or their render does (M8). Sorted.
func (c *assignCalc) touchedInstances() []string {
	set := map[string]bool{}
	for _, i := range c.changedInstances() {
		set[i] = true
	}
	for i := range c.renderChanged {
		set[i] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// stopSet is who the op stops: every running affected instance when the
// disk changes (the snapshot and the apply see a still folder), else the
// running instances whose files change.
func (c *assignCalc) stopSet() []string {
	var out []string
	touched := map[string]bool{}
	for _, i := range c.touchedInstances() {
		touched[i] = true
	}
	for _, inst := range c.affected {
		if c.running[inst] && (c.plan.Disk != nil || touched[inst]) {
			out = append(out, inst)
		}
	}
	return out
}

// regenSet: enabled instances whose files change but aren't running:
// their files are regenerated, they aren't started.
func (c *assignCalc) regenSet() []string {
	var out []string
	for _, inst := range c.touchedInstances() {
		if c.enabled[inst] && !c.running[inst] {
			out = append(out, inst)
		}
	}
	return out
}

// computeAssign is the whole plan: state (planAssignLocked), which
// instances run, the disk (probe, subpath probes, a scan capped at
// previewMaxTime), the dry-run render, the text and the hash. It changes
// nothing.
func (h *Hub) computeAssign(ctx context.Context, id string, req AssignRequest) (*assignCalc, error) {
	h.mu.RLock()
	c, err := h.planAssignLocked(id, req)
	h.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	h.fillSources(c.inputs)
	if err := h.runningOf(ctx, c.affected, c.enabled, c.running); err != nil {
		return nil, err
	}
	if c.plan.Disk != nil {
		if err := h.diskPlan(ctx, id, c); err != nil {
			return nil, err
		}
	}
	if err := h.dryRunAssign(id, c); err != nil {
		return nil, err
	}
	c.plan.Restarts = c.stopSet()
	if c.plan.Restarts == nil {
		c.plan.Restarts = []string{}
	}
	h.assignText(c)
	c.plan.Hash = assignHash(c)
	return c, nil
}

// runningOf fills running for the enabled ones of ids (Docker, outside
// mu).
func (h *Hub) runningOf(ctx context.Context, ids []string, enabled, running map[string]bool) error {
	if h.engine == nil {
		return statusErr(http.StatusServiceUnavailable, "shared folders need the Docker Engine API")
	}
	for _, inst := range ids {
		if !enabled[inst] {
			continue
		}
		r, err := h.projectRunning(ctx, inst)
		if err != nil {
			return statusErr(http.StatusServiceUnavailable, "can't tell whether %s runs: %v", inst, err)
		}
		running[inst] = r
	}
	return nil
}

// diskPlan probes the folder root (the stored device and inode) and the
// subpaths (missing ones are created by the apply), then scans with the
// target and the preview caps. Without ACL support a must_own owner
// change that would cut previous owners is dropped (a warning), and a
// change that would cut anyone's access is refused (explain-only).
func (h *Hub) diskPlan(ctx context.Context, id string, c *assignCalc) error {
	f, d := c.folder, c.plan.Disk
	pr, err := h.probePath(ctx, f.Path, false, id)
	if err != nil {
		return err
	}
	if !pr.Exists || pr.Dev != f.Dev || pr.Ino != f.Ino {
		return errFolderChanged(f.Name)
	}
	subs := map[string]bool{}
	for _, up := range c.plan.Uses {
		if up.Change != "remove" && up.Subpath != "" {
			subs[up.Subpath] = true
		}
	}
	for _, sub := range slices.Sorted(maps.Keys(subs)) {
		sp, err := h.probePath(ctx, path.Join(f.Path, sub), false, id)
		if err != nil {
			return err
		}
		if !sp.Exists {
			d.Mkdir = append(d.Mkdir, sub)
		}
	}
	scan := func() (*folderfix.Report, error) {
		rep, err := h.runFixer(ctx, fixerRun{Mode: "scan", Folder: id, Source: f.Path, Opts: folderfix.Options{
			ExpectDev: f.Dev, ExpectIno: f.Ino, ExpectMountRoot: f.MountRoot,
			Target:     folderfix.Target{GID: f.GID, Files: d.Files, OwnerUID: d.OwnerUID},
			MaxEntries: scanMaxEntries, MaxTime: previewMaxTime}})
		if err != nil {
			return nil, err
		}
		if rep.Plan == nil {
			return nil, statusErr(http.StatusInternalServerError, "shared folder %s: the check returned no plan", f.Name)
		}
		return rep, nil
	}
	rep, err := scan()
	if err != nil {
		return err
	}
	if why := fsProblem(f.Path, rep.FSType); why != "" {
		return statusErr(http.StatusConflict, "%s", why)
	}
	if !writableFS[rep.FSType] {
		return statusErr(http.StatusConflict, "%s is on %s: the Hub fixes ownership only on ext4, xfs, btrfs and zfs (explain-only: set its group and permissions by hand)", f.Path, rep.FSType)
	}
	if !rep.ACL && d.OwnerUID != nil {
		var cut []int
		for _, o := range rep.Owners {
			if o.UID != *d.OwnerUID && !slices.Contains(cut, o.UID) {
				cut = append(cut, o.UID)
			}
		}
		if len(cut) > 0 {
			slices.Sort(cut)
			for _, uid := range cut {
				c.plan.Warnings = append(c.plan.Warnings, fmt.Sprintf("uid %d would lose access: ownership stays; the group part still applies", uid))
			}
			d.OwnerUID = nil
			if rep, err = scan(); err != nil {
				return err
			}
		}
	}
	if !rep.ACL && rep.Plan.LoseAccess.N > 0 {
		return statusErr(http.StatusConflict, "%s has no ACL support, so the fix can't keep what its current groups and owners may do: %d entries would change their access (explain-only: give the folder ACL support, or set its group and permissions by hand)", f.Path, rep.Plan.LoseAccess.N)
	}
	counts := *rep.Plan
	d.Counts, d.Entries, d.Partial = &counts, rep.Entries, rep.Partial
	c.scan = rep
	c.plan.Warnings = append(c.plan.Warnings, skippedWarnings(rep)...)
	if rep.Partial {
		c.plan.Warnings = append(c.plan.Warnings, message.NewPrinter(language.English).Sprintf(
			"the preview's check stopped after %d entries (%s): the counts are partial; the apply plans the whole folder", rep.Entries, rep.PartialReason))
	}
	return nil
}

// skippedWarnings: the entries a run leaves alone, for the admin (T4/T5
// carry: races and skipped.*).
func skippedWarnings(rep *folderfix.Report) []string {
	if rep == nil {
		return nil
	}
	p := message.NewPrinter(language.English)
	var out []string
	add := func(c folderfix.Count, what string) {
		if c.N == 0 {
			return
		}
		w := p.Sprintf("%d %s: left alone", c.N, what)
		if len(c.Sample) > 0 {
			w += " (" + strings.Join(c.Sample[:min(len(c.Sample), 3)], ", ") + ")"
		}
		out = append(out, w)
	}
	add(rep.SetID, "files with setuid or setgid")
	add(rep.Skipped.FileCaps, "files with file capabilities")
	add(rep.HardLinks, "files with more than one link")
	add(rep.MountPoints, "other mounts inside the folder")
	add(rep.Specials, "devices, sockets or FIFOs")
	add(rep.BadACL, "entries whose ACL can't be kept exactly")
	add(rep.Skipped.PathTooLong, "entries with a path over 4096 bytes")
	add(rep.Skipped.ACLTooLarge, "entries with ACLs too large to record")
	return append(out, fixerWarnings(rep)...)
}

// dryRunAssign renders every affected instance's override and env from
// the planned values (ruling 5: before anything stops) and checks its
// custom override. It renders from a planned copy of the settings and
// folder definitions (renderView) under the read lock: h.st is never
// changed, nothing is recorded (no env problems, I3), a panic releases
// the lock. A folder deleted meanwhile is ErrNotFound (C1). Every affected
// instance whose override or env would differ from its current render is
// added to c.renderChanged (M8: stopped and started, or regenerated, like
// the instances whose values change). Any refusal is 409.
func (h *Hub) dryRunAssign(id string, c *assignCalc) error {
	views, err := func() ([]*templates.Template, error) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		cur, ok := h.st.Folders[id]
		if !ok {
			return nil, ErrNotFound
		}
		live := h.liveView()
		planned := renderView{settings: maps.Clone(h.st.Settings), folders: maps.Clone(h.st.Folders)}
		if planned.settings == nil {
			planned.settings = map[string]state.InstanceSettings{}
		}
		for _, inst := range c.changedInstances() {
			next := applyEdits(h.st.Settings[inst], c.edits, inst)
			if next.IsZero() {
				delete(planned.settings, inst)
			} else {
				planned.settings[inst] = next
			}
		}
		pf := cur
		pf.WriteConfirmed = c.wc
		planned.folders[id] = pf
		c.renderChanged = map[string]bool{}
		var views []*templates.Template
		for _, inst := range c.affected {
			t := h.findLocked(inst)
			if t == nil {
				continue
			}
			tmpl := *t
			ov, err := h.renderOverrideIn(planned, &tmpl, planned.settings[inst])
			if err != nil {
				return nil, fmt.Errorf("%s: %w", inst, err)
			}
			env, _, err := h.optionEnvIn(planned, &tmpl, nil)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", inst, err)
			}
			// The current render (errors count as a difference: the
			// apply's own up renders again and decides).
			curOv, oerr := h.renderOverrideIn(live, &tmpl, h.st.Settings[inst])
			curEnv, _, eerr := h.optionEnvIn(live, &tmpl, nil)
			if oerr != nil || eerr != nil || curOv != ov || !maps.Equal(curEnv, env) {
				c.renderChanged[inst] = true
			}
			views = append(views, &tmpl)
		}
		return views, nil
	}()
	if errors.Is(err, ErrNotFound) {
		return err
	}
	if err != nil {
		return statusErr(http.StatusConflict, "with this assignment %v: nothing was changed", err)
	}
	for _, t := range views {
		if err := h.checkUserOverride(t); err != nil {
			return err
		}
	}
	return nil
}

// applyEdits is s with inst's edits applied (a copy).
func applyEdits(s state.InstanceSettings, edits []valueEdit, inst string) state.InstanceSettings {
	s = s.Clone()
	for _, e := range edits {
		if e.Instance != inst {
			continue
		}
		if s.Values == nil {
			s.Values = map[string]any{}
		}
		if s.Types == nil {
			s.Types = map[string]string{}
		}
		if e.Value == "" {
			delete(s.Values, e.Key)
			delete(s.Types, e.Key)
		} else {
			s.Values[e.Key] = e.Value
			s.Types[e.Key] = templates.TypePath
		}
	}
	return s
}

// assignText writes the preview's lines (contract §14.3's example).
func (h *Hub) assignText(c *assignCalc) {
	p := message.NewPrinter(language.English)
	f, pl := c.folder, c.plan
	var lines []string
	if f.Adopted {
		lines = append(lines, fmt.Sprintf("gid %d is this folder's adopted group (shown as *%s*).", f.GID, f.Name))
	} else {
		lines = append(lines, fmt.Sprintf("gid %d is allocated for this folder (shown as *%s*).", f.GID, f.Name))
	}
	if d := pl.Disk; d != nil && d.Counts != nil && c.scan != nil {
		k := d.Counts
		gidS := strconv.Itoa(f.GID)
		var prev []string
		for _, g := range slices.Sorted(maps.Keys(k.KeepGroup)) {
			if g != f.GID {
				prev = append(prev, strconv.Itoa(g))
			}
		}
		groups := strings.Join(prev, ", ")
		if groups == "" {
			groups = "their group"
		} else {
			groups = "group " + groups
		}
		if k.ChangeGroup.N > 0 {
			if k.ChangeGroup.N >= c.scan.Files+c.scan.Dirs {
				lines = append(lines, p.Sprintf("%d files and %d folders change %s → %s.", c.scan.Files, c.scan.Dirs, groups, gidS))
			} else {
				lines = append(lines, p.Sprintf("%d of its %d files and %d folders change %s → %s.", k.ChangeGroup.N, c.scan.Files, c.scan.Dirs, groups, gidS))
			}
		}
		for _, g := range slices.Sorted(maps.Keys(k.KeepGroup)) {
			if g != f.GID {
				lines = append(lines, p.Sprintf("Group %s keeps the access it has now through an ACL on %d entries.", strconv.Itoa(g), k.KeepGroup[g]))
			}
		}
		if k.AddSetgid.N > 0 || k.AddDefaultACL.N > 0 {
			lines = append(lines, p.Sprintf("%d folders get setgid and a default ACL, so files the apps create later stay in group %s with group write.", max(k.AddSetgid.N, k.AddDefaultACL.N), gidS))
		}
		if k.Narrowed.N > 0 {
			lines = append(lines, p.Sprintf("%d existing ACL entries are narrowed to what they grant today.", k.Narrowed.N))
		}
		if d.OwnerUID != nil && k.ChangeOwner.N > 0 {
			lines = append(lines, p.Sprintf("%d entries change owner to uid %s.", k.ChangeOwner.N, strconv.Itoa(*d.OwnerUID)))
			for _, u := range slices.Sorted(maps.Keys(k.KeepUser)) {
				lines = append(lines, p.Sprintf("uid %s keeps the access it has now through an ACL on %d entries.", strconv.Itoa(u), k.KeepUser[u]))
			}
		}
		if d.Files == "rw" {
			lines = append(lines, "Files get group read/write (an app writes to it).")
		} else {
			lines = append(lines, "Files get group read (every app only reads it).")
		}
		for _, m := range d.Mkdir {
			lines = append(lines, fmt.Sprintf("%s is created.", m))
		}
	}
	for _, up := range pl.Uses {
		name := c.names[up.Instance]
		where := up.Label
		if up.Subpath != "" {
			where += ", " + up.Subpath
		}
		switch {
		case up.Change == "remove":
			lines = append(lines, fmt.Sprintf("%s stops using it (%s goes back to its default).", name, up.Label))
		case up.ReadOnly:
			lines = append(lines, fmt.Sprintf("%s mounts it read-only (%s).", name, where))
		case pl.Disk != nil && pl.Disk.OwnerUID != nil && up.Declared && c.isOwner(up):
			lines = append(lines, fmt.Sprintf("%s mounts it read/write and owns it (%s).", name, where))
		default:
			lines = append(lines, fmt.Sprintf("%s mounts it read/write (%s).", name, where))
		}
	}
	stop := c.stopSet()
	if len(stop) > 0 {
		var names []string
		for _, inst := range stop {
			names = append(names, c.names[inst])
		}
		entries := int64(0)
		if pl.Disk != nil {
			entries = pl.Disk.Entries
		}
		pl.Downtime = downtimeText(entries, 3)
		verb := "is"
		if len(names) > 1 {
			verb = "are"
		}
		lines = append(lines, fmt.Sprintf("%s %s stopped for %s, then started.", joinNames(names), verb, pl.Downtime))
	} else {
		pl.Downtime = "none"
	}
	for _, inst := range c.regenSet() {
		lines = append(lines, fmt.Sprintf("%s is not running: its configuration is updated, it isn't started.", c.names[inst]))
	}
	if pl.Disk != nil {
		lines = append(lines, "A permissions snapshot is saved first.")
	} else {
		lines = append(lines, "Nothing changes on disk.")
	}
	pl.Lines = lines
}

// isOwner: up is the folder's must_own use.
func (c *assignCalc) isOwner(up UsePlan) bool {
	return c.mustOwn[up.Instance+"/"+up.Key]
}

// assignHash is sha256 of the plan's decisions (contract §14.3): the
// folder, path, gid, uses without labels, the disk plan without its
// counts, the restarts, and every affected instance's current values,
// ports and enabled flag.
func assignHash(c *assignCalc) string {
	type use struct {
		FolderUse
		Access, JoinsGroup, Change string
		ReadOnly, Declared         bool
		Env                        map[string]string
	}
	type disk struct {
		Files    string
		OwnerUID *int
		Mkdir    []string
		Dev, Ino uint64
	}
	var uses []use
	for _, u := range c.plan.Uses {
		uses = append(uses, use{u.FolderUse, u.Access, u.JoinsGroup, u.Change, u.ReadOnly, u.Declared, u.Env})
	}
	var d *disk
	if p := c.plan.Disk; p != nil {
		d = &disk{p.Files, p.OwnerUID, p.Mkdir, p.Dev, p.Ino}
	}
	doc := struct {
		Kind, Folder, Path, Snapshot string
		GID                          int
		Uses                         []use
		Disk                         *disk
		Restarts                     []string
		Inputs                       map[string]hashInputs
		WriteConfirmed               map[string]bool
	}{"assign", c.plan.Folder, c.plan.Path, c.plan.Snapshot, c.plan.GID, uses, d, c.plan.Restarts, c.inputs, c.wc}
	b, err := json.Marshal(doc)
	if err != nil {
		log.Printf("shared folders: plan hash: %v", err)
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// PreviewAssign computes the plan of assigning folder id to req's uses
// (contract §14.3): nothing changes (a probe, subpath probes and a scan
// capped at 30 s run). Refusals: 400 (unknown instance or key, a
// non-path option, a bad subpath), 404 (folder), 409 (see
// planAssignLocked, diskPlan, dryRunAssign).
func (h *Hub) PreviewAssign(ctx context.Context, id string, req AssignRequest) (*AssignPlan, error) {
	c, err := h.computeAssign(ctx, id, req)
	if err != nil {
		return nil, err
	}
	return c.plan, nil
}

// errSetupChanged is the 409 of an apply whose plan differs from the
// preview's.
func errSetupChanged() error {
	return statusErr(http.StatusConflict, "the setup changed since the preview: preview it again")
}

// markerPending: a marker an interrupted operation left and recovery
// hasn't handled yet (M7: a new apply or undo would overwrite it) is 409.
func (h *Hub) markerPending(id string) error {
	_, err := os.Lstat(h.markerPath(id))
	switch {
	case err == nil:
		return statusErr(http.StatusConflict, "shared folder %s has an interrupted operation that hasn't been recovered yet: it is recovered at the Hub's start (see its last operation); try again after that", id)
	case !errors.Is(err, os.ErrNotExist):
		return statusErr(http.StatusInternalServerError, "shared folder %s: reading its apply marker: %v", id, err)
	}
	return nil
}

// opSecrets is every value the instances' errors must have redacted
// (M5: the folder's op key has no secrets of its own).
func (h *Hub) opSecrets(ids []string) []string {
	var out []string
	for _, inst := range ids {
		out = append(out, h.redactionSet(inst)...)
	}
	return out
}

// StartAssign applies req to folder id in the background once the plan
// recomputed under the locks has planHash (else 409, no operation): 202
// semantics, the outcome in the folder's op record (_folder.<id>).
func (h *Hub) StartAssign(id string, req AssignRequest, planHash, actor string) (*AsyncOp, error) {
	unlock, err := h.folderLock(id)
	if err != nil {
		return nil, err
	}
	return h.startAssignHeld(id, req, planHash, actor, unlock)
}

// startAssignHeld is StartAssign with the folder lock already held by
// the caller (ruling 34: manage_as_folder holds it across its create);
// unlockFolder is called when the operation ends or is refused.
func (h *Hub) startAssignHeld(id string, req AssignRequest, planHash, actor string, unlockFolder func()) (*AsyncOp, error) {
	return h.startAsync(opKeyFolder(id), OpFolderAssign, func(ready func()) (result map[string]string, warnings []string, err error) {
		var deliverTo []string
		detail := ""
		// Last: after every lock is released (the engine re-queues busy
		// instances otherwise).
		defer func() {
			h.auditFolder(actor, "folder.assign", id, detail, err)
			for _, inst := range deliverTo {
				h.TriggerDelivery(inst, TriggerSave, true)
			}
		}()
		defer unlockFolder()
		if err := h.markerPending(id); err != nil {
			return nil, nil, err
		}
		h.mu.RLock()
		affected := h.assignAffectedLocked(id, req)
		_, exists := h.st.Folders[id]
		h.mu.RUnlock()
		if !exists {
			return nil, nil, ErrNotFound
		}
		unlockApps, err := h.lockApps(affected)
		if err != nil {
			return nil, nil, err
		}
		defer unlockApps()
		defer h.markApplying(id, affected)()
		c, err := h.computeAssign(context.Background(), id, req)
		if err != nil {
			return nil, nil, err
		}
		for _, inst := range c.affected {
			if !slices.Contains(affected, inst) {
				return nil, nil, errSetupChanged()
			}
		}
		if planHash == "" || c.plan.Hash != planHash {
			return nil, nil, errSetupChanged()
		}
		ready()
		res, warns, dt, deliver, err := h.runAssign(id, c, actor)
		detail, deliverTo = dt, deliver
		return res, warns, err
	})
}

// prefixed is ws, each prefixed with the run's name ("snapshot: …").
func prefixed(run string, ws []string) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, run+": "+w)
	}
	return out
}

// runAssign is the apply after it was accepted (contract §14.3
// sequence). It returns the op's result, warnings, the folder.assign
// detail and the instances to deliver to.
func (h *Hub) runAssign(id string, c *assignCalc, actor string) (map[string]string, []string, string, []string, error) {
	ctx := context.Background()
	f, d := c.folder, c.plan.Disk
	result := map[string]string{"add": strconv.Itoa(c.adds), "remove": strconv.Itoa(c.removes)}
	warnings := slices.Clone(c.plan.Warnings)
	detail := fmt.Sprintf("add=%d remove=%d", c.adds, c.removes)
	secrets := h.opSecrets(c.affected)
	fb := &failCtx{id: id, actor: actor, secrets: secrets}
	m := &applyMarker{Kind: "apply", Folder: id, Instances: c.plan.Restarts, Phase: "disk", At: time.Now().UTC()}
	fb.m = m
	for _, e := range c.edits {
		m.Values = append(m.Values, mvalue{e.Instance, e.Key, e.Value})
	}
	if d != nil {
		m.Files, m.OwnerUID = d.Files, d.OwnerUID
	}
	if err := h.writeMarker(id, m); err != nil {
		return result, warnings, detail, nil, h.failBeforeState(fb, statusErr(http.StatusInternalServerError, "writing the apply marker: %v", err), "", false)
	}
	stopped, err := h.stopAll(c.plan.Restarts)
	fb.stopped = stopped
	if err != nil {
		return result, warnings, detail, nil, h.failBeforeState(fb, err, "", false)
	}

	// The disk: snapshot, apply, verify.
	snap, changedN := "", int64(0)
	if d != nil {
		var diskChanged bool
		var ws []string
		snap, changedN, ws, diskChanged, err = h.applyDisk(ctx, id, f, d, m)
		warnings = append(warnings, ws...)
		if snap != "" {
			result["snapshot"] = snap
		}
		if err != nil {
			fb.entries = changedN
			return result, warnings, detail, nil, h.failBeforeState(fb, err, snap, diskChanged)
		}
		result["entries"] = strconv.FormatInt(changedN, 10)
		detail += fmt.Sprintf(" entries=%d snapshot=%s", changedN, snapshotTS(snap))
	}

	// Phase state: recorded before the save (I1: unrecorded, the save
	// doesn't happen).
	m.Phase = "state"
	if err := h.writeMarker(id, m); err != nil {
		fb.entries = changedN
		return result, warnings, detail, nil, h.failBeforeState(fb, statusErr(http.StatusInternalServerError, "recording the apply's phase: %v", err), snap, d != nil)
	}
	touched := c.touchedInstances()
	regen := c.regenSet()
	members := map[string]*directory.Membership{}
	for _, inst := range regen {
		members[inst] = h.groupSnapshot(inst)
	}
	h.mu.Lock()
	prevSettings := map[string]state.InstanceSettings{}
	prevHad := map[string]bool{}
	for _, inst := range c.changedInstances() {
		prevSettings[inst], prevHad[inst] = h.st.Settings[inst]
		next := applyEdits(h.st.Settings[inst], c.edits, inst)
		if next.IsZero() {
			delete(h.st.Settings, inst)
		} else {
			h.st.Settings[inst] = next
		}
	}
	prevFolder := h.st.Folders[id]
	nf := prevFolder
	nf.WriteConfirmed = c.wc
	if len(nf.WriteConfirmed) == 0 {
		nf.WriteConfirmed = nil
	}
	if d != nil {
		nf.LastApply = &state.FolderApply{At: m.At, Files: d.Files, OwnerUID: d.OwnerUID, Snapshot: snap}
	}
	h.st.Folders[id] = nf
	if serr := h.saveStateLocked(); serr != nil {
		for inst, s := range prevSettings {
			if prevHad[inst] {
				h.st.Settings[inst] = s
			} else {
				delete(h.st.Settings, inst)
			}
		}
		h.st.Folders[id] = prevFolder
		h.mu.Unlock()
		fb.entries = changedN
		return result, warnings, detail, nil, h.failBeforeState(fb, serr, snap, d != nil)
	}
	// Enabled instances that don't run: their files now (not started).
	var regenErrs []string
	for _, inst := range regen {
		t := h.findLocked(inst)
		if t == nil {
			continue
		}
		tmpl := *t
		if e := h.generateOverrideLocked(&tmpl, h.st.Settings[inst]); e != nil {
			regenErrs = append(regenErrs, fmt.Sprintf("%s: %v", inst, e))
		} else if e := h.refreshInstanceEnvLocked(&tmpl, members[inst]); e != nil {
			regenErrs = append(regenErrs, fmt.Sprintf("%s: %v", inst, e))
		}
	}
	h.mu.Unlock()
	for _, inst := range regen {
		warnings = append(warnings, fmt.Sprintf("%s is not running: its configuration was updated, it wasn't started", c.names[inst]))
	}
	for _, e := range regenErrs {
		warnings = append(warnings, redactValues("regenerating "+e, secrets))
	}

	// Start what was stopped, with the new configuration.
	startErr := h.startAll(stopped)
	h.removeMarker(id)
	// settings.change per changed key (actor the admin), folder.apply
	// when the disk changed.
	for _, e := range c.edits {
		after := e.Value
		if after == "" {
			after = "unset"
		}
		h.auditOp(actor, "settings.change", e.Instance+"/"+e.Key, "scope=instance: "+e.before+" -> "+after, nil)
	}
	if d != nil {
		h.auditFolder(actor, "folder.apply", id, fmt.Sprintf("entries=%d snapshot=%s", changedN, snapshotTS(snap)), nil)
	}
	deliver := []string{}
	for _, inst := range touched {
		if c.enabled[inst] {
			deliver = append(deliver, inst)
		}
	}
	if startErr != nil {
		err := statusErr(http.StatusInternalServerError, "the assignment was saved, but %v: start them from the app list", startErr)
		return result, warnings, detail, deliver, withSecrets(err, append(secrets, secretsOf(startErr)...))
	}
	return result, warnings, detail, deliver, nil
}

// stopAll stops ids (compose down, volumes kept), in order. On a failure
// the instance whose down failed is in the returned list too (I2: its
// down may have half-run; composeUp of a running project changes
// nothing), so the caller starts it again.
func (h *Hub) stopAll(ids []string) ([]string, error) {
	var stopped []string
	for _, inst := range ids {
		t := h.Template(inst)
		if t == nil {
			return stopped, statusErr(http.StatusConflict, "%s has no template now", inst)
		}
		if err := h.composeDown(t); err != nil {
			stopped = append(stopped, inst)
			return stopped, fmt.Errorf("stopping %s failed: %w", inst, withSecrets(err, h.redactionSet(inst)))
		}
		stopped = append(stopped, inst)
	}
	return stopped, nil
}

// startAll starts ids again (compose up with what state holds now);
// the error names every one that didn't start.
func (h *Hub) startAll(ids []string) error {
	var errs []error
	for _, inst := range ids {
		t := h.Template(inst)
		if t == nil {
			errs = append(errs, fmt.Errorf("%s has no template now", inst))
			continue
		}
		if err := h.composeUp(t); err != nil {
			if composeFailed(err) {
				h.rollbackUp(t)
			}
			errs = append(errs, fmt.Errorf("%s didn't start: %w", inst, withSecrets(err, h.redactionSet(inst))))
		}
	}
	return errors.Join(errs...)
}

// failCtx is what failBeforeState needs of the running apply.
type failCtx struct {
	id, actor string
	m         *applyMarker
	stopped   []string
	secrets   []string
	entries   int64
}

// failBeforeState handles a failure before the state save: the stopped
// instances start again with their old configuration, the marker goes,
// and the error says what changed on disk (snap: the snapshot that
// undoes it, recorded as last_apply so "Undo last fix" offers it; I4:
// audited folder.apply with the snapshot). The error keeps the stopped
// instances' redaction sets (M5).
func (h *Hub) failBeforeState(fb *failCtx, cause error, snap string, diskChanged bool) error {
	id, m := fb.id, fb.m
	keepMarker := false // the snapshot couldn't be recorded: the marker names it for recovery
	if diskChanged && snap != "" {
		h.mu.Lock()
		if f, ok := h.st.Folders[id]; ok {
			prev := f
			f.LastApply = &state.FolderApply{At: m.At, Files: m.Files, OwnerUID: m.OwnerUID, Snapshot: snap}
			h.st.Folders[id] = f
			if err := h.saveStateLocked(); err != nil {
				h.st.Folders[id] = prev
				keepMarker = true
				log.Printf("shared folders: ERROR: %s: recording the snapshot to undo: %v (marker kept: recovery records it at the next start)", id, err)
			}
		}
		h.mu.Unlock()
	}
	startErr := h.startAll(fb.stopped)
	if !keepMarker {
		h.removeMarker(id)
	}
	var b strings.Builder
	b.WriteString(cause.Error())
	b.WriteString(": the settings are unchanged")
	switch {
	case diskChanged && snap != "":
		fmt.Fprintf(&b, "; some permissions may have changed: permissions snapshot %s can undo them (Undo last fix)", snap)
	case snap != "":
		fmt.Fprintf(&b, "; nothing on disk changed (permissions snapshot %s was saved)", snap)
	default:
		b.WriteString("; nothing on disk changed")
	}
	if len(fb.stopped) > 0 {
		if startErr != nil {
			fmt.Fprintf(&b, "; starting the apps again failed: %v", startErr)
		} else {
			fmt.Fprintf(&b, "; %s started again with the old configuration", joinNames(h.appNames(fb.stopped)))
		}
	}
	status := errStatus(cause)
	if startErr != nil || diskChanged {
		status = http.StatusInternalServerError
	}
	sec := append(slices.Clone(fb.secrets), secretsOf(cause)...)
	sec = append(sec, secretsOf(startErr)...)
	err := withSecrets(&StatusError{Status: status, Err: errors.New(b.String())}, sec)
	if diskChanged {
		h.auditFolder(fb.actor, "folder.apply", id, fmt.Sprintf("entries=%d snapshot=%s", fb.entries, snapshotTS(snap)), err)
	}
	return err
}

// checkSavedSnapshot (M2): the snapshot the Hub stored for this apply is
// an apply snapshot of this folder with the apply's target and the
// snapshot run's count.
func (h *Hub) checkSavedSnapshot(rel string, f state.Folder, d *DiskPlan, entries int64) error {
	hdr, err := h.snapshotHeaderOf(rel)
	if err != nil {
		return err
	}
	ownerOK := (hdr.OwnerUID == nil) == (d.OwnerUID == nil) && (hdr.OwnerUID == nil || *hdr.OwnerUID == *d.OwnerUID)
	if hdr.Kind != "apply" || hdr.GID != f.GID || hdr.Files != d.Files || !ownerOK || hdr.RootDev != f.Dev || hdr.RootIno != f.Ino || hdr.Entries != entries {
		return statusErr(http.StatusInternalServerError, "the permissions snapshot doesn't match the apply (kind %s, gid %d, files %s, %d entries; want apply, %d, %s, %d)",
			hdr.Kind, hdr.GID, hdr.Files, hdr.Entries, f.GID, d.Files, entries)
	}
	return nil
}

// applyDisk runs the free-space check, the snapshot (saved by the Hub,
// its header checked, its name recorded in the marker), the apply
// (--expect and --expect-digest from the snapshot) and the verify scan.
// diskChanged: the apply may have changed something (it ran and didn't
// refuse). Warnings: every run's races and skips (M6).
func (h *Hub) applyDisk(ctx context.Context, id string, f state.Folder, d *DiskPlan, m *applyMarker) (snap string, changed int64, warns []string, diskChanged bool, err error) {
	if err := needFree(h.cfg.DataDir, 0, "the permissions snapshot of shared folder "+f.Name); err != nil {
		return "", 0, nil, false, err
	}
	target := folderfix.Target{GID: f.GID, Files: d.Files, OwnerUID: d.OwnerUID}
	base := folderfix.Options{ExpectDev: f.Dev, ExpectIno: f.Ino, ExpectMountRoot: f.MountRoot, Target: target}
	var saved string
	snapRep, err := h.runFixer(ctx, fixerRun{Mode: "snapshot", Folder: id, Source: f.Path, Opts: base,
		Out: func(r io.Reader) error {
			rel, err := h.saveSnapshot(id, r)
			saved = rel
			return err
		}})
	warns = append(warns, prefixed("snapshot", skippedWarnings(snapRep))...)
	if err != nil {
		if saved != "" {
			h.dropSnapshot(saved)
		}
		return "", 0, warns, false, fmt.Errorf("the permissions snapshot failed: %w", err)
	}
	if saved == "" || snapRep.Plan == nil || !digestRe.MatchString(snapRep.Plan.Digest) {
		if saved != "" {
			h.dropSnapshot(saved)
		}
		return "", 0, warns, false, statusErr(http.StatusInternalServerError, "the permissions snapshot returned no plan")
	}
	if err := h.checkSavedSnapshot(saved, f, d, snapRep.Plan.Changes); err != nil {
		h.dropSnapshot(saved)
		return "", 0, warns, false, err
	}
	// I1: the snapshot is recorded before anything changes, or nothing
	// changes.
	m.Snapshot = saved
	if err := h.writeMarker(id, m); err != nil {
		m.Snapshot = ""
		h.dropSnapshot(saved)
		return "", 0, warns, false, statusErr(http.StatusInternalServerError, "recording the permissions snapshot: %v", err)
	}
	applyOpts := base
	applyOpts.ExpectDigest = snapRep.Plan.Digest
	applyOpts.Target.Mkdir = d.Mkdir
	applyRep, err := h.runFixer(ctx, fixerRun{Mode: "apply", Folder: id, Source: f.Path, Opts: applyOpts,
		Extra: folderfix.ArgsExtra{Expect: snapRep.Plan.Changes}})
	if applyRep != nil {
		changed = applyRep.Changed
	}
	warns = append(warns, prefixed("apply", skippedWarnings(applyRep))...)
	if err != nil {
		// Exit 2 (409) is a refusal: nothing changed.
		return saved, changed, warns, errStatus(err) != http.StatusConflict, fmt.Errorf("the apply failed: %w", err)
	}
	ver, err := h.runFixer(ctx, fixerRun{Mode: "scan", Folder: id, Source: f.Path, Opts: base})
	warns = append(warns, prefixed("verify", fixerWarnings(ver))...)
	if err != nil {
		return saved, changed, warns, true, fmt.Errorf("the verify scan failed: %w", err)
	}
	if ver.Expected == nil || ver.Partial {
		return saved, changed, warns, true, statusErr(http.StatusInternalServerError, "the verify scan was incomplete")
	}
	e := ver.Expected
	if n := e.Group.N + e.Setgid.N + e.DefaultACL.N + e.Mode.N + e.Owner.N; n > 0 {
		return saved, changed, warns, true, statusErr(http.StatusInternalServerError,
			"the verify scan found entries not as planned (group %d, setgid %d, default ACL %d, mode %d, owner %d)",
			e.Group.N, e.Setgid.N, e.DefaultACL.N, e.Mode.N, e.Owner.N)
	}
	h.storeScan(id, ver)
	return saved, changed, warns, true, nil
}

// dropSnapshot removes a snapshot a failed run left half-trusted.
func (h *Hub) dropSnapshot(rel string) {
	if snapshotRel(rel) != nil {
		return
	}
	p := filepath.Join(h.snapshotsDir(), filepath.FromSlash(rel))
	os.Remove(p + ".sha256")
	os.Remove(p)
}

// ── undo ────────────────────────────────────────────────

// undoCalc is a computed undo.
type undoCalc struct {
	plan     *AssignPlan
	folder   state.Folder
	apply    state.FolderApply
	header   *snapshotHeader
	target   folderfix.Target // the header's (M3)
	affected []string
	enabled  map[string]bool
	running  map[string]bool
	names    map[string]string
	inputs   map[string]hashInputs
	dry      *folderfix.Report // restore --dry-run (R56)
}

func errNoUndo(name string) error {
	return statusErr(http.StatusNotFound, "shared folder %s has no fix to undo (no apply yet, or the last operation was an undo)", name)
}

// snapshotRun is a fixer run fed snapshot rel (checksum checked again,
// streamed: M4) at /in.
func (h *Hub) snapshotRun(ctx context.Context, rel string, r fixerRun) (*folderfix.Report, error) {
	f, size, err := h.openSnapshot(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r.In, r.InSize = f, size
	return h.runFixer(ctx, r)
}

// restoreDryRun is `restore --dry-run` of rel on folder f (R56): what a
// restore would rewrite (ToRestore) and leave alone (ChangedSince), with
// nothing written.
func (h *Hub) restoreDryRun(ctx context.Context, id, rel string, f state.Folder) (*folderfix.Report, error) {
	return h.snapshotRun(ctx, rel, fixerRun{Mode: "restore", Folder: id, Source: f.Path,
		Opts:  folderfix.Options{ExpectDev: f.Dev, ExpectIno: f.Ino, ExpectMountRoot: f.MountRoot, Target: folderfix.Target{GID: f.GID}},
		Extra: folderfix.ArgsExtra{DryRun: true}})
}

// computeUndo builds the undo plan from last_apply's snapshot (404
// without one), checking the snapshot (checksum, header — whose target
// must be last_apply's, M3) and the folder root, and counting with a
// restore dry run what it would put back and leave alone (R56).
func (h *Hub) computeUndo(ctx context.Context, id string) (*undoCalc, error) {
	h.mu.RLock()
	f, ok := h.st.Folders[id]
	if !ok {
		h.mu.RUnlock()
		return nil, ErrNotFound
	}
	if f.LastApply == nil || f.LastApply.Snapshot == "" {
		h.mu.RUnlock()
		return nil, errNoUndo(f.Name)
	}
	u := &undoCalc{folder: f, apply: *f.LastApply, enabled: map[string]bool{}, running: map[string]bool{},
		names: map[string]string{}, inputs: map[string]hashInputs{}}
	uses := h.folderUsesLocked(id)
	set := map[string]bool{}
	for _, x := range uses {
		set[x.Instance] = true
	}
	for _, inst := range slices.Sorted(maps.Keys(set)) {
		s := h.st.Settings[inst]
		u.affected = append(u.affected, inst)
		u.enabled[inst] = h.st.IsEnabled(inst)
		u.inputs[inst] = hashInputs{Values: maps.Clone(s.Values), Ports: maps.Clone(s.Ports), Enabled: u.enabled[inst]}
		u.names[inst] = inst
		if t := h.findLocked(inst); t != nil {
			u.names[inst] = appName(t)
		}
	}
	h.mu.RUnlock()
	h.fillSources(u.inputs)
	hdr, err := h.snapshotHeaderOf(u.apply.Snapshot)
	if err != nil {
		return nil, err
	}
	if hdr.Kind != "apply" || hdr.GID != f.GID || hdr.RootDev != f.Dev || hdr.RootIno != f.Ino {
		return nil, statusErr(http.StatusConflict, "permissions snapshot %s is not of this folder as it is now (kind %s, gid %d): it can't be undone", u.apply.Snapshot, hdr.Kind, hdr.GID)
	}
	ownerOK := (hdr.OwnerUID == nil) == (u.apply.OwnerUID == nil) && (hdr.OwnerUID == nil || *hdr.OwnerUID == *u.apply.OwnerUID)
	if hdr.Files != u.apply.Files || !ownerOK {
		return nil, statusErr(http.StatusConflict, "permissions snapshot %s was made for another target (files %s) than the last apply records (files %s): it can't be undone", u.apply.Snapshot, hdr.Files, u.apply.Files)
	}
	u.header = hdr
	u.target = folderfix.Target{GID: hdr.GID, Files: hdr.Files, OwnerUID: hdr.OwnerUID}
	if err := h.runningOf(ctx, u.affected, u.enabled, u.running); err != nil {
		return nil, err
	}
	pr, err := h.probePath(ctx, f.Path, false, id)
	if err != nil {
		return nil, err
	}
	if !pr.Exists || pr.Dev != f.Dev || pr.Ino != f.Ino {
		return nil, errFolderChanged(f.Name)
	}
	dry, err := h.restoreDryRun(ctx, id, u.apply.Snapshot, f)
	if err != nil {
		return nil, err
	}
	u.dry = dry
	pl := &AssignPlan{Folder: id, GID: f.GID, Path: f.Path, Uses: []UsePlan{}, Restarts: []string{}, Snapshot: u.apply.Snapshot,
		Disk: &DiskPlan{Files: hdr.Files, OwnerUID: hdr.OwnerUID, Entries: hdr.Entries, Dev: f.Dev, Ino: f.Ino}}
	for _, x := range uses {
		pl.Uses = append(pl.Uses, UsePlan{FolderUse: FolderUse{Instance: x.Instance, Key: x.Key, Subpath: x.Subpath},
			Label: x.Label, Access: x.Access, ReadOnly: x.ReadOnly, Declared: x.Declared, JoinsGroup: templates.JoinGroupAdd, Change: "keep"})
	}
	for _, inst := range u.affected {
		if u.running[inst] {
			pl.Restarts = append(pl.Restarts, inst)
		}
	}
	p := message.NewPrinter(language.English)
	at := u.apply.At.UTC().Format("2006-01-02 15:04 UTC")
	lines := []string{
		p.Sprintf("Undo the permissions fix of %s: snapshot %s recorded %d entries.", at, snapshotTS(u.apply.Snapshot), hdr.Entries),
		p.Sprintf("%d entries go back to the owner, group, mode and ACLs they had before the fix; %d changed since the fix and are left alone.", dry.ToRestore, dry.ChangedSince.N),
		"An undo snapshot of the entries it rewrites is saved first, as a safety copy: an undo can't be undone.",
		"The setting values don't change.",
	}
	for _, x := range uses {
		lines = append(lines, fmt.Sprintf("%s (%s) may lose access to the restored entries: they go back to their previous group.", u.names[x.Instance], x.Label))
	}
	pl.Warnings = append(pl.Warnings, prefixed("check", skippedWarnings(dry))...)
	pl.Downtime = "none"
	if len(pl.Restarts) > 0 {
		var names []string
		for _, inst := range pl.Restarts {
			names = append(names, u.names[inst])
		}
		pl.Downtime = downtimeText(hdr.Entries, 3)
		verb := "is"
		if len(names) > 1 {
			verb = "are"
		}
		lines = append(lines, fmt.Sprintf("%s %s stopped for %s, then started.", joinNames(names), verb, pl.Downtime))
	}
	pl.Lines = lines
	doc := struct {
		Kind, Folder, Path, Snapshot string
		GID                          int
		Entries                      int64
		Disk                         *DiskPlan
		Restarts                     []string
		Inputs                       map[string]hashInputs
	}{"undo", id, f.Path, u.apply.Snapshot, f.GID, hdr.Entries, pl.Disk, pl.Restarts, u.inputs}
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	pl.Hash = hex.EncodeToString(sum[:])
	u.plan = pl
	return u, nil
}

// PreviewUndo is the undo of folder id's last fix (contract §14.4):
// 404 without an apply snapshot; nothing changes.
func (h *Hub) PreviewUndo(ctx context.Context, id string) (*AssignPlan, error) {
	u, err := h.computeUndo(ctx, id)
	if err != nil {
		return nil, err
	}
	return u.plan, nil
}

// StartUndo runs the undo in the background once its recomputed plan has
// planHash (else 409): stop → undo snapshot → restore → verify (a restore
// dry run finds nothing left to rewrite) → state (last_apply cleared) →
// start.
func (h *Hub) StartUndo(id, planHash, actor string) (*AsyncOp, error) {
	unlockFolder, err := h.folderLock(id)
	if err != nil {
		return nil, err
	}
	return h.startAsync(opKeyFolder(id), OpFolderUndo, func(ready func()) (result map[string]string, warnings []string, err error) {
		detail := ""
		defer func() {
			if detail != "" || err != nil {
				h.auditFolder(actor, "folder.apply", id, detail, err)
			}
		}()
		defer unlockFolder()
		if err := h.markerPending(id); err != nil {
			return nil, nil, err
		}
		h.mu.RLock()
		set := map[string]bool{}
		for _, x := range h.folderUsesLocked(id) {
			set[x.Instance] = true
		}
		_, exists := h.st.Folders[id]
		h.mu.RUnlock()
		if !exists {
			return nil, nil, ErrNotFound
		}
		affected := slices.Sorted(maps.Keys(set))
		unlockApps, err := h.lockApps(affected)
		if err != nil {
			return nil, nil, err
		}
		defer unlockApps()
		defer h.markApplying(id, affected)()
		u, err := h.computeUndo(context.Background(), id)
		if err != nil {
			return nil, nil, err
		}
		if !slices.Equal(u.affected, affected) || planHash == "" || u.plan.Hash != planHash {
			return nil, nil, errSetupChanged()
		}
		ready()
		result, warnings, detail, err = h.runUndo(id, u)
		return result, warnings, err
	})
}

// runUndo is the accepted undo. The detail names the snapshots also on a
// failure (I4).
func (h *Hub) runUndo(id string, u *undoCalc) (map[string]string, []string, string, error) {
	ctx := context.Background()
	f := u.folder
	result := map[string]string{"snapshot": u.apply.Snapshot}
	var warnings []string
	secrets := h.opSecrets(u.affected)
	detail := func() string {
		d := "undo snapshot=" + snapshotTS(u.apply.Snapshot)
		if s := result["undo_snapshot"]; s != "" {
			d += " safety=" + snapshotTS(s)
		}
		return d
	}
	m := &applyMarker{Kind: "undo", Folder: id, Instances: u.plan.Restarts, Phase: "disk", Snapshot: u.apply.Snapshot,
		Files: u.target.Files, OwnerUID: u.target.OwnerUID, At: time.Now().UTC()}
	var stopped []string
	fail := func(cause error, restored bool) error {
		startErr := h.startAll(stopped)
		h.removeMarker(id)
		msg := cause.Error() + ": the setting values are unchanged"
		if restored {
			msg += "; some entries may already be restored"
			if m.Undo != "" {
				msg += " (undo snapshot " + m.Undo + " records them as they were)"
			}
			msg += "; Undo last fix can run again"
		} else {
			msg += "; nothing on disk changed"
		}
		if startErr != nil {
			msg += "; starting the apps again failed: " + startErr.Error()
		} else if len(stopped) > 0 {
			msg += "; " + joinNames(h.appNames(stopped)) + " started again"
		}
		status := errStatus(cause)
		if restored || startErr != nil {
			status = http.StatusInternalServerError
		}
		sec := append(slices.Clone(secrets), secretsOf(cause)...)
		sec = append(sec, secretsOf(startErr)...)
		return withSecrets(&StatusError{Status: status, Err: errors.New(msg)}, sec)
	}
	if err := h.writeMarker(id, m); err != nil {
		return result, nil, detail(), fail(statusErr(http.StatusInternalServerError, "writing the undo marker: %v", err), false)
	}
	var err error
	stopped, err = h.stopAll(u.plan.Restarts)
	if err != nil {
		return result, nil, detail(), fail(err, false)
	}
	if err := needFree(h.cfg.DataDir, 0, "the undo snapshot of shared folder "+f.Name); err != nil {
		return result, nil, detail(), fail(err, false)
	}
	base := folderfix.Options{ExpectDev: f.Dev, ExpectIno: f.Ino, ExpectMountRoot: f.MountRoot, Target: u.target}
	saved := ""
	urep, err := h.snapshotRun(ctx, u.apply.Snapshot, fixerRun{Mode: "snapshot", Folder: id, Source: f.Path, Opts: base, Extra: folderfix.ArgsExtra{Kind: "undo"},
		Out: func(r io.Reader) error {
			rel, err := h.saveSnapshot(id, r)
			saved = rel
			return err
		}})
	warnings = append(warnings, prefixed("undo snapshot", skippedWarnings(urep))...)
	if err != nil {
		if saved != "" {
			h.dropSnapshot(saved)
		}
		return result, warnings, detail(), fail(fmt.Errorf("the undo snapshot failed: %w", err), false)
	}
	m.Undo = saved
	result["undo_snapshot"] = saved
	// I1: the safety copy is recorded before anything changes.
	if err := h.writeMarker(id, m); err != nil {
		m.Undo = ""
		return result, warnings, detail(), fail(statusErr(http.StatusInternalServerError, "recording the undo snapshot: %v", err), false)
	}
	restoreOpts := folderfix.Options{ExpectDev: f.Dev, ExpectIno: f.Ino, ExpectMountRoot: f.MountRoot, Target: folderfix.Target{GID: f.GID}}
	rep, err := h.snapshotRun(ctx, u.apply.Snapshot, fixerRun{Mode: "restore", Folder: id, Source: f.Path, Opts: restoreOpts})
	warnings = append(warnings, prefixed("restore", skippedWarnings(rep))...)
	if err != nil {
		return result, warnings, detail(), fail(fmt.Errorf("the restore failed: %w", err), errStatus(err) != http.StatusConflict)
	}
	if rep.Failed.N > 0 {
		return result, warnings, detail(), fail(statusErr(http.StatusInternalServerError, "%d entries couldn't be restored", rep.Failed.N), true)
	}
	// Verify (R56): a restore dry run now finds nothing left to rewrite.
	ver, err := h.restoreDryRun(ctx, id, u.apply.Snapshot, f)
	if err != nil {
		return result, warnings, detail(), fail(fmt.Errorf("the undo's verify failed: %w", err), true)
	}
	if ver.ToRestore > 0 {
		return result, warnings, detail(), fail(statusErr(http.StatusInternalServerError, "the undo's verify found %d entries still as the fix left them", ver.ToRestore), true)
	}
	result["entries"] = strconv.FormatInt(rep.Changed, 10)
	result["changed_since"] = strconv.FormatInt(rep.ChangedSince.N, 10)
	if rep.ChangedSince.N > 0 {
		warnings = append(warnings, message.NewPrinter(language.English).Sprintf("%d entries changed since the fix and were left alone", rep.ChangedSince.N))
	}

	m.Phase = "state"
	if err := h.writeMarker(id, m); err != nil {
		return result, warnings, detail(), fail(statusErr(http.StatusInternalServerError, "recording the undo's phase: %v", err), true)
	}
	h.mu.Lock()
	if cur, ok := h.st.Folders[id]; ok && cur.LastApply != nil && cur.LastApply.Snapshot == u.apply.Snapshot {
		prev := cur
		cur.LastApply = nil // R42: an undo can't be undone
		h.st.Folders[id] = cur
		if serr := h.saveStateLocked(); serr != nil {
			h.st.Folders[id] = prev
			log.Printf("shared folders: ERROR: %s: clearing last_apply after the undo: %v", id, serr)
			warnings = append(warnings, "the undo finished but couldn't be recorded: Undo last fix may still be offered")
		}
	}
	h.mu.Unlock()
	startErr := h.startAll(stopped)
	h.removeMarker(id)
	d := fmt.Sprintf("%s entries=%d changed_since=%d", detail(), rep.Changed, rep.ChangedSince.N)
	if startErr != nil {
		err := statusErr(http.StatusInternalServerError, "the undo finished, but %v: start them from the app list", startErr)
		return result, warnings, d, withSecrets(err, append(secrets, secretsOf(startErr)...))
	}
	return result, warnings, d, nil
}

// ── recovery ─────────────────────────────────────────────

// RecoverFolderApplies (Init, after RecoverRestores, background): every
// marker <data>/folders/<id>.applying.json left by a Hub stop. The
// instances it lists are started with what state.yaml holds (phase disk:
// the old values; state: the new ones, if the save landed), the folder's
// op record is marked interrupted and names the snapshot, the marker
// goes. The fixer never runs again. While a marker stays, a new apply or
// undo of the folder is 409 (M7); a recovery that can't take its locks
// records why and keeps the marker for the next start.
func (h *Hub) RecoverFolderApplies() {
	entries, _ := os.ReadDir(h.foldersDir())
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".applying.json")
		if !ok || !settings.FolderIDRe.MatchString(id) {
			continue
		}
		h.goBackground(func() { h.recoverFolderApply(id) })
	}
}

func (h *Hub) recoverFolderApply(id string) {
	key := opKeyFolder(id)
	prev := h.LastOp(key)
	rec := OpRecord{Op: OpFolderAssign, At: time.Now().UTC(), Status: http.StatusInternalServerError}
	if prev != nil {
		rec.Op, rec.OpID = prev.Op, prev.OpID
	}
	data, err := os.ReadFile(h.markerPath(id))
	var m applyMarker
	if err == nil {
		err = json.Unmarshal(data, &m)
	}
	if err != nil {
		rec.Error = fmt.Sprintf("interrupted: the Hub stopped while shared folder %s was being changed, and its marker can't be read (%v): check the apps that use it and start them", id, err)
		h.recordOp(key, rec)
		h.removeMarker(id)
		return
	}
	if m.Kind == "undo" {
		rec.Op = OpFolderUndo
	}
	gaveUp := func(why error) {
		rec.Error = clipRunes(fmt.Sprintf("interrupted, and not recovered yet: %v; %s stay as they are (stopped) until the next Hub start, which tries again — start them by hand meanwhile", why, joinNames(h.appNames(m.Instances))), 600)
		h.recordOp(key, rec)
		log.Printf("shared folders: %s: %s", id, rec.Error)
	}
	unlockFolder, err := h.folderLock(id)
	if err != nil {
		gaveUp(err)
		return
	}
	defer unlockFolder()
	var unlockApps func()
	deadline := time.Now().Add(h.restartWait)
	for {
		u, err := h.lockApps(m.Instances)
		if err == nil {
			unlockApps = u
			break
		}
		if time.Now().After(deadline) {
			gaveUp(err)
			return
		}
		time.Sleep(h.lockPoll)
	}
	var deliver []string
	defer func() {
		// After the locks: the engine would see the instances busy.
		for _, inst := range deliver {
			h.TriggerDelivery(inst, TriggerSave, true)
		}
	}()
	defer unlockApps()

	h.mu.Lock()
	f, defined := h.st.Folders[id]
	name := id
	if defined {
		name = f.Name
	}
	committed := false
	switch m.Kind {
	case "undo":
		committed = !defined || f.LastApply == nil || f.LastApply.Snapshot != m.Snapshot
	default:
		committed = len(m.Values) > 0
		for _, v := range m.Values {
			cur, _ := h.st.Settings[v.Instance].Values[v.Key].(string)
			if cur != v.Value {
				committed = false
			}
		}
		if len(m.Values) == 0 && defined && m.Snapshot != "" {
			committed = f.LastApply != nil && f.LastApply.Snapshot == m.Snapshot
		}
		// The disk may be partly changed: offer the undo (a restore
		// rewrites only entries still as the apply left them).
		if !committed && defined && m.Snapshot != "" && (f.LastApply == nil || f.LastApply.Snapshot != m.Snapshot) {
			prevF := f
			f.LastApply = &state.FolderApply{At: m.At, Files: m.Files, OwnerUID: m.OwnerUID, Snapshot: m.Snapshot}
			h.st.Folders[id] = f
			if err := h.saveStateLocked(); err != nil {
				h.st.Folders[id] = prevF
				log.Printf("shared folders: ERROR: %s: recording the snapshot to undo: %v", id, err)
			}
		}
	}
	h.mu.Unlock()

	var started []string
	for _, inst := range m.Instances {
		if h.IsEnabled(inst) {
			started = append(started, inst)
		}
	}
	startErr := h.startAll(started)
	var b strings.Builder
	fmt.Fprintf(&b, "interrupted: the Hub stopped while shared folder %s was being ", name)
	if m.Kind == "undo" {
		b.WriteString("undone (phase " + m.Phase + ")")
		if committed {
			b.WriteString(": the undo had finished")
		} else {
			b.WriteString(": some entries may already be restored; Undo last fix can run again")
			if m.Undo != "" {
				b.WriteString(" (undo snapshot " + m.Undo + " records them as they were)")
			}
		}
	} else {
		b.WriteString("applied (phase " + m.Phase + ")")
		switch {
		case committed:
			b.WriteString(": the new settings had been saved")
		case m.Snapshot != "":
			b.WriteString(": the settings are unchanged; some permissions may have changed: permissions snapshot " + m.Snapshot + " can undo them (Undo last fix)")
		default:
			b.WriteString(": the settings are unchanged and nothing on disk changed")
		}
	}
	if len(started) > 0 {
		if startErr != nil {
			fmt.Fprintf(&b, "; starting %s failed: %v", joinNames(h.appNames(started)), redactValues(startErr.Error(), secretsOf(startErr)))
		} else {
			fmt.Fprintf(&b, "; %s started again", joinNames(h.appNames(started)))
		}
	}
	rec.Error = clipRunes(b.String(), 600)
	rec.Result = map[string]string{}
	if m.Snapshot != "" {
		rec.Result["snapshot"] = m.Snapshot
	}
	if m.Undo != "" {
		rec.Result["undo_snapshot"] = m.Undo
	}
	h.recordOp(key, rec)
	h.removeMarker(id)
	log.Printf("shared folders: %s", rec.Error)
	if committed && m.Kind != "undo" {
		changed := map[string]bool{}
		for _, v := range m.Values {
			changed[v.Instance] = true
		}
		for _, inst := range slices.Sorted(maps.Keys(changed)) {
			if h.IsEnabled(inst) {
				deliver = append(deliver, inst)
			}
		}
	}
}
