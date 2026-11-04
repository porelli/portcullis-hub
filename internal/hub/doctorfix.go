package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// The doctor's one-click fixes (contract §14.6, Task 12). A fix is
// previewed (PreviewFix: exactly what will change, nothing changed) and
// applied with the preview's hash (ApplyFix: recomputed under the fix's
// locks, any difference 409 "the setup changed since the preview").
// Fixes that touch data go through the folder assignment and undo
// operations (snapshot + verify), never another path; explain-only and
// link findings have no preview (409). Every apply is audited doctor.fix
// besides what its steps audit.

// OpRebind is rebind_port's operation (the instance's own op record).
const OpRebind = "rebind"

// FixPlan is a fix's preview.
type FixPlan struct {
	FP       string      `json:"fp"`
	Kind     string      `json:"fix_kind"`
	Lines    []string    `json:"lines"`
	Warnings []string    `json:"warnings,omitempty"`
	Assign   *AssignPlan `json:"assign,omitempty"`
	Hash     string      `json:"plan_hash"`
}

// Fixer is one kind of one-click fix (Project 3 registers more).
// Preview changes nothing; Apply re-checks planHash and answers 202
// semantics (an AsyncOp) or a synchronous refusal.
type Fixer interface {
	Kind() string
	Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error)
	Apply(h *Hub, f doctor.Finding, params map[string]string, planHash, actor string) (*AsyncOp, error)
}

// fixTargeter is an optional Fixer part: the ids doctor.fix's detail
// names ("fix=<kind> <ids>").
type fixTargeter interface {
	fixTarget(h *Hub, f doctor.Finding, params map[string]string) string
}

var (
	fixersMu sync.RWMutex
	fixers   = map[string]Fixer{}
)

// RegisterFixer adds a fix kind; a kind registered twice panics (init
// time only).
func RegisterFixer(f Fixer) {
	fixersMu.Lock()
	defer fixersMu.Unlock()
	if f.Kind() == "" {
		panic("doctor: a fixer needs a kind")
	}
	if _, dup := fixers[f.Kind()]; dup {
		panic("doctor: fixer " + f.Kind() + " registered twice")
	}
	fixers[f.Kind()] = f
}

func fixerFor(kind string) Fixer {
	fixersMu.RLock()
	defer fixersMu.RUnlock()
	return fixers[kind]
}

func init() {
	RegisterFixer(manageAsFolderFixer{})
	RegisterFixer(reapplyFolderFixer{})
	RegisterFixer(undoFolderFixer{})
	RegisterFixer(rebindPortFixer{})
}

// fixParamFix picks one of a finding's fixes (its fix_kind, else one of
// more_fix_kinds).
const fixParamFix = "fix"

// findingFix is the current finding fp (404) and the fixer its params
// pick: explain-only and link findings, or none, are 409; a fix the
// finding doesn't offer is 400.
func (h *Hub) findingFix(ctx context.Context, fp string, params map[string]string) (doctor.Finding, Fixer, error) {
	r, err := h.Doctor(ctx)
	if err != nil {
		return doctor.Finding{}, nil, err
	}
	var f *doctor.Finding
	for i := range r.Findings {
		if r.Findings[i].FP == fp {
			f = &r.Findings[i]
		}
	}
	if f == nil {
		return doctor.Finding{}, nil, statusErr(http.StatusNotFound, "no finding %s", clip(fp, 32))
	}
	switch {
	case f.Class == doctor.FixExplain:
		msg := "explain-only: this finding has no one-click fix"
		if len(f.Steps) > 0 {
			msg += ". " + strings.Join(f.Steps, " ")
		}
		return *f, nil, statusErr(http.StatusConflict, "%s", msg)
	case f.Class == doctor.FixLink && f.Link != nil:
		return *f, nil, statusErr(http.StatusConflict, "this finding opens the settings panel at %s's setting %s: the doctor never edits setting values itself", f.Link.Instance, f.Link.Option)
	case f.Class != doctor.FixOneClick || f.FixKind == "":
		return *f, nil, statusErr(http.StatusConflict, "this finding has no fix")
	}
	kind := f.FixKind
	if v := params[fixParamFix]; v != "" && v != kind {
		if !slices.Contains(f.MoreFixes, v) {
			return *f, nil, statusErr(http.StatusBadRequest, "this finding doesn't offer fix %q", clip(v, 32))
		}
		kind = v
	}
	fx := fixerFor(kind)
	if fx == nil {
		return *f, nil, statusErr(http.StatusConflict, "fix %s isn't available in this Hub", kind)
	}
	return *f, fx, nil
}

// checkFixParams: only the listed params (and "fix"), one line each.
func checkFixParams(params map[string]string, allowed ...string) error {
	for _, k := range slices.Sorted(maps.Keys(params)) {
		if k != fixParamFix && !slices.Contains(allowed, k) {
			return statusErr(http.StatusBadRequest, "unknown fix parameter %q", clip(k, 32))
		}
		if templates.HasControlChars(params[k]) || len(params[k]) > 1024 {
			return statusErr(http.StatusBadRequest, "fix parameter %s must be one line of text", k)
		}
	}
	return nil
}

// PreviewFix previews finding fp's fix with params (404 unknown fp, 409
// explain-only or link, 400 bad params): nothing changes.
func (h *Hub) PreviewFix(ctx context.Context, fp string, params map[string]string) (*FixPlan, error) {
	f, fx, err := h.findingFix(ctx, fp, params)
	if err != nil {
		return nil, err
	}
	p, err := fx.Preview(ctx, h, f, params)
	if err != nil {
		return nil, err
	}
	p.FP, p.Kind = fp, fx.Kind()
	if p.Lines == nil {
		p.Lines = []string{}
	}
	return p, nil
}

// ApplyFix applies finding fp's fix once its recomputed plan has
// planHash (else 409): 202 semantics. Audited doctor.fix (target fp,
// detail "fix=<kind> <ids> op=<op id>"; refusals refused) after the call
// returns, never under a lock of the Hub's.
func (h *Hub) ApplyFix(ctx context.Context, fp string, params map[string]string, planHash, actor string) (op *AsyncOp, err error) {
	detail := ""
	defer func() { h.auditDoctor(actor, "doctor.fix", fp, detail, err) }()
	if actor == "" {
		return nil, statusErr(http.StatusUnauthorized, "a fix needs a signed-in admin")
	}
	f, fx, err := h.findingFix(ctx, fp, params)
	if err != nil {
		return nil, err
	}
	detail = "fix=" + fx.Kind()
	if t, ok := fx.(fixTargeter); ok {
		if ids := t.fixTarget(h, f, params); ids != "" {
			detail += " " + ids
		}
	}
	op, err = fx.Apply(h, f, params, planHash, actor)
	if op != nil {
		detail += " op=" + op.OpID
	}
	return op, err
}

// fixHash is sha256 of v's JSON.
func fixHash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		log.Printf("doctor: fix hash: %v", err)
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ── reapply_folder ──────────────────────────────────────

type reapplyFolderFixer struct{}

func (reapplyFolderFixer) Kind() string { return doctor.FixReapplyFolder }

func (reapplyFolderFixer) fixTarget(_ *Hub, f doctor.Finding, _ map[string]string) string {
	return strings.Join(f.Folders, ",")
}

// findingFolder is the one folder finding f is about.
func findingFolder(f doctor.Finding) (string, error) {
	if len(f.Folders) != 1 {
		return "", statusErr(http.StatusConflict, "this finding names no single shared folder")
	}
	return f.Folders[0], nil
}

// reapplyRequest is folder id's current uses as an assignment that keeps
// them all and plans the disk (contract §14.6: the assignment of the
// folder's current uses).
func (h *Hub) reapplyRequest(id string) (AssignRequest, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if _, ok := h.st.Folders[id]; !ok {
		return AssignRequest{}, ErrNotFound
	}
	req := AssignRequest{Uses: []FolderUse{}, reapply: true}
	for _, u := range h.folderUsesLocked(id) {
		req.Uses = append(req.Uses, FolderUse{Instance: u.Instance, Key: u.Key, Subpath: u.Subpath,
			Write: !u.Declared && u.Access == templates.FolderWrite})
	}
	if len(req.Uses) == 0 {
		return req, statusErr(http.StatusConflict, "shared folder %s has no uses to apply it for: assign it first", id)
	}
	return req, nil
}

func (reapplyFolderFixer) Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	if err := checkFixParams(params); err != nil {
		return nil, err
	}
	id, err := findingFolder(f)
	if err != nil {
		return nil, err
	}
	req, err := h.reapplyRequest(id)
	if err != nil {
		return nil, err
	}
	plan, err := h.PreviewAssign(ctx, id, req)
	if err != nil {
		return nil, err
	}
	// The assignment's hash: StartAssign recomputes and compares it under
	// the folder's and the instances' locks.
	return &FixPlan{Lines: plan.Lines, Warnings: plan.Warnings, Assign: plan, Hash: plan.Hash}, nil
}

func (reapplyFolderFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash, actor string) (*AsyncOp, error) {
	if err := checkFixParams(params); err != nil {
		return nil, err
	}
	id, err := findingFolder(f)
	if err != nil {
		return nil, err
	}
	req, err := h.reapplyRequest(id)
	if err != nil {
		return nil, err
	}
	return h.StartAssign(id, req, planHash, actor)
}

// ── undo_folder ─────────────────────────────────────────

type undoFolderFixer struct{}

func (undoFolderFixer) Kind() string { return doctor.FixUndoFolder }

func (undoFolderFixer) fixTarget(_ *Hub, f doctor.Finding, _ map[string]string) string {
	return strings.Join(f.Folders, ",")
}

func (undoFolderFixer) Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	if err := checkFixParams(params); err != nil {
		return nil, err
	}
	id, err := findingFolder(f)
	if err != nil {
		return nil, err
	}
	plan, err := h.PreviewUndo(ctx, id)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: plan.Lines, Warnings: plan.Warnings, Assign: plan, Hash: plan.Hash}, nil
}

func (undoFolderFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash, actor string) (*AsyncOp, error) {
	if err := checkFixParams(params); err != nil {
		return nil, err
	}
	id, err := findingFolder(f)
	if err != nil {
		return nil, err
	}
	return h.StartUndo(id, planHash, actor)
}

// ── manage_as_folder ────────────────────────────────────

type manageAsFolderFixer struct{}

func (manageAsFolderFixer) Kind() string { return doctor.FixManageAsFolder }

func (manageAsFolderFixer) fixTarget(_ *Hub, f doctor.Finding, params map[string]string) string {
	if in, err := manageInput(f, params); err == nil {
		return in.ID
	}
	return ""
}

// slugID is s as a folder id: lowercase, other characters as "-", a
// letter first ("folder-" otherwise), at most 31 characters.
func slugID(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" || id[0] < 'a' || id[0] > 'z' {
		id = strings.Trim("folder-"+id, "-")
	}
	if len(id) > 31 {
		id = strings.TrimRight(id[:31], "-")
	}
	return id
}

// manageInput is the definition manage_as_folder creates: the finding's
// one path, params name and id (defaults: the path's base name, slugged).
func manageInput(f doctor.Finding, params map[string]string) (FolderInput, error) {
	if err := checkFixParams(params, "name", "id"); err != nil {
		return FolderInput{}, err
	}
	if len(f.Paths) != 1 {
		return FolderInput{}, statusErr(http.StatusConflict, "this finding names no single path")
	}
	p := f.Paths[0]
	in := FolderInput{Path: p, Name: strings.TrimSpace(params["name"]), ID: strings.TrimSpace(params["id"])}
	if in.Name == "" {
		in.Name = path.Base(p)
	}
	if in.ID == "" {
		in.ID = slugID(path.Base(p))
	}
	if !settings.FolderIDRe.MatchString(in.ID) {
		return in, statusErr(http.StatusBadRequest, "the folder id must match %s", settings.FolderIDRe)
	}
	if err := checkFolderFields(in); err != nil {
		return in, err
	}
	return in, nil
}

// manageCalc is manage_as_folder's computed plan.
type manageCalc struct {
	in     FolderInput
	path   string
	folder state.Folder // as the create would store it (predicted gid)
	req    AssignRequest
	assign *assignCalc
	lines  []string
	warns  []string
	hash   string
}

// managePlan computes manage_as_folder for in: the finding's setting uses
// of the path (a custom-override use: explain-only, 409), the create's
// checks, probe and check and its predicted definition (planFolderHeld),
// then the assignment of those uses to it, planned as a definition not
// stored yet (computeAssignFor). Nothing changes.
func (h *Hub) managePlan(ctx context.Context, in FolderInput) (*manageCalc, error) {
	p, err := h.folderPrechecks(ctx, in)
	if err != nil {
		return nil, err
	}
	c := &manageCalc{in: in, path: p, req: AssignRequest{Uses: []FolderUse{}}}
	h.mu.RLock()
	for _, u := range h.pathUsagesLocked() {
		if u.HostPath != p {
			continue
		}
		if u.Source != PathSourceSetting {
			h.mu.RUnlock()
			return nil, statusErr(http.StatusConflict, "explain-only: %s mounts %s in its custom override: remove the mount in Expert and use the template's folder setting with a shared folder", u.Instance, p)
		}
		c.req.Uses = append(c.req.Uses, FolderUse{Instance: u.Instance, Key: u.Key, Write: !u.Declared && u.Writes})
	}
	h.mu.RUnlock()
	if len(c.req.Uses) == 0 {
		return nil, errSetupChanged()
	}
	if c.folder, c.warns, err = h.planFolderHeld(ctx, in, p); err != nil {
		return nil, err
	}
	if c.assign, err = h.computeAssignFor(ctx, in.ID, c.req, &c.folder); err != nil {
		return nil, err
	}
	c.lines = append(c.lines, fmt.Sprintf("Shared folder *%s* (id %s) is defined at %s.", in.Name, in.ID, p))
	for _, e := range c.assign.edits {
		c.lines = append(c.lines, fmt.Sprintf("%s's %s: %s → %s.", c.assign.names[e.Instance], e.label, e.before, e.Value))
	}
	c.lines = append(c.lines, c.assign.plan.Lines...)
	c.warns = append(c.warns, c.assign.plan.Warnings...)
	fd := c.folder
	c.hash = fixHash(struct {
		Kind, ID, Name, Path, MountRoot, Assign string
		GID                                     int
		Adopted                                 bool
		Dev, Ino                                uint64
	}{doctor.FixManageAsFolder, in.ID, in.Name, p, fd.MountRoot, c.assign.plan.Hash, fd.GID, fd.Adopted, fd.Dev, fd.Ino})
	return c, nil
}

func (manageAsFolderFixer) Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	in, err := manageInput(f, params)
	if err != nil {
		return nil, err
	}
	c, err := h.managePlan(ctx, in)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: c.lines, Warnings: c.warns, Assign: c.assign.plan, Hash: c.hash}, nil
}

// Apply (ruling 34): under the new id's folder lock, held throughout,
// the plan is recomputed (any difference, the predicted gid included,
// 409 before anything is defined), the definition created, then the
// assignment validated and started (startAssignHeld, which takes over the
// lock). A refusal after the create — a definition other than the
// planned one, the assignment's own recomputation differing, busy —
// deletes the definition again (its gid stays used: never reused) and
// answers the refusal. folder.create / folder.delete are audited after
// the lock is released.
func (manageAsFolderFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash, actor string) (op *AsyncOp, err error) {
	in, err := manageInput(f, params)
	if err != nil {
		return nil, err
	}
	unlock, err := h.folderLock(in.ID)
	if err != nil {
		return nil, err
	}
	held := true
	var createDetail, deleteDetail string
	var createErr, deleteErr error
	created, deleted := false, false
	defer func() {
		if held {
			unlock()
		}
		if created || createErr != nil {
			h.auditFolder(actor, "folder.create", in.ID, createDetail, createErr)
		}
		if deleted {
			h.auditFolder(actor, "folder.delete", in.ID, deleteDetail, deleteErr)
		}
	}()
	ctx := context.Background()
	c, err := h.managePlan(ctx, in)
	if err != nil {
		return nil, err
	}
	if planHash == "" || c.hash != planHash {
		return nil, errSetupChanged()
	}
	var fd state.Folder
	fd, _, _, createDetail, createErr = h.defineFolderHeld(ctx, in, c.path)
	if createErr != nil {
		return nil, createErr
	}
	created = true
	undefine := func() {
		deleteDetail, deleteErr = h.deleteFolderHeld(in.ID)
		deleted = true
		if deleteErr != nil {
			log.Printf("doctor: manage_as_folder: deleting the new definition %s failed: %v", in.ID, deleteErr)
		}
	}
	if fd.GID != c.folder.GID || fd.Adopted != c.folder.Adopted || fd.Dev != c.folder.Dev || fd.Ino != c.folder.Ino || fd.MountRoot != c.folder.MountRoot {
		undefine()
		return nil, errSetupChanged()
	}
	if h.testHookManageDefined != nil {
		h.testHookManageDefined()
	}
	// startAssignHeld releases the folder lock when its operation ends,
	// or after onRefused when it refuses (startAsync returns only then).
	// An accepted operation that fails keeps the definition (its
	// last_apply may hold the undo; the gid is used either way): the op
	// record says so (M3).
	kept := fmt.Sprintf("shared folder %s was defined (gid %d) and is kept: assign it again or delete it", in.ID, fd.GID)
	held = false
	op, err = h.startAssignHeld(in.ID, c.req, c.assign.plan.Hash, actor, unlock, func(error) { undefine() },
		func(err error) error { return noteErr(err, kept) })
	return op, err
}

// noteErr is err with note appended to its message, its status kept (an
// OpError's record too).
func noteErr(err error, note string) error {
	var oe *OpError
	if errors.As(err, &oe) {
		r := oe.Record
		r.Error += "; " + note
		return &OpError{Record: r, Err: oe.Err}
	}
	return fmt.Errorf("%w; %s", err, note)
}

// ── rebind_port ─────────────────────────────────────────

type rebindPortFixer struct{}

func (rebindPortFixer) Kind() string { return doctor.FixRebindPort }

func (rebindPortFixer) fixTarget(h *Hub, f doctor.Finding, _ map[string]string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if p, ok := h.rebindPortLocked(f); ok {
		return p.Instance + "/" + p.Key
	}
	return ""
}

// rebindPortLocked is the template port rebind_port finding f is about
// (never a custom-override port: the Hub never writes the custom
// override; never a host-network port: compose publishes nothing for it,
// so <KEY>_BIND can't move it). Caller holds mu.
func (h *Hub) rebindPortLocked(f doctor.Finding) (doctor.PortIn, bool) {
	for _, p := range h.portInsLocked() {
		if !p.Custom && !p.HostNetwork && p.LanOnly && doctor.PortFP(p) == f.FP {
			return p, true
		}
	}
	return doctor.PortIn{}, false
}

// rebindCalc is rebind_port's computed plan.
type rebindCalc struct {
	port          doctor.PortIn
	tmpl          *templates.Template // a copy
	addr, oldBind string
	cur, next     map[string]string
	lines, warns  []string
	hash          string
}

// rebindAddress checks the typed address (400): an IP, no zone, not
// unspecified, inside the local networks, not a main-domain address.
// A failed lookup of the main domain is a warning only.
func (h *Hub) rebindAddress(ctx context.Context, s string) (netip.Addr, []string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return a, nil, statusErr(http.StatusBadRequest, "the address must be an IP address, e.g. 192.168.1.10")
	}
	a = a.Unmap()
	if a.IsUnspecified() {
		return a, nil, statusErr(http.StatusBadRequest, "%s is every interface: give the host's LAN address", a)
	}
	if !IsLocal(a, h.LocalNetworks()) {
		return a, nil, statusErr(http.StatusBadRequest, "%s isn't in the local networks (Hub Settings → Local networks)", a)
	}
	var warns []string
	addrs, derr := h.domainAddrs(ctx)
	if derr != nil {
		warns = append(warns, fmt.Sprintf("couldn't resolve %s: the address wasn't checked against its addresses", h.cfg.Domain))
	}
	for _, d := range addrs {
		if d.Unmap() == a {
			return a, nil, statusErr(http.StatusBadRequest, "%s is an address of %s, where the internet reaches the Hub: give a LAN-only address", a, h.cfg.Domain)
		}
	}
	return a, warns, nil
}

// rebindPlan computes rebind_port: the address, the finding's template
// port (enabled instance, not being applied) and the whole port
// configuration with <KEY>_BIND set to it. Nothing changes.
func (h *Hub) rebindPlan(ctx context.Context, f doctor.Finding, params map[string]string) (*rebindCalc, error) {
	if err := checkFixParams(params, "address"); err != nil {
		return nil, err
	}
	a, warns, err := h.rebindAddress(ctx, params["address"])
	if err != nil {
		return nil, err
	}
	c := &rebindCalc{addr: a.String(), warns: warns}
	h.mu.RLock()
	p, ok := h.rebindPortLocked(f)
	var t *templates.Template
	if ok {
		if l := h.findLocked(p.Instance); l != nil {
			cp := *l
			t = &cp
		}
	}
	enabled := h.st.IsEnabled(p.Instance)
	pend := h.pendingLocked(p.Instance)
	c.cur = maps.Clone(h.st.Settings[p.Instance].Ports)
	h.mu.RUnlock()
	if !ok || t == nil || !enabled {
		return nil, errSetupChanged()
	}
	if pend != nil {
		return nil, pend
	}
	c.port, c.tmpl, c.oldBind = p, t, p.Bind
	if c.oldBind == "" {
		c.oldBind = "0.0.0.0"
	}
	if ob, err := netip.ParseAddr(strings.Trim(c.oldBind, "[]")); err == nil && ob.Unmap() == a {
		return nil, statusErr(http.StatusBadRequest, "%s is already bound to %s", p.Key, a)
	}
	c.next = maps.Clone(c.cur)
	if c.next == nil {
		c.next = map[string]string{}
	}
	c.next[p.Key+"_BIND"] = c.addr
	if err := validatePorts(t, c.next); err != nil {
		return nil, err
	}
	src, err := templates.SourceHash(t)
	if err != nil {
		src = "error: " + err.Error()
	}
	c.lines = []string{fmt.Sprintf("%s bind %s → %s, %s restarts", p.Key, c.oldBind, c.addr, appName(t))}
	c.hash = fixHash(struct {
		Kind, FP, Instance, Key, Old, Addr, Source string
		Ports                                      map[string]string
		Enabled                                    bool
	}{doctor.FixRebindPort, f.FP, p.Instance, p.Key, c.oldBind, c.addr, src, c.cur, enabled})
	return c, nil
}

func (rebindPortFixer) Preview(ctx context.Context, h *Hub, f doctor.Finding, params map[string]string) (*FixPlan, error) {
	c, err := h.rebindPlan(ctx, f, params)
	if err != nil {
		return nil, err
	}
	return &FixPlan{Lines: c.lines, Warnings: c.warns, Hash: c.hash}, nil
}

// Apply (ruling 35): op rebind on the instance's own record, under its
// lockApp: the plan recomputed (409 on another hash), validated like a
// port save (parseSettings with the whole port configuration, the
// collision check), state, override and env written under mu, then
// restarted inline (restartLocked: no background Restart waiting on the
// held lock). A failed restart puts the old <KEY>_BIND back while it is
// still this rebind's address (a save committed meanwhile is kept, and a
// bind changed meanwhile is left and reported), regenerates from the
// current state and, when the restart had stopped the instance, starts
// it again (composeUp): an OpError with the restart's reason, rolled_back
// only when the old bind is back and running. A failed down alone (the
// up worked) is a warning. Audited settings.change (ports)
// after the lock is released.
func (rebindPortFixer) Apply(h *Hub, f doctor.Finding, params map[string]string, planHash, actor string) (*AsyncOp, error) {
	ctx := context.Background()
	c0, err := h.rebindPlan(ctx, f, params)
	if err != nil {
		return nil, err
	}
	inst := c0.port.Instance
	return h.startAsync(inst, OpRebind, func(ready func()) (map[string]string, []string, error) {
		var changes []settingChange
		var auditErr error
		defer func() {
			for _, ch := range changes {
				h.auditOp(actor, "settings.change", inst+"/"+ch.key, "scope="+ch.scope+": "+ch.before+" -> "+ch.after, auditErr)
			}
		}()
		unlock, err := h.lockApp(inst)
		if err != nil {
			return nil, nil, err
		}
		defer unlock()
		defer h.TriggerReconcile()
		c, err := h.rebindPlan(ctx, f, params)
		if err != nil {
			return nil, nil, err
		}
		if planHash == "" || c.hash != planHash || c.port.Instance != inst {
			return nil, nil, errSetupChanged()
		}
		t := c.tmpl
		h.mu.RLock()
		folders := h.folderSourceLocked()
		h.mu.RUnlock()
		parsed, err := parseSettings(t, h.kinds, folders, SettingsUpdate{Ports: c.next})
		if err != nil {
			return nil, nil, err
		}
		members := h.groupSnapshot(inst)

		// write puts s in state and regenerates the override and env.
		// Caller holds mu.
		write := func(s state.InstanceSettings) error {
			if s.IsZero() {
				delete(h.st.Settings, inst)
			} else {
				h.st.Settings[inst] = s
			}
			if err := h.saveStateLocked(); err != nil {
				return err
			}
			if err := h.generateOverrideLocked(t, s); err != nil {
				return statusErr(http.StatusInternalServerError, "override generation failed: %v", err)
			}
			return h.writeOptionEnvLocked(t, members)
		}
		h.mu.Lock()
		if err := h.pendingLocked(inst); err != nil {
			h.mu.Unlock()
			return nil, nil, err
		}
		prev := h.st.Settings[inst].Clone()
		if !maps.Equal(prev.Ports, c.cur) {
			h.mu.Unlock()
			return nil, nil, errSetupChanged()
		}
		next, _, _, ch, err := h.nextSettingsLocked(t, prev, parsed)
		if err != nil {
			h.mu.Unlock()
			return nil, nil, err
		}
		h.st.Settings[inst] = next
		if err := h.checkPortCollisionsLocked(t); err != nil {
			h.st.Settings[inst] = prev
			h.mu.Unlock()
			return nil, nil, err
		}
		if err := write(next); err != nil {
			// Nothing restarted: the previous configuration back.
			if werr := write(prev); werr != nil {
				log.Printf("rebind %s: putting the previous configuration back failed: %v", inst, werr)
			}
			h.mu.Unlock()
			return nil, nil, err
		}
		h.mu.Unlock()
		changes = ch
		ready()

		stopped, downErr, rerr := h.restartSteps(t)
		if rerr == nil {
			// The up with the new bind worked: a failed down before it
			// is no failed rebind (M2).
			warns := slices.Clone(c.warns)
			if downErr != nil {
				warns = append(warns, fmt.Sprintf("compose down failed before the restart (%v): the up with the new bind worked, but some containers may not have been recreated", downErr))
			}
			return map[string]string{"bind": c.addr, "key": c.port.Key}, warns, nil
		}
		// Roll back only <KEY>_BIND, and only while it is still this
		// rebind's address (I2: a save committed during the restart is
		// kept), then regenerate from the current state; start the
		// instance again only if the restart stopped it (M2).
		bindKey := c.port.Key + "_BIND"
		h.mu.Lock()
		now := h.st.Settings[inst].Clone()
		nowBind, nowSet := now.Ports[bindKey]
		ours := nowBind == c.addr
		if ours {
			if old, had := c.cur[bindKey]; had {
				now.Ports[bindKey] = old
			} else {
				delete(now.Ports, bindKey)
				if len(now.Ports) == 0 {
					now.Ports = nil
				}
			}
		}
		werr := write(now)
		h.mu.Unlock()
		var uerr error
		if stopped {
			uerr = h.composeUp(t)
		}
		name := appName(t)
		var cfg, start string
		switch {
		case werr != nil:
			cfg = fmt.Sprintf("putting the old bind %s back failed (%v); %s may still use %s", c.oldBind, werr, name, c.addr)
		case !ours:
			shown := nowBind
			if !nowSet || shown == "" {
				shown = "the default"
			}
			cfg = fmt.Sprintf("%s changed since the rebind started (now %s): left as it is", bindKey, shown)
		default:
			cfg = fmt.Sprintf("the old bind %s was put back", c.oldBind)
		}
		switch {
		case !stopped:
			start = fmt.Sprintf("nothing was stopped: %s still runs as it was", name)
		case uerr != nil:
			start = fmt.Sprintf("starting %s again failed (%v)", name, uerr)
		default:
			start = fmt.Sprintf("%s started again", name)
		}
		err = fmt.Errorf("%s; %s: restarting with %s bind %s failed: %w", cfg, start, c.port.Key, c.addr, rerr)
		auditErr = err
		// rolled_back only when the old bind is back and the instance
		// runs with it (M1).
		rolledBack := ours && werr == nil && (!stopped || uerr == nil)
		return nil, c.warns, &OpError{Record: h.opRecordOf(inst, OpRebind, err, rolledBack), Err: err}
	})
}
