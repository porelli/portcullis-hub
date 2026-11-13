package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/settings"
)

// The Portcullis MCP's doctor and shared-folder tools (plan 4 Task 20;
// contract §14.8, §15.10, G15, G45). Each tool's Run calls the same Server
// work its HTTP twin's handler calls (doctorScan, applyFix, muteFinding,
// createFolder, startAssign, …: the same Hub method, its checks, locks
// and audit, attributed via ai and the AI client with the consumed
// confirmation of a D call) — never an HTTP loopback.
//
// Classes: doctor_apply_fix is D when its plan touches data
// (Hub.FixTouchesData: re-derived like ApplyFix, fail closed) and for a
// zone-wide DNSSEC signing (dnssec_sign; Hub.FixNeedsConfirmation);
// folder_apply is D when its plan widens access (AssignPlan.WidensAccess:
// adds a use or changes the disk), judged on the plan whose hash the call
// carries; folder_recheck_apply is D when it accepts another directory;
// delete_folder and folder_undo_apply are always D. The Hub refuses the
// same operations from the AI without a confirmation (defence in depth).

// Argument types.
type (
	fpArgs struct {
		FP string `json:"fp" jsonschema:"the finding's fingerprint (fp, 16 hex) from doctor_findings"`
	}
	// fixArgs are a fix's params as named fields (no free-form map): fix
	// picks one of the finding's fixes, rebind_port takes address,
	// manage_as_folder name and id.
	fixArgs struct {
		FP      string `json:"fp" jsonschema:"the finding's fingerprint (fp) from doctor_findings"`
		Fix     string `json:"fix,omitempty" jsonschema:"one of the finding's fixes (fix_kind or more_fix_kinds; default fix_kind)"`
		Address string `json:"address,omitempty" jsonschema:"rebind_port: the LAN address to bind the port to"`
		Name    string `json:"name,omitempty" jsonschema:"manage_as_folder: the new shared folder's name"`
		ID      string `json:"id,omitempty" jsonschema:"manage_as_folder: the new shared folder's id"`
	}
	applyFixArgs struct {
		fixArgs
		PlanHash string `json:"plan_hash" jsonschema:"the plan_hash doctor_preview_fix answered for the same arguments"`
	}
	muteArgs struct {
		FP           string `json:"fp" jsonschema:"the finding's fingerprint (fp)"`
		Reason       string `json:"reason" jsonschema:"why it is muted (one line, at most 200 characters)"`
		FindingToken string `json:"finding_token" jsonschema:"the finding's token from doctor_findings (a digest of what it judged: the mute is refused if the finding changed since)"`
	}
	folderIDArgs struct {
		ID string `json:"id" jsonschema:"the shared folder's id"`
	}
	createFolderArgs struct {
		ID          string `json:"id" jsonschema:"the new folder's id (lowercase letters, digits and -, a letter first)"`
		Name        string `json:"name" jsonschema:"its name (one line, at most 64 characters)"`
		Path        string `json:"path" jsonschema:"its host path, under one of the Hub's bind roots"`
		Description string `json:"description,omitempty" jsonschema:"what it holds (at most 500 characters)"`
		GID         *int   `json:"gid,omitempty" jsonschema:"adopt this existing host group (a number) instead of allocating one"`
		Create      bool   `json:"create,omitempty" jsonschema:"create the directory if it doesn't exist (default false)"`
	}
	updateFolderArgs struct {
		ID          string `json:"id" jsonschema:"the shared folder's id"`
		Name        string `json:"name" jsonschema:"its name"`
		Path        string `json:"path" jsonschema:"its host path (a change only while no app uses it)"`
		Description string `json:"description" jsonschema:"what it holds"`
	}
	checkPathArgs struct {
		Path string `json:"path" jsonschema:"the host path to check (nothing is created)"`
	}
	assignArgs struct {
		ID   string          `json:"id" jsonschema:"the shared folder's id"`
		Uses []hub.FolderUse `json:"uses" jsonschema:"the full desired set of the folder's uses ([] removes every use)"`
	}
	assignApplyArgs struct {
		assignArgs
		PlanHash string `json:"plan_hash" jsonschema:"the plan_hash folder_preview answered for the same uses"`
	}
	planHashArgs struct {
		ID       string `json:"id" jsonschema:"the shared folder's id"`
		PlanHash string `json:"plan_hash" jsonschema:"the plan_hash of the matching preview"`
	}
	recheckApplyArgs struct {
		ID               string `json:"id" jsonschema:"the shared folder's id"`
		PlanHash         string `json:"plan_hash" jsonschema:"the plan_hash folder_recheck_preview answered"`
		ConfirmDifferent bool   `json:"confirm_different_directory,omitempty" jsonschema:"accept a different directory (the preview's different_directory): forgets the last apply"`
	}
)

// params is the fix's params map as the route takes it (nil: none, as
// a body without params decodes).
func (a fixArgs) params() map[string]string {
	var p map[string]string
	for k, v := range map[string]string{"fix": a.Fix, "address": a.Address, "name": a.Name, "id": a.ID} {
		if v != "" {
			if p == nil {
				p = map[string]string{}
			}
			p[k] = v
		}
	}
	return p
}

// fpOK is the {fp} rule of the doctor routes (findingFP: 404).
func fpOK(fp string) error {
	if !fpRe.MatchString(fp) {
		return &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no such finding")}
	}
	return nil
}

// folderIDOK is the {id} rule of the folder routes (folderID: 400).
func folderIDOK(id string) error {
	if !settings.FolderIDRe.MatchString(id) {
		return badArg("invalid shared folder id")
	}
	return nil
}

// apiErr is a Hub error as writeAPIErr answers it: a bare ErrNotFound is
// 404 "no such shared folder, finding or snapshot".
func apiErr(err error) error {
	if err != nil && errors.Is(err, hub.ErrNotFound) && err.Error() == hub.ErrNotFound.Error() {
		return &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no such shared folder, finding or snapshot")}
	}
	return err
}

// opRecordOf is the op record under key (the routes' writeOpRecord: 404
// when none).
func (s *Server) opRecordOf(key, what string) (*hub.OpRecord, error) {
	rec := s.Hub.LastOp(key)
	if rec == nil {
		return nil, &hub.StatusError{Status: http.StatusNotFound, Err: errors.New("no operation recorded for " + what)}
	}
	return rec, nil
}

func (s *Server) registerDoctorTools() {
	for _, t := range []Tool{
		// ── The doctor ──
		admin("doctor_findings", "The doctor's report: every finding (severity, title, why, the instances, folders and paths, the fix — one-click, explain-only with steps, or a link — its fp and token), the counts, the muted ones and the disk scans. It runs the configuration checks now; doctor_scan runs the disk checks.",
			ClassRead, "GET /api/doctor", "", func(ctx context.Context, _ directory.Actor, _ noArgs) (any, error) {
				return s.Hub.Doctor(ctx)
			}),
		admin("doctor_scan", "Run the doctor's disk checks (every shared folder and checked host path, then the containers' groups) in the background: answers {op_id, op, instance, poll}; see doctor_op.",
			ClassWrite, "POST /api/doctor/scan", "doctor.scan", func(_ context.Context, a directory.Actor, _ noArgs) (any, error) {
				op, err := s.doctorScan(a)
				if err != nil {
					return nil, err
				}
				return opAcceptedBody(op), nil
			}),
		admin("doctor_op", "The doctor's last disk-check operation record (running, then ok / error with its result and warnings).",
			ClassRead, "GET /api/doctor/op", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				return s.opRecordOf("_doctor", "the doctor")
			}),
		admin("doctor_preview_fix", "What a finding's one-click fix would do (nothing changes): its lines, warnings, the assignment plan of a folder fix, touches_data (whether it changes data on disk or revokes access) and the plan_hash doctor_apply_fix needs. Explain-only and link findings have no preview.",
			ClassRead, "POST /api/doctor/findings/{fp}/preview", "", func(ctx context.Context, _ directory.Actor, in fixArgs) (any, error) {
				if err := fpOK(in.FP); err != nil {
					return nil, err
				}
				p, err := s.Hub.PreviewFix(ctx, in.FP, in.params())
				return p, apiErr(err)
			}),
		perCallCtx(admin("doctor_apply_fix", "Apply a finding's one-click fix previewed with doctor_preview_fix (the same arguments and its plan_hash; a change since is refused). Runs in the background: answers {op_id, op, instance, poll}. A fix that changes data on disk or revokes access (touches_data), or turns on DNSSEC signing for a whole zone (dnssec_sign), needs your confirmation in the browser.",
			ClassWrite, "POST /api/doctor/findings/{fp}/apply", "doctor.fix", func(ctx context.Context, a directory.Actor, in applyFixArgs) (any, error) {
				if err := fpOK(in.FP); err != nil {
					return nil, err
				}
				op, err := s.applyFix(ctx, in.FP, in.params(), in.PlanHash, a)
				if err != nil {
					return nil, apiErr(err)
				}
				return opAcceptedBody(op), nil
			}), s.fixClass, argReader("fp"), s.fixConsequences),
		perCallCtx(admin("doctor_mute", "Mute a finding with a reason; it comes back as soon as what it judged changes. finding_token is the finding's token from doctor_findings (a finding that changed since is refused). Muting a Problem or an AI revocation finding needs your confirmation in the browser.",
			ClassWrite, "POST /api/doctor/findings/{fp}/mute", "doctor.mute", func(ctx context.Context, a directory.Actor, in muteArgs) (any, error) {
				if err := fpOK(in.FP); err != nil {
					return nil, err
				}
				// MuteFinding runs the doctor again: the token is checked
				// against the finding as it is now.
				if err := s.muteFinding(ctx, in.FP, in.Reason, a, in.FindingToken); err != nil {
					return nil, apiErr(err)
				}
				return map[string]string{"status": "muted"}, nil
			}), s.muteClass, argReader("fp"), s.muteConsequences),
		admin("doctor_unmute", "Unmute a finding.",
			ClassWrite, "DELETE /api/doctor/findings/{fp}/mute", "doctor.unmute", func(_ context.Context, a directory.Actor, in fpArgs) (any, error) {
				if err := fpOK(in.FP); err != nil {
					return nil, err
				}
				if err := s.unmuteFinding(in.FP, a); err != nil {
					return nil, apiErr(err)
				}
				return map[string]string{"status": "unmuted"}, nil
			}),
		// ── Shared folders ──
		admin("list_folders", "Every shared folder: id, name, path, description, its group (gid, adopted), its uses (instance, option, subpath, access, read-only), its last operation and last disk check.",
			ClassRead, "GET /api/folders", "", func(context.Context, directory.Actor, noArgs) (any, error) {
				fs := s.Hub.Folders()
				if fs == nil {
					fs = []hub.FolderView{}
				}
				return map[string]any{"folders": fs}, nil
			}),
		admin("create_folder", "Define a shared folder (name, host path; a group is allocated, or an existing host group adopted with gid). Nothing on disk changes (create: true only makes a missing directory); assign it to apps with folder_preview / folder_apply.",
			ClassWrite, "POST /api/folders", "folder.create", func(ctx context.Context, a directory.Actor, in createFolderArgs) (any, error) {
				view, warns, err := s.createFolder(ctx, hub.FolderInput{ID: in.ID, Name: in.Name, Path: in.Path, Description: in.Description, GID: in.GID, Create: in.Create}, a)
				if err != nil {
					return nil, apiErr(err)
				}
				if warns == nil {
					warns = []string{}
				}
				return map[string]any{"folder": view, "warnings": warns}, nil
			}),
		admin("update_folder", "Change a shared folder's name and description (and its path while no app uses it).",
			ClassWrite, "PUT /api/folders/{id}", "folder.update", func(ctx context.Context, a directory.Actor, in updateFolderArgs) (any, error) {
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				view, err := s.updateFolder(ctx, in.ID, hub.FolderInput{Name: in.Name, Path: in.Path, Description: in.Description}, a)
				if err != nil {
					return nil, apiErr(err)
				}
				return map[string]any{"folder": view}, nil
			}),
		{Name: "delete_folder", Description: "Delete a shared folder's definition (refused while an app uses it). Its files are never touched; its group number stays used.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "DELETE /api/folders/{id}", Audit: "folder.delete", In: folderIDArgs{},
			Typed: idOf,
			Consequences: func(_ context.Context, args json.RawMessage) []string {
				return []string{"Deletes the definition of shared folder " + idOf(args) + ": nothing on disk changes, and its group number is never reused."}
			},
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, _ := decode[folderIDArgs](args)
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				if err := s.deleteFolder(in.ID, toolActor(ctx, c)); err != nil {
					return nil, apiErr(err)
				}
				return map[string]string{"status": "deleted"}, nil
			}},
		admin("check_folder_path", "Check a host path before defining a folder there: whether it exists, its filesystem, ACL and xattr support, the files, directories and owners, and problems in plain words. Nothing is created or changed.",
			ClassRead, "POST /api/folders/check", "", func(ctx context.Context, _ directory.Actor, in checkPathArgs) (any, error) {
				pc, err := s.checkFolderPath(ctx, in.Path, false)
				return pc, apiErr(err)
			}),
		admin("folder_preview", "What assigning a shared folder to these uses would do (nothing changes): per use add / remove / keep with its access, the disk plan (files that change group, ACLs, a snapshot first), the apps restarted and the downtime, warnings, and the plan_hash folder_apply needs.",
			ClassRead, "POST /api/folders/{id}/assign/preview", "", func(ctx context.Context, _ directory.Actor, in assignArgs) (any, error) {
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				if in.Uses == nil {
					return nil, badArg("uses is required (the full desired set; [] removes every use)")
				}
				p, err := s.Hub.PreviewAssign(ctx, in.ID, hub.AssignRequest{Uses: in.Uses})
				return p, apiErr(err)
			}),
		perCallCtx(admin("folder_apply", "Apply a shared folder assignment previewed with folder_preview (the same uses and its plan_hash; a change since is refused). Runs in the background: answers {op_id, op, instance, folder, poll}; see folder_op. An assignment that gives an app the folder, adds write access or changes permissions on disk needs your confirmation in the browser.",
			ClassWrite, "POST /api/folders/{id}/assign/apply", "folder.assign", func(_ context.Context, a directory.Actor, in assignApplyArgs) (any, error) {
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				if in.Uses == nil {
					return nil, badArg("uses is required (the full desired set; [] removes every use)")
				}
				if in.PlanHash == "" {
					return nil, badArg("plan_hash is required: folder_preview answers it")
				}
				// StartAssign recomputes the plan under the folder's and
				// the instances' locks: another hash is 409.
				op, err := s.startAssign(in.ID, hub.AssignRequest{Uses: in.Uses}, in.PlanHash, a)
				if err != nil {
					return nil, apiErr(err)
				}
				return opAcceptedBody(op), nil
			}), s.assignClass, idOf, s.assignConsequences),
		admin("folder_undo_preview", "What undoing a shared folder's last permissions fix would do (nothing changes): the snapshot it restores, the entries put back and those changed since, the uses that lose access, and the plan_hash folder_undo_apply needs.",
			ClassRead, "POST /api/folders/{id}/undo/preview", "", func(ctx context.Context, _ directory.Actor, in folderIDArgs) (any, error) {
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				p, err := s.Hub.PreviewUndo(ctx, in.ID)
				return p, apiErr(err)
			}),
		{Name: "folder_undo_apply", Description: "Undo a shared folder's last permissions fix, previewed with folder_undo_preview (its plan_hash): the permissions snapshot is restored on disk. An undo can't be undone. Runs in the background: answers {op_id, op, instance, folder, poll}.",
			Class: ClassDestructive, Scope: ScopeAdmin, Twin: "POST /api/folders/{id}/undo/apply", Audit: "folder.apply", In: planHashArgs{},
			Typed: idOf, Consequences: s.undoConsequences,
			Run: func(ctx context.Context, c *directory.Caller, args json.RawMessage) (any, error) {
				in, _ := decode[planHashArgs](args)
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				if in.PlanHash == "" {
					return nil, badArg("plan_hash is required: folder_undo_preview answers it")
				}
				op, err := s.startUndo(in.ID, in.PlanHash, toolActor(ctx, c))
				if err != nil {
					return nil, apiErr(err)
				}
				return opAcceptedBody(op), nil
			}},
		admin("folder_recheck_preview", "Re-check a shared folder's identity (after a reboot on btrfs or LVM): the stored and the current device, inode and mount root, whether it is a different directory now, and the plan_hash folder_recheck_apply needs. Nothing changes.",
			ClassRead, "POST /api/folders/{id}/recheck/preview", "", func(ctx context.Context, _ directory.Actor, in folderIDArgs) (any, error) {
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				c, err := s.Hub.PreviewRecheck(ctx, in.ID)
				return c, apiErr(err)
			}),
		perCall(admin("folder_recheck_apply", "Store the identity folder_recheck_preview showed (its plan_hash). Accepting a different directory (confirm_different_directory) needs your confirmation in the browser: someone may have swapped the folder.",
			ClassWrite, "POST /api/folders/{id}/recheck/apply", "folder.update", func(ctx context.Context, a directory.Actor, in recheckApplyArgs) (any, error) {
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				v, err := s.applyRecheck(ctx, in.ID, in.PlanHash, in.ConfirmDifferent, a)
				if err != nil {
					return nil, apiErr(err)
				}
				return map[string]any{"folder": v}, nil
			}), recheckClass, idOf, recheckConsequences),
		admin("folder_op", "A shared folder's last operation record (an assignment, an undo: running, then ok / error with its result and warnings).",
			ClassRead, "GET /api/folders/{id}/op", "", func(_ context.Context, _ directory.Actor, in folderIDArgs) (any, error) {
				if err := folderIDOK(in.ID); err != nil {
					return nil, err
				}
				return s.opRecordOf("_folder."+in.ID, "shared folder "+in.ID)
			}),
	} {
		s.registerTool(t)
	}
}

// fixClass (G45): doctor_apply_fix is W only when the fix the Hub
// re-derives for these arguments (FixTouchesData, ApplyFix's rules) is
// config-only and its plan has the call's plan_hash; anything else —
// touches data, unknown finding, no fix, a failing preview, another hash,
// undecodable arguments — is D.
func (s *Server) fixClass(ctx context.Context, args json.RawMessage) ToolClass {
	in, err := decode[applyFixArgs](args)
	if err != nil || fpOK(in.FP) != nil {
		return ClassDestructive
	}
	rep, err := s.doctorReport(ctx)
	if err != nil {
		return ClassDestructive
	}
	touches, err := s.Hub.FixNeedsConfirmation(ctx, rep, in.FP, in.params(), in.PlanHash)
	if err != nil || touches {
		return ClassDestructive
	}
	return ClassWrite
}

func (s *Server) fixConsequences(ctx context.Context, args json.RawMessage) []string {
	in, _ := decode[applyFixArgs](args)
	rep, err := s.doctorReport(ctx)
	var p *hub.FixPlan
	if err == nil {
		p, err = s.Hub.PreviewFixIn(ctx, rep, in.FP, in.params())
	}
	if err != nil {
		return []string{"Applies the doctor's fix for finding " + in.FP + " (its preview fails now: " + q(clipMessage(err.Error(), 300)) + ")."}
	}
	lines := []string{"Applies the doctor's fix " + p.Kind + " for finding " + in.FP + ":"}
	if p.TouchesData {
		lines[0] = "Applies the doctor's fix " + p.Kind + " for finding " + in.FP + ", which changes data on disk or revokes access:"
	}
	return append(lines, append(p.Lines, p.Warnings...)...)
}

// assignClass: folder_apply is W only for the plan the call's plan_hash
// names (recomputed now: another hash, or a preview that fails, is D)
// when that plan doesn't widen access (AssignPlan.WidensAccess: only
// removals, nothing on disk). StartAssign runs only a plan with that
// hash.
func (s *Server) assignClass(ctx context.Context, args json.RawMessage) ToolClass {
	in, err := decode[assignApplyArgs](args)
	if err != nil || folderIDOK(in.ID) != nil || in.Uses == nil || in.PlanHash == "" {
		return ClassDestructive
	}
	p, err := s.Hub.PreviewAssign(ctx, in.ID, hub.AssignRequest{Uses: in.Uses})
	if err != nil || p.Hash != in.PlanHash || p.WidensAccess() {
		return ClassDestructive
	}
	return ClassWrite
}

func (s *Server) assignConsequences(ctx context.Context, args json.RawMessage) []string {
	in, _ := decode[assignApplyArgs](args)
	p, err := s.Hub.PreviewAssign(ctx, in.ID, hub.AssignRequest{Uses: in.Uses})
	if err != nil {
		return []string{"Applies an assignment of shared folder " + in.ID + " (its preview fails now: " + q(clipMessage(err.Error(), 300)) + ")."}
	}
	return append(append([]string{"Applies this assignment of shared folder " + in.ID + ":"}, p.Lines...), p.Warnings...)
}

func (s *Server) undoConsequences(ctx context.Context, args json.RawMessage) []string {
	in, _ := decode[planHashArgs](args)
	p, err := s.Hub.PreviewUndo(ctx, in.ID)
	if err != nil {
		return []string{"Undoes shared folder " + in.ID + "'s last permissions fix (its preview fails now: " + q(clipMessage(err.Error(), 300)) + ")."}
	}
	return append(append([]string{"Undoes shared folder " + in.ID + "'s last permissions fix (it can't be undone itself):"}, p.Lines...), p.Warnings...)
}

// recheckClass: D when the call accepts a different directory (or its
// arguments don't decode).
func recheckClass(args json.RawMessage) ToolClass {
	in, err := decode[recheckApplyArgs](args)
	if err != nil || in.ConfirmDifferent {
		return ClassDestructive
	}
	return ClassWrite
}

func recheckConsequences(args json.RawMessage) []string {
	return []string{"Accepts a different directory as shared folder " + idOf(args) + ": the apps that use it get that directory at their next start, and Undo last fix is no longer offered. If you didn't move the folder, someone may have swapped it."}
}

// doctorReport is the doctor's report, run once per tool call (the
// call's memo: class and consequences share it); without a memo, a run
// of its own. Runs that must judge the current state — ApplyFix,
// MuteFinding — run the doctor again inside the Hub.
func (s *Server) doctorReport(ctx context.Context) (*doctor.Report, error) {
	m := memoOf(ctx)
	if m == nil {
		return s.Hub.Doctor(ctx)
	}
	m.docOnce.Do(func() { m.doc, m.docErr = s.Hub.Doctor(ctx) })
	return m.doc, m.docErr
}

// findingIn is fp's finding in r (nil when it isn't there).
func findingIn(r *doctor.Report, fp string) *doctor.Finding {
	if r == nil {
		return nil
	}
	for i := range r.Findings {
		if r.Findings[i].FP == fp {
			return &r.Findings[i]
		}
	}
	return nil
}

// muteClassOf (fix round 1 ruling): muting is D for a finding whose
// current severity is problem, for ai_credentials_revoking (an owed
// revocation), and for a finding that can't be located (fail closed);
// otherwise W.
func muteClassOf(r *doctor.Report, fp string) ToolClass {
	f := findingIn(r, fp)
	if f == nil || f.Severity == doctor.Problem || f.Kind == doctor.KindAICredentialsRevoking {
		return ClassDestructive
	}
	return ClassWrite
}

func (s *Server) muteClass(ctx context.Context, args json.RawMessage) ToolClass {
	in, err := decode[muteArgs](args)
	if err != nil || fpOK(in.FP) != nil {
		return ClassDestructive
	}
	rep, err := s.doctorReport(ctx)
	if err != nil {
		return ClassDestructive
	}
	return muteClassOf(rep, in.FP)
}

func (s *Server) muteConsequences(ctx context.Context, args json.RawMessage) []string {
	in, _ := decode[muteArgs](args)
	rep, _ := s.doctorReport(ctx)
	f := findingIn(rep, in.FP)
	if f == nil {
		return []string{"Mutes finding " + in.FP + " (it isn't in the doctor's report now: the mute is refused unless it is)."}
	}
	return []string{
		"Mutes the doctor's " + string(f.Severity) + " " + f.Kind + ": " + q(f.Title) + ".",
		"It leaves the counts and stays hidden until what it judged changes. Reason: " + q(clipMessage(in.Reason, 200)) + ".",
	}
}
