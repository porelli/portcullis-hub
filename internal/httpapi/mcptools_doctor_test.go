package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 20: the Portcullis MCP's doctor and shared-folder tools
// (contract §14.8, §15.10, G15, G45).

// withFolderSetup adds the shared-folder fixture of newFolderEnv to o:
// the photos app enabled, using shared folder media (/srv/media, gid
// 60001) through its undeclared option extra, and a pinned fixer image.
func withFolderSetup(o mcpEnvOpts) mcpEnvOpts {
	extra := map[string][2]string{"photos": {folderAppManifest, folderAppCompose}}
	for k, v := range o.extra {
		extra[k] = v
	}
	o.extra = extra
	cfg, seed := o.cfg, o.seed
	o.cfg = func(c *hub.Config) {
		c.FixerImage = testFixerImage
		if cfg != nil {
			cfg(c)
		}
	}
	o.seed = func(st *state.AppState) {
		st.Enabled = append(st.Enabled, "photos")
		st.Folders = map[string]state.Folder{"media": {Name: "Family media", Path: "/srv/media", GID: 60001,
			CreatedAt: time.Now().UTC(), Dev: mediaDev, Ino: mediaIno, MountRoot: "/srv/media"}}
		st.FolderGIDs = []int{60001}
		if st.Settings == nil {
			st.Settings = map[string]state.InstanceSettings{}
		}
		st.Settings["photos"] = state.InstanceSettings{Values: map[string]any{"extra": "folder:media"}}
		if seed != nil {
			seed(st)
		}
	}
	return o
}

// scriptFolderDisk makes the fixer answer for /srv/media (scriptDisk).
func scriptFolderDisk(t *testing.T, e *toolEnv) {
	t.Helper()
	if e.s.Hub.Template("photos") == nil {
		t.Fatal("photos template not loaded (see the log)")
	}
	scriptDisk(e.eng.fakeEngine, mediaIno, "/srv/media")
}

func newFolderToolEnv(t *testing.T) *toolEnv {
	t.Helper()
	e := newToolEnvWith(t, withFolderSetup(mcpEnvOpts{}))
	scriptFolderDisk(t, e)
	return e
}

// photosSMB is lan_only_exposed's fingerprint of photos' PHOTOS_SMB.
var photosSMB = doctor.Fingerprint(doctor.KindLANOnlyExposed, "photos", "PHOTOS_SMB", "tcp")

// findingOfKind is the current report's finding of kind (fatal if none).
func findingOfKind(t *testing.T, h *hub.Hub, kind string) doctor.Finding {
	t.Helper()
	r, err := h.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.Kind == kind {
			return f
		}
	}
	t.Fatalf("no %s finding in %+v", kind, r.Findings)
	return doctor.Finding{}
}

// rawTool calls an admin tool as root without approving anything.
func (e *toolEnv) rawTool(t *testing.T, name string, args any) (string, bool) {
	t.Helper()
	return resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", name, args, nil))
}

// approve approves the confirmation txt asks for (its typed check) and
// returns its id.
func (e *toolEnv) approve(t *testing.T, txt string) string {
	t.Helper()
	m := confirmTextRe.FindStringSubmatch(txt)
	if m == nil {
		t.Fatalf("no confirmation in %q", txt)
	}
	v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, m[1], "root")
	if err != nil {
		t.Fatal(err)
	}
	e.decide(t, m[1], v.Typed, true)
	return v.ID
}

// planHashOf is the plan_hash of a preview tool's answer.
func planHashOf(t *testing.T, txt string, isErr bool) string {
	t.Helper()
	var p struct {
		PlanHash string `json:"plan_hash"`
	}
	if isErr || json.Unmarshal([]byte(txt), &p) != nil || len(p.PlanHash) != 64 {
		t.Fatalf("preview = %s (isError %v)", txt, isErr)
	}
	return p.PlanHash
}

// lastAuditOf is the newest entry of action.
func lastAuditOf(t *testing.T, e *toolEnv, action string) directory.AuditEntry {
	t.Helper()
	all := readAudit(t, e.audit)
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Action == action {
			return all[i]
		}
	}
	t.Fatalf("no %s audit entry", action)
	return directory.AuditEntry{}
}

// TestDoctorToolsMirror: doctor_apply_fix on a data-touching plan asks for
// a confirmation first (nothing runs); approved, it runs and is audited
// doctor.fix via ai, the client and the confirmation. A config-only plan
// runs at once, audited doctor.fix via ai and the client.
func TestDoctorToolsMirror(t *testing.T) {
	e := newFolderToolEnv(t)
	// The disk check finds the folder drifted (the scripted scan).
	txt, isErr, conf := e.tool(t, "doctor_scan", map[string]any{})
	if isErr || conf != "" || !strings.Contains(txt, `"poll":"/api/doctor/op"`) {
		t.Fatalf("doctor_scan = %s %v %q", txt, isErr, conf)
	}
	waitIdle(t, e.s.Hub, "_doctor")
	if a := lastAuditOf(t, e, "doctor.scan"); a.Via != "ai" || a.Client != mcpClient || a.Result != "ok" {
		t.Errorf("doctor.scan audit = %+v", a)
	}

	// Data: reapply_folder (folder_owner).
	owner := findingOfKind(t, e.s.Hub, doctor.KindFolderOwner)
	txt, isErr = e.rawTool(t, "doctor_preview_fix", map[string]any{"fp": owner.FP})
	if !strings.Contains(txt, `"touches_data":true`) {
		t.Fatalf("preview = %s", txt)
	}
	hash := planHashOf(t, txt, isErr)
	args := map[string]any{"fp": owner.FP, "plan_hash": hash}
	txt, isErr = e.rawTool(t, "doctor_apply_fix", args)
	if !isErr || !strings.HasPrefix(txt, textConfirmPrefix) {
		t.Fatalf("data fix without confirmation = %s %v", txt, isErr)
	}
	if r := e.s.Hub.LastOp("_folder.media"); r != nil {
		t.Errorf("the fix ran before the confirmation: %+v", r)
	}
	conf = e.approve(t, txt)
	txt, isErr = e.rawTool(t, "doctor_apply_fix", args)
	if isErr || !strings.Contains(txt, `"poll":"/api/folders/media/op"`) {
		t.Fatalf("confirmed data fix = %s %v %q", txt, isErr, conf)
	}
	waitIdle(t, e.s.Hub, "_folder.media")
	a := lastAuditOf(t, e, "doctor.fix")
	if a.Via != "ai" || a.Client != mcpClient || a.Target != owner.FP || !strings.Contains(a.Detail, "fix=reapply_folder") ||
		!strings.HasSuffix(a.Detail, "confirmation "+conf) {
		t.Errorf("doctor.fix audit = %+v", a)
	}

	// Config only: rebind_port, at once.
	fix := map[string]any{"fp": photosSMB, "address": "192.168.1.10"}
	txt, isErr = e.rawTool(t, "doctor_preview_fix", fix)
	if !strings.Contains(txt, `"touches_data":false`) {
		t.Fatalf("rebind preview = %s", txt)
	}
	fix["plan_hash"] = planHashOf(t, txt, isErr)
	txt, isErr, conf = e.tool(t, "doctor_apply_fix", fix)
	if isErr || conf != "" || !strings.Contains(txt, `"poll":"/api/instances/photos/op"`) {
		t.Fatalf("config-only fix = %s %v confirmation %q", txt, isErr, conf)
	}
	waitIdle(t, e.s.Hub, "photos")
	a = lastAuditOf(t, e, "doctor.fix")
	if a.Via != "ai" || a.Client != mcpClient || a.Target != photosSMB || !strings.Contains(a.Detail, "fix=rebind_port") || strings.Contains(a.Detail, "confirmation") {
		t.Errorf("rebind doctor.fix audit = %+v", a)
	}
}

// TestDoctorToolClassPerCall: the per-call classes fail closed.
func TestDoctorToolClassPerCall(t *testing.T) {
	e := newFolderToolEnv(t)
	ctx := context.Background()
	raw := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	prev := func(tool string, args map[string]any) string {
		txt, isErr := e.rawTool(t, tool, args)
		return planHashOf(t, txt, isErr)
	}
	rebind := prev("doctor_preview_fix", map[string]any{"fp": photosSMB, "address": "192.168.1.10"})
	removeAll := prev("folder_preview", map[string]any{"id": "media", "uses": []any{}})
	addLibrary := prev("folder_preview", map[string]any{"id": "media", "uses": []any{map[string]any{"instance": "photos", "key": "extra"}, map[string]any{"instance": "photos", "key": "library"}}})
	for _, c := range []struct {
		name string
		got  ToolClass
		want ToolClass
	}{
		{"rebind, its hash", s(e).fixClass(ctx, raw(map[string]any{"fp": photosSMB, "address": "192.168.1.10", "plan_hash": rebind})), ClassWrite},
		{"rebind, another address", s(e).fixClass(ctx, raw(map[string]any{"fp": photosSMB, "address": "192.168.1.11", "plan_hash": rebind})), ClassDestructive},
		{"rebind, no hash", s(e).fixClass(ctx, raw(map[string]any{"fp": photosSMB, "address": "192.168.1.10", "plan_hash": ""})), ClassDestructive},
		{"rebind, a bad address", s(e).fixClass(ctx, raw(map[string]any{"fp": photosSMB, "address": "8.8.8.8", "plan_hash": rebind})), ClassDestructive},
		{"unknown finding", s(e).fixClass(ctx, raw(map[string]any{"fp": "0123456789abcdef", "plan_hash": rebind})), ClassDestructive},
		{"bad fp", s(e).fixClass(ctx, raw(map[string]any{"fp": "x", "plan_hash": rebind})), ClassDestructive},
		{"fix arguments undecodable", s(e).fixClass(ctx, json.RawMessage(`[]`)), ClassDestructive},
		{"remove every use, its hash", s(e).assignClass(ctx, raw(map[string]any{"id": "media", "uses": []any{}, "plan_hash": removeAll})), ClassWrite},
		{"remove every use, a stale hash", s(e).assignClass(ctx, raw(map[string]any{"id": "media", "uses": []any{}, "plan_hash": addLibrary})), ClassDestructive},
		{"add a use", s(e).assignClass(ctx, raw(map[string]any{"id": "media", "uses": []any{map[string]any{"instance": "photos", "key": "extra"}, map[string]any{"instance": "photos", "key": "library"}}, "plan_hash": addLibrary})), ClassDestructive},
		{"unknown folder", s(e).assignClass(ctx, raw(map[string]any{"id": "nope", "uses": []any{}, "plan_hash": removeAll})), ClassDestructive},
		{"assign undecodable", s(e).assignClass(ctx, json.RawMessage(`{"id":3}`)), ClassDestructive},
		{"recheck", recheckClass(raw(map[string]any{"id": "media", "plan_hash": "x"})), ClassWrite},
		{"recheck, another directory", recheckClass(raw(map[string]any{"id": "media", "plan_hash": "x", "confirm_different_directory": true})), ClassDestructive},
		{"recheck undecodable", recheckClass(json.RawMessage(`[]`)), ClassDestructive},
	} {
		if c.got != c.want {
			t.Errorf("%s: class %s, want %s", c.name, c.got, c.want)
		}
	}
	// The data fix (reapply_folder) is D without any preview hash too.
	e.tool(t, "doctor_scan", map[string]any{})
	waitIdle(t, e.s.Hub, "_doctor")
	owner := findingOfKind(t, e.s.Hub, doctor.KindFolderOwner)
	if got := s(e).fixClass(ctx, raw(map[string]any{"fp": owner.FP, "plan_hash": ""})); got != ClassDestructive {
		t.Errorf("reapply_folder: class %s, want D", got)
	}
}

func s(e *toolEnv) *Server { return e.s }

// TestFolderApplyNeedsPlanHash: folder_apply requires the preview's
// plan_hash; a removal-only plan runs at once (audited via ai), an adding
// one asks for a confirmation first; the Hub refuses a widening apply
// from the AI without one, and a stale hash is 409 after the
// confirmation.
func TestFolderApplyNeedsPlanHash(t *testing.T) {
	e := newFolderToolEnv(t)
	adds := []any{map[string]any{"instance": "photos", "key": "extra"}, map[string]any{"instance": "photos", "key": "library"}}
	if txt, isErr := e.rawTool(t, "folder_apply", map[string]any{"id": "media", "uses": adds}); !isErr || !strings.Contains(txt, "invalid arguments") {
		t.Errorf("no plan_hash = %s %v", txt, isErr)
	}
	txt, isErr := e.rawTool(t, "folder_preview", map[string]any{"id": "media", "uses": adds})
	hash := planHashOf(t, txt, isErr)
	// The Hub itself refuses the AI without a confirmation.
	ai := directory.Actor{User: "root", Via: directory.ViaAI, Client: mcpClient}
	if _, err := e.s.Hub.StartAssign("media", hub.AssignRequest{Uses: []hub.FolderUse{{Instance: "photos", Key: "extra"}, {Instance: "photos", Key: "library"}}}, hash, ai); err == nil ||
		!strings.Contains(err.Error(), "confirmation") {
		t.Errorf("Hub StartAssign from the AI without a confirmation = %v", err)
	}
	pending, isErr := e.rawTool(t, "folder_apply", map[string]any{"id": "media", "uses": adds, "plan_hash": hash})
	if !isErr || !strings.HasPrefix(pending, textConfirmPrefix) {
		t.Fatalf("adding apply = %s %v, want a confirmation", pending, isErr)
	}
	stale := map[string]any{"id": "media", "uses": adds, "plan_hash": strings.Repeat("0", 64)}
	if txt, isErr, conf := e.tool(t, "folder_apply", stale); !isErr || conf == "" || !strings.HasPrefix(txt, "409: ") || !strings.Contains(txt, "the setup changed since the preview") {
		t.Errorf("stale hash = %s %v %q", txt, isErr, conf)
	}
	conf := e.approve(t, pending)
	txt, isErr = e.rawTool(t, "folder_apply", map[string]any{"id": "media", "uses": adds, "plan_hash": hash})
	if isErr || !strings.Contains(txt, `"folder":"media"`) {
		t.Fatalf("confirmed apply = %s %v %q", txt, isErr, conf)
	}
	waitIdle(t, e.s.Hub, "_folder.media")
	// Accepted (the fake fixer's snapshot has no plan, so the operation
	// itself fails after it started: never a refusal).
	if a := lastAuditOf(t, e, "folder.assign"); a.Via != "ai" || !strings.HasSuffix(a.Detail, "confirmation "+conf) || a.Result == "refused" {
		t.Errorf("folder.assign audit = %+v", a)
	}
	// Removing every use: W, at once.
	txt, isErr = e.rawTool(t, "folder_preview", map[string]any{"id": "media", "uses": []any{}})
	hash = planHashOf(t, txt, isErr)
	txt, isErr, conf2 := e.tool(t, "folder_apply", map[string]any{"id": "media", "uses": []any{}, "plan_hash": hash})
	conf = conf2
	if isErr || conf != "" {
		t.Fatalf("removal = %s %v %q", txt, isErr, conf)
	}
	waitIdle(t, e.s.Hub, "_folder.media")
	if a := lastAuditOf(t, e, "folder.assign"); a.Via != "ai" || a.Client != mcpClient || strings.Contains(a.Detail, "confirmation") || a.Result != "ok" {
		t.Errorf("removal audit = %+v", a)
	}
	if fs := e.s.Hub.Folders(); len(fs) != 1 || len(fs[0].Uses) != 0 {
		t.Errorf("folders after the removal = %+v", fs)
	}
}

// TestDoctorMuteTool: doctor_mute takes the finding's token as
// finding_token (a changed one is refused), doctor_unmute lifts it; both
// audited via ai.
func TestDoctorMuteTool(t *testing.T) {
	e := newFolderToolEnv(t)
	f := findingOfKind(t, e.s.Hub, doctor.KindLANOnlyExposed)
	if txt, isErr, _ := e.tool(t, "doctor_mute", map[string]any{"fp": f.FP, "reason": "behind the router", "finding_token": "nope"}); !isErr || !strings.HasPrefix(txt, "409: ") {
		t.Errorf("wrong token = %s %v", txt, isErr)
	}
	if txt, isErr, _ := e.tool(t, "doctor_mute", map[string]any{"fp": f.FP, "reason": "behind the router", "finding_token": f.Token}); isErr {
		t.Fatalf("mute = %s", txt)
	}
	if a := lastAuditOf(t, e, "doctor.mute"); a.Via != "ai" || a.Client != mcpClient || a.Target != f.FP || a.Result != "ok" {
		t.Errorf("doctor.mute audit = %+v", a)
	}
	if got := findingOfKind(t, e.s.Hub, doctor.KindLANOnlyExposed); got.Muted == nil {
		t.Errorf("not muted: %+v", got)
	}
	if txt, isErr, _ := e.tool(t, "doctor_unmute", map[string]any{"fp": f.FP}); isErr {
		t.Fatalf("unmute = %s", txt)
	}
	if txt, isErr, _ := e.tool(t, "doctor_unmute", map[string]any{"fp": f.FP}); !isErr || !strings.HasPrefix(txt, "404: ") {
		t.Errorf("unmute twice = %s %v", txt, isErr)
	}
	if txt, isErr, _ := e.tool(t, "doctor_unmute", map[string]any{"fp": "zz"}); !isErr || !strings.HasPrefix(txt, "404: ") {
		t.Errorf("bad fp = %s %v", txt, isErr)
	}
}

// TestCheckFolderPathTool (fix round 1): check_folder_path never creates
// anything, and it makes the route's Hub call.
func TestCheckFolderPathTool(t *testing.T) {
	e := newFolderToolEnv(t)
	t.Run("no create argument", func(t *testing.T) {
		if txt, isErr := e.rawTool(t, "check_folder_path", map[string]any{"path": "/srv/docs", "create": true}); !isErr || !strings.HasPrefix(txt, textSecretArgs) {
			t.Errorf("check_folder_path with create = %s %v, want the undeclared-argument refusal", txt, isErr)
		}
	})
	t.Run("never creates", func(t *testing.T) {
		rec := &callRec{}
		e.s.callHook = rec.hook
		defer func() { e.s.callHook = nil }()
		if txt, isErr := e.rawTool(t, "check_folder_path", map[string]any{"path": "/srv/media"}); isErr || !strings.Contains(txt, `"exists":true`) {
			t.Errorf("check = %s %v", txt, isErr)
		}
		if got := rec.take(); len(got) != 1 || got[0] != `CheckFolderPath ["/srv/media",false]` {
			t.Errorf("Hub calls = %q", got)
		}
	})
}

// TestDoctorMuteClass (fix round 1 ruling): doctor_mute is D for a
// Problem, for ai_credentials_revoking and for a finding the report
// doesn't have (or arguments that don't decode); W otherwise. One doctor
// run serves the call's class and consequences.
func TestDoctorMuteClass(t *testing.T) {
	e := newToolEnvWith(t, withFolderSetup(mcpEnvOpts{seed: func(st *state.AppState) {
		st.FolderChanged = map[string][]state.FolderChange{"photos": {{Instance: "photos", Key: "extra", Folder: "media", At: time.Now().UTC(),
			Detail: "another directory"}}}
	}}))
	scriptFolderDisk(t, e)
	ctx := context.Background()
	raw := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	warn := findingOfKind(t, e.s.Hub, doctor.KindLANOnlyExposed)
	prob := findingOfKind(t, e.s.Hub, doctor.KindFolderChanged)
	if warn.Severity != doctor.Warning || prob.Severity != doctor.Problem {
		t.Fatalf("fixture severities %s / %s", warn.Severity, prob.Severity)
	}
	mute := func(fp string) json.RawMessage {
		return raw(map[string]any{"fp": fp, "reason": "r", "finding_token": "t"})
	}
	revoking := &doctor.Report{Findings: []doctor.Finding{{FP: "aaaaaaaaaaaaaaaa", Kind: doctor.KindAICredentialsRevoking, Severity: doctor.Warning},
		{FP: "bbbbbbbbbbbbbbbb", Kind: doctor.KindAICompanionImageOld, Severity: doctor.Warning}}}
	for _, c := range []struct {
		name      string
		got, want ToolClass
	}{
		{"a warning", s(e).muteClass(ctx, mute(warn.FP)), ClassWrite},
		{"a problem", s(e).muteClass(ctx, mute(prob.FP)), ClassDestructive},
		{"unknown finding", s(e).muteClass(ctx, mute("0123456789abcdef")), ClassDestructive},
		{"bad fp", s(e).muteClass(ctx, mute("nope")), ClassDestructive},
		{"undecodable", s(e).muteClass(ctx, json.RawMessage(`[]`)), ClassDestructive},
		{"ai_credentials_revoking (a warning)", muteClassOf(revoking, "aaaaaaaaaaaaaaaa"), ClassDestructive},
		{"another AI warning", muteClassOf(revoking, "bbbbbbbbbbbbbbbb"), ClassWrite},
		{"no report", muteClassOf(nil, "aaaaaaaaaaaaaaaa"), ClassDestructive},
	} {
		if c.got != c.want {
			t.Errorf("%s: class %s, want %s", c.name, c.got, c.want)
		}
	}
	// Through the tool: a Problem asks for a confirmation whose page names
	// it; the warning mutes at once.
	txt, isErr := e.rawTool(t, "doctor_mute", map[string]any{"fp": prob.FP, "reason": "known", "finding_token": prob.Token})
	if !isErr || !strings.HasPrefix(txt, textConfirmPrefix) {
		t.Fatalf("muting a problem = %s %v", txt, isErr)
	}
	m := confirmTextRe.FindStringSubmatch(txt)
	v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, m[1], "root")
	if err != nil || !strings.Contains(strings.Join(v.Consequences, " "), "problem folder_changed") {
		t.Errorf("confirmation page = %+v %v", v, err)
	}
	if txt, isErr, conf := e.tool(t, "doctor_mute", map[string]any{"fp": warn.FP, "reason": "known", "finding_token": warn.Token}); isErr || conf != "" {
		t.Errorf("muting a warning = %s %v %q", txt, isErr, conf)
	}
	// One doctor run per call: class and consequences share the memo.
	mc := withCallMemo(ctx, &directory.Caller{User: "root"})
	r1, _ := s(e).doctorReport(mc)
	r2, _ := s(e).doctorReport(mc)
	if r1 == nil || r1 != r2 {
		t.Error("doctorReport ran twice within one call")
	}
}
