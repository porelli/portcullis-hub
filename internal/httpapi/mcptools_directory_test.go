package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/hub"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/lldap"
)

// Plan 4 Task 18: the Portcullis MCP's users and groups tools, twins of
// /api/directory/* (contract §9, §15.10; G15, G37, G39).

// inviteMarker is the token of every invite link markerInviter hands out:
// no tool result may hold it, nor the global redactor's placeholder (the
// tools drop the link themselves, G39).
const inviteMarker = "INVITEMARKER-0123456789abcdef"

// markerInviter is core's invite API with marker links.
type markerInviter struct {
	mu    sync.Mutex
	users []string
}

func (m *markerInviter) Available() error { return nil }

func (m *markerInviter) Create(_ context.Context, username string) (*invite.Invite, error) {
	m.mu.Lock()
	m.users = append(m.users, username)
	m.mu.Unlock()
	return &invite.Invite{URL: "https://enroll.example.org/invite/" + inviteMarker + "-" + username, ExpiresAt: time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)}, nil
}

// noInviteLink fails when txt holds an invite link, the marker, the
// redactor's placeholder, or a url / link key (G39).
func noInviteLink(t *testing.T, tool, txt string) {
	t.Helper()
	for _, bad := range []string{inviteMarker, "/invite/", "[invite link hidden]", `"url"`, `"link"`, `"token"`, `"password"`} {
		if strings.Contains(txt, bad) {
			t.Errorf("%s: the result holds %q: %s", tool, bad, txt)
		}
	}
}

// directoryToolEnv is a tool env whose directory hands out marker invites.
func directoryToolEnv(t *testing.T) (*toolEnv, *markerInviter) {
	t.Helper()
	e := newToolEnv(t, nil, nil)
	inv := &markerInviter{}
	e.s.Directory.Invites = inv
	return e, inv
}

// TestDirectoryToolsGuardrails (§9.5, ruling 1): delete_person on the
// bootstrap admin and on the Hub's service account is refused exactly as
// the HTTP twin refuses it (checkTarget, 409, the same message), after the
// confirmation, and audited refused via ai with the client and the
// confirmation; nothing changes in LLDAP.
func TestDirectoryToolsGuardrails(t *testing.T) {
	e, _ := directoryToolEnv(t)
	e.ll.AddUser("admin", "admin@example.org", "Admin", "", "lldap_admin")
	for _, target := range []string{directory.CoreAdmin, "portcullis-hub"} {
		code, body := e.do(t, "root", "DELETE", "/api/directory/users/"+target, `{"confirm":"`+target+`"}`)
		if code != 409 {
			t.Fatalf("http delete %s = %d %s", target, code, body)
		}
		n := len(readAudit(t, e.audit))
		txt, isErr, conf := e.tool(t, "delete_person", map[string]any{"username": target})
		if !isErr || conf == "" || txt != "409: "+strings.TrimSpace(body) {
			t.Errorf("tool delete %s = %q %v (confirmation %q), http %q", target, txt, isErr, conf, body)
		}
		var got []directory.AuditEntry
		for _, a := range readAudit(t, e.audit)[n:] {
			if a.Action == "user.delete" {
				got = append(got, a)
			}
		}
		if len(got) != 1 || got[0].Result != "refused" || got[0].Via != "ai" || got[0].Client != mcpClient || got[0].Target != target ||
			!strings.HasSuffix(got[0].Detail, "confirmation "+conf) {
			t.Errorf("tool delete %s audit = %+v", target, got)
		}
		if !e.ll.HasUser(target) {
			t.Errorf("%s was deleted", target)
		}
	}
	// The other user-targeting tools refuse both accounts too.
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"update_person", map[string]any{"username": "admin", "display_name": "X"}},
		{"set_details", map[string]any{"username": "portcullis-hub", "attrs": map[string]any{}}},
		{"require_passkey", map[string]any{"username": "admin"}},
		{"remove_passkeys", map[string]any{"username": "portcullis-hub"}},
		{"send_invite", map[string]any{"username": "admin"}},
		{"clear_actions", map[string]any{"username": "portcullis-hub"}},
		{"add_member", map[string]any{"group": "helpers", "username": "admin"}},
	} {
		txt, isErr, _ := e.tool(t, c.tool, c.args)
		if !isErr || !strings.HasPrefix(txt, "409: ") {
			t.Errorf("%s %v = %q %v, want the 409 refusal", c.tool, c.args, txt, isErr)
		}
	}
}

// TestCreatePersonNoInviteLink (G39, §15.10): create_person onboards by
// invite (core is asked) but the result holds no link, url, token or
// password — only that an invite was created and when it expires; into
// an administrator group it says "run ./portcullis invite <user> on the
// server" instead of the server-invite internals. send_invite, remove_passkeys
// with an invite and import_apply's create rows drop the link too.
func TestCreatePersonNoInviteLink(t *testing.T) {
	e, inv := directoryToolEnv(t)
	txt, isErr, conf := e.tool(t, "create_person", map[string]any{"username": "erin", "email": "erin@example.org", "display_name": "Erin"})
	if isErr || conf != "" {
		t.Fatalf("create_person = %q %v (confirmation %q: no groups, W)", txt, isErr, conf)
	}
	noInviteLink(t, "create_person", txt)
	var res map[string]any
	if err := json.Unmarshal([]byte(txt), &res); err != nil {
		t.Fatal(err)
	}
	invRes, _ := res["invite"].(map[string]any)
	if res["username"] != "erin" || invRes["created"] != true || invRes["expires_at"] == nil || !strings.Contains(invRes["note"].(string), "never shown to the AI") {
		t.Errorf("create_person result = %s", txt)
	}
	if len(inv.users) != 1 || inv.users[0] != "erin" || !e.ll.HasUser("erin") {
		t.Errorf("invites %v, erin created %v", inv.users, e.ll.HasUser("erin"))
	}
	// Into an administrator group: D, no invite, the fixed server text.
	txt, isErr, conf = e.tool(t, "create_person", map[string]any{"username": "olga", "email": "olga@example.org", "display_name": "Olga", "groups": []string{"lldap_admin"}})
	if isErr || conf == "" {
		t.Fatalf("create_person into lldap_admin = %q %v (confirmation %q)", txt, isErr, conf)
	}
	noInviteLink(t, "create_person (admin)", txt)
	if !strings.Contains(txt, `"server_invite":"run ./portcullis invite olga on the server"`) || strings.Contains(txt, `"./portcullis invite olga"`) {
		t.Errorf("admin create_person = %s", txt)
	}
	if len(inv.users) != 1 {
		t.Errorf("core was asked for an administrator's invite: %v", inv.users)
	}
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"send_invite", map[string]any{"username": "erin"}},
		{"remove_passkeys", map[string]any{"username": "erin", "invite": true}},
		{"import_apply", map[string]any{"rows": []any{map[string]any{"user": "gina", "create": true, "email": "gina@example.org", "display_name": "Gina"}}}},
		{"directory_overview", nil},
		{"get_person", map[string]any{"username": "olga"}},
	} {
		txt, isErr, _ := e.tool(t, c.tool, c.args)
		if isErr {
			t.Errorf("%s = %q", c.tool, txt)
		}
		noInviteLink(t, c.tool, txt)
	}
	if len(inv.users) != 4 {
		t.Errorf("invites = %v, want erin, erin, erin, gina", inv.users)
	}
	// The overview's server invites are the fixed text too.
	txt, _, _ = e.tool(t, "get_person", map[string]any{"username": "olga"})
	if !strings.Contains(txt, `"server_invite":"run ./portcullis invite olga on the server"`) {
		t.Errorf("get_person olga = %s", txt)
	}
	// No password argument exists: a call naming one is refused.
	txt, isErr = resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "create_person",
		map[string]any{"username": "hugo", "email": "hugo@example.org", "display_name": "Hugo", "password": "pw-0123456789"}, nil))
	if !isErr || !strings.HasPrefix(txt, textSecretArgs) || e.ll.HasUser("hugo") {
		t.Errorf("create_person with a password = %q %v", txt, isErr)
	}
}

// TestSetGroupRuleSameAsHTTP (ruling 1): set_group_rule and PUT
// /api/directory/groups/{group}/rule write the same group.rule audit
// entry, the tool's via ai with the client.
func TestSetGroupRuleSameAsHTTP(t *testing.T) {
	var entries [2]directory.AuditEntry
	for i := range 2 {
		e, _ := directoryToolEnv(t)
		mustDo(t, e.hub, "root", "POST", "/api/directory/fields", `{"name":"dept","label":"Dept","kind":"text"}`, 200)
		mustDo(t, e.hub, "root", "POST", "/api/directory/groups", `{"name":"eng"}`, 200)
		mustDo(t, e.hub, "root", "POST", "/api/directory/groups/eng/convert", `{"rule":"dept = \"Eng\"","preview":{"matching":[],"kept_as_exception":[],"joining":[],"expiry_dropped":[]}}`, 200)
		n := len(readAudit(t, e.audit))
		if i == 0 {
			mustDo(t, e.hub, "root", "PUT", "/api/directory/groups/eng/rule", `{"rule":"dept = \"Ops\""}`, 200)
		} else if txt, isErr, conf := e.tool(t, "set_group_rule", map[string]any{"group": "eng", "rule": `dept = "Ops"`}); isErr || conf != "" {
			t.Fatalf("set_group_rule = %q %v %q", txt, isErr, conf)
		}
		var got []directory.AuditEntry
		for _, a := range readAudit(t, e.audit)[n:] {
			if a.Action == "group.rule" {
				got = append(got, a)
			}
		}
		if len(got) != 1 {
			t.Fatalf("group.rule entries = %+v", got)
		}
		entries[i] = got[0]
	}
	h, tl := entries[0], entries[1]
	if h.Via != "" || h.Client != "" || tl.Via != "ai" || tl.Client != mcpClient {
		t.Errorf("attribution: http %+v, tool %+v", h, tl)
	}
	if auditKey(h) != auditKey(tl) || h.Actor != tl.Actor || tl.Detail != `rule=dept = "Ops"` {
		t.Errorf("audit differs: http %+v, tool %+v", h, tl)
	}
}

// TestOtherAdminNeedsTypedName (§9.5, ruling 4): remove_passkeys,
// require_passkey and delete_person on another administrator ask, on the
// confirmation page, for that person's name (and the passkey touch); the
// consequences say they are an administrator; approved, the reset runs
// with the name as the HTTP flow's confirm and is flagged in the audit.
func TestOtherAdminNeedsTypedName(t *testing.T) {
	e, _ := directoryToolEnv(t)
	e.ll.AddUser("ops", "ops@example.org", "Ops", "", "lldap_admin")
	pending := ""
	for _, tool := range []string{"remove_passkeys", "require_passkey", "delete_person"} {
		txt, isErr := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", tool, map[string]any{"username": "ops"}, nil))
		m := confirmTextRe.FindStringSubmatch(txt)
		if !isErr || m == nil {
			t.Fatalf("%s ops = %q", tool, txt)
		}
		v, err := e.s.Hub.ConfirmationPage(hub.ListenerHub, m[1], "root")
		if err != nil {
			t.Fatal(err)
		}
		if v.Typed != "ops" || !strings.Contains(strings.Join(v.Consequences, " "), "ops is an administrator") {
			t.Errorf("%s: typed %q, consequences %q", tool, v.Typed, v.Consequences)
		}
		if tool == "remove_passkeys" {
			pending = m[1]
		}
	}
	// Any other typed text is refused; the name approves.
	d := hub.Decision{Approve: true, Typed: "root", Proof: freshauth.Proof{Code: "good-code", CodeVerifier: strings.Repeat("v", 43), Nonce: "n0nce"}}
	if _, err := e.s.Hub.DecideConfirmation(context.Background(), hub.ListenerHub, pending, "root", d); err == nil {
		t.Errorf("approved with the acting admin's name")
	}
	e.decide(t, pending, "ops", true)
	txt, isErr := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "remove_passkeys", map[string]any{"username": "ops"}, nil))
	if isErr {
		t.Fatalf("remove_passkeys ops = %q %v", txt, isErr)
	}
	a := lastEntry(t, e, "user.remove_passkeys")
	if a.Result != "ok" || !strings.Contains(a.Detail, "target_is_lldap_admin=true") || a.Via != "ai" {
		t.Errorf("audit = %+v", a)
	}
}

// lastEntry is the newest audit entry of action.
func lastEntry(t *testing.T, e *toolEnv, action string) directory.AuditEntry {
	t.Helper()
	all := readAudit(t, e.audit)
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Action == action {
			return all[i]
		}
	}
	t.Fatalf("no %s entry", action)
	return directory.AuditEntry{}
}

// brokenLLDAP is the LLDAP side failing every read.
type brokenLLDAP struct{ directory.Directory }

func (brokenLLDAP) ListGroups(context.Context) ([]lldap.Group, error) {
	return nil, errors.New("lldap down")
}

// TestDirectoryToolClassPerCall (G37, ruling 2): the access-widening
// directory tools are D exactly when the directory's own definitions say
// the call widens access — into an administrator, permission or guarding
// group; create_person with groups; set_details / import_apply on a
// field a guarding group's rule uses; import_apply creating or removing
// people — and D when that can't be decided (unknown group, directory
// down). set_permission is D on every call.
func TestDirectoryToolClassPerCall(t *testing.T) {
	e, _ := directoryToolEnv(t)
	for _, g := range []string{"admin_secretapp", "hr_edit"} {
		e.ll.AddGroup(g)
	}
	mustDo(t, e.hub, "root", "POST", "/api/directory/fields", `{"name":"clearance","label":"Clearance","kind":"text","admin_only":true}`, 200)
	mustDo(t, e.hub, "root", "POST", "/api/directory/fields", `{"name":"dept","label":"Dept","kind":"text"}`, 200)
	mustDo(t, e.hub, "root", "PUT", "/api/directory/permissions/edit_details", `{"group":"hr_edit"}`, 200)
	mustDo(t, e.hub, "root", "POST", "/api/directory/groups/admin_secretapp/convert", `{"rule":"clearance = \"top\"","preview":{"matching":[],"kept_as_exception":[],"joining":[],"expiry_dropped":[]}}`, 200)
	byName := map[string]Tool{}
	for _, tl := range e.s.tools(ScopeAdmin) {
		byName[tl.Name] = tl
	}
	class := func(tool string, args any) ToolClass {
		b, _ := json.Marshal(args)
		tl := byName[tool]
		if tl.ClassFor == nil {
			return tl.Class
		}
		return tl.ClassFor(b)
	}
	rows := []struct {
		tool string
		args any
		want ToolClass
	}{
		{"add_member", map[string]any{"group": "helpers", "username": "dana"}, ClassWrite},
		{"add_member", map[string]any{"group": "lldap_admin", "username": "dana"}, ClassDestructive},
		{"add_member", map[string]any{"group": "LLDAP_ADMIN", "username": "dana"}, ClassDestructive},
		{"add_member", map[string]any{"group": "lldap_password_manager", "username": "dana"}, ClassDestructive},
		{"add_member", map[string]any{"group": "hr_edit", "username": "dana"}, ClassDestructive},
		{"add_member", map[string]any{"group": "admin_secretapp", "username": "dana"}, ClassDestructive},
		{"add_member", map[string]any{"group": "nosuch", "username": "dana"}, ClassDestructive},
		{"set_member_expiry", map[string]any{"group": "helpers", "username": "dana", "until": "2099-01-01T00:00:00Z"}, ClassWrite},
		{"set_member_expiry", map[string]any{"group": "hr_edit", "username": "dana"}, ClassDestructive},
		{"set_group_rule", map[string]any{"group": "helpers", "manual": true}, ClassWrite},
		{"set_group_rule", map[string]any{"group": "admin_secretapp", "rule": `clearance = "x"`}, ClassDestructive},
		{"convert_group", map[string]any{"group": "helpers", "rule": `dept = "x"`, "preview": map[string]any{}}, ClassWrite},
		{"convert_group", map[string]any{"group": "hr_edit", "rule": `clearance = "x"`, "preview": map[string]any{}}, ClassDestructive},
		{"add_exception", map[string]any{"group": "helpers", "user": "dana", "reason": "r"}, ClassWrite},
		{"add_exception", map[string]any{"group": "admin_secretapp", "user": "dana", "reason": "r", "include": true}, ClassDestructive},
		{"remove_exception", map[string]any{"group": "helpers", "username": "dana"}, ClassWrite},
		{"remove_exception", map[string]any{"group": "admin_secretapp", "username": "dana"}, ClassDestructive},
		{"create_person", map[string]any{"username": "x", "email": "x@example.org", "display_name": "X"}, ClassWrite},
		{"create_person", map[string]any{"username": "x", "email": "x@example.org", "display_name": "X", "groups": []string{"helpers"}}, ClassDestructive},
		{"set_details", map[string]any{"username": "dana", "attrs": map[string]any{"dept": []string{"Eng"}}}, ClassWrite},
		{"set_details", map[string]any{"username": "dana", "attrs": map[string]any{"clearance": []string{"top"}}}, ClassDestructive},
		{"import_apply", map[string]any{"rows": []any{map[string]any{"user": "dana", "display_name": "D", "attrs": map[string]any{"dept": []string{"Eng"}}}}}, ClassWrite},
		{"import_apply", map[string]any{"rows": []any{map[string]any{"user": "dana", "attrs": map[string]any{"clearance": []string{"top"}}}}}, ClassDestructive},
		{"import_apply", map[string]any{"rows": []any{map[string]any{"user": "zed", "create": true, "email": "zed@example.org", "display_name": "Zed"}}}, ClassDestructive},
		{"import_apply", map[string]any{"rows": []any{map[string]any{"user": "dana", "remove": true}}}, ClassDestructive},
		{"set_permission", map[string]any{"perm": "invite", "group": ""}, ClassDestructive},
	}
	for _, r := range rows {
		if got := class(r.tool, r.args); got != r.want {
			t.Errorf("%s %v = %s, want %s", r.tool, r.args, got, r.want)
		}
	}
	// The directory down: every per-call one fails closed.
	e.s.Directory.LLDAP = brokenLLDAP{e.s.Directory.LLDAP}
	for _, r := range rows {
		if r.want == ClassWrite && r.tool != "create_person" {
			if got := class(r.tool, r.args); got != ClassDestructive {
				t.Errorf("directory down: %s %v = %s, want D", r.tool, r.args, got)
			}
		}
	}
}

// TestSetPasswordForm (U, ruling 4): set_password takes no password, its
// call answers the Hub's form https://hub.<d>/#users/<name>?password;
// accepted, it reports the newest user.password audit entry (server-side
// evidence, never the client's accept) and never a password.
func TestSetPasswordForm(t *testing.T) {
	e, _ := directoryToolEnv(t)
	txt, isErr := resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "set_password", map[string]any{"username": "dana"}, nil))
	if !isErr || !strings.Contains(txt, "https://hub.example.org/#users/dana?password") {
		t.Errorf("set_password = %q", txt)
	}
	const marker = "PWMARKER-0123456789"
	txt, isErr = resultText(e.call(t, "/mcp/admin", "root", "2025-11-25", "set_password", map[string]any{"username": "dana", "password": marker}, nil))
	if !isErr || !strings.HasPrefix(txt, textSecretArgs+"https://hub.example.org/#users/dana?password") {
		t.Errorf("set_password with a password = %q", txt)
	}
	txt, isErr = e.accept(t, "set_password", map[string]any{"username": "dana"})
	if isErr || !strings.Contains(txt, `"last_set":null`) {
		t.Errorf("accepted before any change = %q %v", txt, isErr)
	}
	mustDo(t, e.hub, "root", "POST", "/api/directory/users/dana/password", `{"password":"`+marker+`"}`, 200)
	txt, isErr = e.accept(t, "set_password", map[string]any{"username": "dana"})
	if isErr || !strings.Contains(txt, `"result":"ok"`) || !strings.Contains(txt, `"actor":"root"`) || strings.Contains(txt, marker) {
		t.Errorf("accepted after the change = %q %v", txt, isErr)
	}
}

// TestAuditRecentPaginated (ruling 7): audit_recent pages through the
// audit log, newest first, at most 200 per call; entries made through
// the Portcullis MCP carry via and client; via=ai keeps only those.
func TestAuditRecentPaginated(t *testing.T) {
	e, _ := directoryToolEnv(t)
	for i := range 5 {
		mustDo(t, e.hub, "root", "POST", "/api/directory/groups", `{"name":"g`+string(rune('a'+i))+`"}`, 200)
	}
	if txt, isErr, _ := e.tool(t, "create_group", map[string]any{"name": "viaai"}); isErr {
		t.Fatal(txt)
	}
	page := func(args map[string]any) (out struct {
		Entries    []directory.AuditEntry `json:"entries"`
		NextOffset *int                   `json:"next_offset"`
	}) {
		t.Helper()
		txt, isErr, _ := e.tool(t, "audit_recent", args)
		if isErr || json.Unmarshal([]byte(txt), &out) != nil {
			t.Fatalf("audit_recent %v = %q", args, txt)
		}
		return out
	}
	p := page(map[string]any{"limit": 2})
	if len(p.Entries) != 2 || p.Entries[0].Target != "viaai" || p.Entries[0].Via != "ai" || p.Entries[0].Client != mcpClient || p.NextOffset == nil || *p.NextOffset != 2 {
		t.Fatalf("first page = %+v", p)
	}
	p2 := page(map[string]any{"limit": 2, "offset": 2})
	if len(p2.Entries) != 2 || p2.Entries[0].Target != "gd" || p2.Entries[1].Target != "gc" {
		t.Errorf("second page = %+v", p2)
	}
	ai := page(map[string]any{"via": "ai"})
	if len(ai.Entries) != 1 || ai.Entries[0].Target != "viaai" || ai.NextOffset != nil {
		t.Errorf("via ai = %+v", ai)
	}
	for _, bad := range []map[string]any{{"limit": 201}, {"limit": -1}, {"offset": -1}, {"via": "human"}} {
		if txt, isErr, _ := e.tool(t, "audit_recent", bad); !isErr || !strings.HasPrefix(txt, "400: ") {
			t.Errorf("audit_recent %v = %q %v", bad, txt, isErr)
		}
	}
}
