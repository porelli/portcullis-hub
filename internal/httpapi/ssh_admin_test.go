package httpapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/state"
)

// sshPeopleEnv: SSH on, bob ordinary, sam holds ssh_access, helga
// sign_in_help; web is delegable.
func sshPeopleEnv(t *testing.T) *peopleEnv {
	t.Helper()
	e := newPeopleEnv(t)
	e.ll.AddGroup("ssh_mgrs")
	e.ll.AddGroup("hr_help")
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	e.ll.AddUser("sam", "sam@example.org", "Sam", "", "ssh_mgrs")
	e.ll.AddUser("helga", "helga@example.org", "Helga", "", "hr_help")
	mustDo(t, e.people, "root", "PUT", "/api/directory/permissions/ssh_access", `{"group":"ssh_mgrs"}`, 200)
	mustDo(t, e.people, "root", "PUT", "/api/directory/permissions/sign_in_help", `{"group":"hr_help"}`, 200)
	enableSSH(t, e.s.Hub)
	return e
}

func TestSSHAdminRoutesAdminOnly(t *testing.T) {
	e := sshPeopleEnv(t)
	for _, r := range e.s.hubMux().patterns {
		if !strings.Contains(r, "/api/ssh/") {
			continue
		}
		method, path, _ := strings.Cut(r, " ")
		path = strings.NewReplacer("{id}", "web", "{name}", "bob", "{u}", "bob").Replace(path)
		resp, _ := doAs(t, e.hub, "bob", method, path, `{}`)
		if resp.StatusCode != 403 {
			t.Errorf("bob %s %s = %d, want 403", method, path, resp.StatusCode)
		}
	}
	if b := mustDo(t, e.hub, "root", "GET", "/api/ssh/settings", "", 200); !strings.Contains(b, `"enabled":true`) {
		t.Errorf("settings %s", b)
	}
	// SSH admin routes never on the people listener.
	if r, _ := doAs(t, e.people, "root", "GET", "/api/ssh/settings", ""); r.StatusCode != 404 && r.StatusCode != 405 {
		t.Errorf("people listener answers /api/ssh/settings: %d", r.StatusCode)
	}
}

func TestSSHAdminWritesNeedFresh(t *testing.T) {
	e := sshPeopleEnv(t)
	// Switching SSH off needs no fresh sign-in; back on does.
	mustDo(t, e.hub, "root", "PUT", "/api/ssh/settings", `{"enabled":false,"default_ttl_hours":8}`, 200)
	if r, _ := doAs(t, e.hub, "root", "PUT", "/api/ssh/settings", `{"enabled":true,"default_ttl_hours":8}`); r.StatusCode != 403 {
		t.Errorf("enable without a fresh sign-in = %d", r.StatusCode)
	}
	enableSSH(t, e.s.Hub)
	mustDo(t, e.hub, "root", "POST", "/api/ssh/hostgroups", `{"id":"web","label":"Web"}`, 204)
	// Label only: no proof needed. Delegable: access changes → proof.
	mustDo(t, e.hub, "root", "PUT", "/api/ssh/hostgroups/web", `{"label":"Web servers"}`, 204)
	if r, _ := doAs(t, e.hub, "root", "PUT", "/api/ssh/hostgroups/web", `{"label":"Web servers","delegable":true}`); r.StatusCode != 403 {
		t.Errorf("delegable without a fresh sign-in = %d", r.StatusCode)
	}
	// Creating a host returns a code and needs the fresh sign-in.
	if r, _ := doAs(t, e.hub, "root", "POST", "/api/ssh/hosts", `{"id":"web-1","names":["web-1.example.org"],"host_groups":["web"],"managed":true}`); r.StatusCode != 403 {
		t.Errorf("create host without a fresh sign-in = %d", r.StatusCode)
	}
}

func TestDelegatedRoutesHolderOnly(t *testing.T) {
	e := sshPeopleEnv(t)
	for _, p := range []string{"/api/ssh/delegated/grants", "/api/ssh/delegated/hostgroups/web/access"} {
		if r, _ := doAs(t, e.people, "bob", "GET", p, ""); r.StatusCode != 403 {
			t.Errorf("bob GET %s = %d", p, r.StatusCode)
		}
	}
	if b := mustDo(t, e.people, "sam", "GET", "/api/ssh/delegated/grants", "", 200); !strings.Contains(b, `"grants":[]`) {
		t.Errorf("sam's grants %s", b)
	}
	// all isn't delegable.
	if r, _ := doAs(t, e.people, "sam", "GET", "/api/ssh/delegated/hostgroups/all/access", ""); r.StatusCode != 403 {
		t.Errorf("non-delegable host group access = %d", r.StatusCode)
	}
}

func TestPeopleMySSH(t *testing.T) {
	e := sshPeopleEnv(t)
	var v map[string]any
	json.Unmarshal([]byte(mustDo(t, e.people, "bob", "GET", "/api/me/ssh", "", 200)), &v)
	if v["user"] != "bob" || v["enabled"] != true {
		t.Errorf("card %v", v)
	}
	if cmds, _ := v["commands"].([]any); len(cmds) != 2 || !strings.HasPrefix(cmds[0].(string), "portcullis login ") {
		t.Errorf("commands %v", v["commands"])
	}
	if b := mustDo(t, e.people, "bob", "POST", "/api/me/ssh/revoke-all", "", 200); !strings.Contains(b, `"revoked":0`) {
		t.Errorf("revoke-all %s", b)
	}
}

func TestRevokeAllHelperRules(t *testing.T) {
	e := sshPeopleEnv(t)
	mustDo(t, e.people, "helga", "GET", "/api/directory/users/bob/ssh", "", 200)
	mustDo(t, e.people, "helga", "POST", "/api/directory/users/bob/ssh/revoke-all", "", 200)
	// An administrator's certificates: administrators only.
	if r, _ := doAs(t, e.people, "helga", "POST", "/api/directory/users/root/ssh/revoke-all", ""); r.StatusCode != 403 {
		t.Errorf("helga → root = %d", r.StatusCode)
	}
	if r, _ := doAs(t, e.people, "bob", "GET", "/api/directory/users/sam/ssh", ""); r.StatusCode != 403 {
		t.Errorf("bob → sam = %d", r.StatusCode)
	}
	mustDo(t, e.people, "root", "POST", "/api/directory/users/sam/ssh/revoke-all", "", 200)
}

func TestMCPNeverSignsOrCodes(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	for _, scope := range []string{ScopeAdmin, ScopePeople} {
		for _, tl := range e.s.tools(scope) {
			n := tl.Name
			for _, bad := range []string{"sign", "certify", "enrol", "code", "host_cert", "source", "ssh_settings", "rotate", "privileged"} {
				if strings.Contains(n, "ssh") && strings.Contains(n, bad) {
					t.Errorf("tool %s looks like it %s", n, bad)
				}
			}
			if strings.Contains(n, "ssh") && (strings.HasPrefix(tl.Twin, "POST /api/ssh/hosts") || tl.Twin == "POST /api/ssh/host-certificates" ||
				tl.Twin == "PUT /api/ssh/settings" || strings.HasPrefix(tl.Twin, "POST /api/ssh/hostgroups") || strings.HasPrefix(tl.Twin, "PUT /api/ssh/hostgroups")) {
				t.Errorf("tool %s mirrors %s", n, tl.Twin)
			}
		}
	}
}

func TestMCPSetGrantRefusesPrivileged(t *testing.T) {
	e := newToolEnv(t, nil, nil)
	var tool *Tool
	for _, tl := range e.s.tools(ScopeAdmin) {
		if tl.Name == "set_ssh_grant" {
			tl := tl
			tool = &tl
		}
	}
	if tool == nil {
		t.Fatal("no set_ssh_grant")
	}
	// Its arguments can't express sudo, root forwarding or agent forwarding.
	b, _ := json.Marshal(tool.In)
	for _, f := range []string{"sudo", "agent_forwarding"} {
		if strings.Contains(string(b), f) {
			t.Errorf("set_ssh_grant takes %s", f)
		}
	}
	// The Hub refuses a privileged grant via AI whatever the arguments.
	ai := &directory.Caller{User: "root", Admin: true, Via: directory.ViaAI, Client: "x"}
	_, err := e.s.Hub.SaveGrant(t.Context(), ai, sshGrantFor("all"), "", nil)
	if err == nil {
		t.Error("a grant on all (privileged) via AI accepted")
	}
}

func sshGrantFor(hg string) (g state.SSHGrant) {
	g.Group, g.HostGroup, g.Accounts, g.Sudo = "staff", hg, []string{"{username}"}, "none"
	return g
}

// TestSSHToolConsequencesShowEveryField: every argument of an SSH D tool
// that takes effect appears in its confirmation. A field added later
// without its line fails here (the map must name it).
func TestSSHToolConsequencesShowEveryField(t *testing.T) {
	cases := map[string]struct {
		in   any
		show map[string]string // JSON field → text the consequences must hold
	}{
		"set_ssh_grant": {sshGrantArgs{}, map[string]string{
			"id": "Replaces grant", "group": `"g-group"`, "host_group": `"g-host_group"`, "accounts": `"g-accounts"`,
			"ttl_hours": "Certificates last 7 h", "port_forwarding": "Allows port forwarding"}},
		"revoke_ssh_certificates": {sshRevokeArgs{}, map[string]string{"user": `"g-user"`, "fingerprints": `"g-fingerprints"`}},
	}
	e := newToolEnv(t, nil, nil)
	for name, c := range cases {
		var tool *Tool
		for _, tl := range e.s.tools(ScopeAdmin) {
			if tl.Name == name {
				tl := tl
				tool = &tl
			}
		}
		if tool == nil {
			t.Fatalf("no %s", name)
		}
		rt := reflect.TypeOf(c.in)
		args := map[string]any{}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if _, ok := c.show[key]; !ok {
				t.Errorf("%s: argument %s has no consequence line in this test (add one, and show it)", name, key)
				continue
			}
			switch f.Type.Kind() {
			case reflect.String:
				args[key] = "g-" + key
			case reflect.Slice:
				args[key] = []string{"g-" + key}
			case reflect.Bool:
				args[key] = true
			case reflect.Int:
				args[key] = 7
			default:
				t.Errorf("%s: argument %s of kind %s", name, key, f.Type.Kind())
			}
		}
		raw, _ := json.Marshal(args)
		text := strings.Join(tool.Consequences(t.Context(), raw), "\n")
		for key, want := range c.show {
			if !strings.Contains(text, want) {
				t.Errorf("%s: %s isn't shown (%q missing) in %q", name, key, want, text)
			}
		}
	}
	// Every SSH D tool is covered here.
	for _, tl := range e.s.tools(ScopeAdmin) {
		if strings.Contains(tl.Name, "ssh") && tl.Class == ClassDestructive {
			if _, ok := cases[tl.Name]; !ok {
				t.Errorf("D tool %s isn't covered", tl.Name)
			}
		}
	}
}

// The UI's reads: Settings carries the listener's fresh sign-in flow
// field, the delegate list its delegable host groups (none yet), the
// group page's uses the group's SSH line.
func TestSSHPageReads(t *testing.T) {
	e := sshPeopleEnv(t)
	var set map[string]any
	json.Unmarshal([]byte(mustDo(t, e.hub, "root", "GET", "/api/ssh/settings", "", 200)), &set)
	if _, ok := set["user_ca_fp"]; !ok {
		t.Errorf("settings lost the view's fields: %v", set)
	}
	if b := mustDo(t, e.people, "sam", "GET", "/api/ssh/delegated/grants", "", 200); !strings.Contains(b, `"host_groups":[]`) {
		t.Errorf("delegated %s", b)
	}
	e.s.Hub.SetPeople(e.s.Directory)
	e.s.Hub.SetSSHDirectory(e.s.Directory)
	mustDo(t, e.hub, "root", "POST", "/api/ssh/hostgroups", `{"id":"web","label":"Web"}`, 204)
	mustDo(t, e.hub, "root", "POST", "/api/ssh/grants", `{"group":"ssh_mgrs","host_group":"web","accounts":["{username}"],"sudo":"none"}`, 200)
	var u struct {
		SSH []string `json:"ssh"`
	}
	json.Unmarshal([]byte(mustDo(t, e.people, "root", "GET", "/api/directory/groups/ssh_mgrs/uses", "", 200)), &u)
	if !reflect.DeepEqual(u.SSH, []string{"web (own account)"}) {
		t.Errorf("group uses ssh %v", u.SSH)
	}
	json.Unmarshal([]byte(mustDo(t, e.people, "root", "GET", "/api/directory/groups/hr_help/uses", "", 200)), &u)
	if u.SSH == nil || len(u.SSH) != 0 {
		t.Errorf("unused group ssh %v, want []", u.SSH)
	}
}
