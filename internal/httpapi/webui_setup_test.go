package httpapi

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/templates"
)

// Apps & instances Task 7: the setup form shown before an instance first
// starts (Install… / + Add instance). The browser behaviour is checked
// against the harness (task-7-report.md); these tests pin the id derived
// from the label (CheckIDShape's rules), the create body for each groups
// mode and where a refusal of the Hub is shown.

// setupJS runs the setup form's helpers from the served page with stub
// state and answers expr (JSON).
func setupJS(t *testing.T, expr string) any {
	t.Helper()
	page := hubIndex(t)
	var src strings.Builder
	src.WriteString(`let catalogCache = {nextcloud: {manifest: {name: "Nextcloud", icon: "☁️", instances: "multi"}}};
const PortcullisSettings = { setupEditorHtml: o => '<span data-ed data-key="' + escapeHtml(o.key) + '"></span>' };
`)
	i := strings.Index(page, "    const HOST_LABEL_RE = ")
	if i < 0 {
		t.Fatal("the hub index lacks HOST_LABEL_RE")
	}
	src.WriteString(page[i : i+strings.Index(page[i:], "\n")+1])
	for _, fn := range []string{"escapeHtml", "normHost", "hostProblem", "appName", "templateLabel", "modalHead", "deriveInstanceId", "idShapeProblem",
		"setupGroupNames", "setupHost", "setupFormHtml", "usersGroupChoices", "setupDerivedText", "setupProblems", "setupRequestBody", "setupErrorField"} {
		src.WriteString(hubFunc(t, page, fn))
	}
	var v any
	out := runNode(t, src.String()+"\nprocess.stdout.write(JSON.stringify("+expr+"));\n")
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return v
}

// TestHubSetupDeriveID: a label gives "<template>-<its words>" by
// CheckIDShape's rules — lowercase ASCII letters and digits joined by
// single "-", no "portcullis" segment, at most 31 characters, never the
// template id itself; every derived id passes the Hub's own checks.
func TestHubSetupDeriveID(t *testing.T) {
	cases := map[string]string{
		"Family":                                "nextcloud-family",
		"Nextcloud family":                      "nextcloud-family",
		"  Team  A  ":                           "nextcloud-team-a",
		"Équipe Zürich":                         "nextcloud-equipe-zurich",
		"ops__2026--x":                          "nextcloud-ops-2026-x",
		"Portcullis team":                       "nextcloud-team",
		"portcullis":                            "",
		"Nextcloud":                             "",
		"":                                      "",
		"!!!":                                   "",
		"日本":                                    "",
		"a very long label that keeps going on": "nextcloud-a-very-long-label-tha",
		"Team-":                                 "nextcloud-team",
		"x portcullisx":                         "nextcloud-x-portcullisx",
		"Cloud <script>":                        "nextcloud-cloud-script",
	}
	labels := make([]string, 0, len(cases))
	for k := range cases {
		labels = append(labels, k)
	}
	b, _ := json.Marshal(labels)
	got, ok := setupJS(t, string(b)+`.map(l => deriveInstanceId("nextcloud", l))`).([]any)
	if !ok || len(got) != len(labels) {
		t.Fatalf("derived = %v", got)
	}
	for i, l := range labels {
		id, _ := got[i].(string)
		if id != cases[l] {
			t.Errorf("%q → %q, want %q", l, id, cases[l])
		}
		if id == "" {
			continue
		}
		if err := templates.CheckIDShape(id); err != nil || !templates.InstanceIDRe.MatchString(id) || strings.HasPrefix(id, templates.ReservedInstancePrefix) {
			t.Errorf("%q → %q, which the Hub refuses (%v)", l, id, err)
		}
	}
	// A template id of several words isn't repeated either.
	if got := setupJS(t, `[deriveInstanceId("home-assistant", "Home Assistant upstairs"), deriveInstanceId("home-assistant", "Home office")]`); fmt.Sprint(got) != "[home-assistant-upstairs home-assistant-home-office]" {
		t.Errorf("multi-word template = %v", got)
	}
	// The id check says what CheckIDShape would refuse.
	shape := setupJS(t, `["nextcloud-a", "nextcloud", "Nextcloud-a", "1cloud", "next_cloud", "next--cloud", "next-", "next-portcullis-x", "a234567890123456789012345678901x", ""].map(i => idShapeProblem(i, "nextcloud"))`).([]any)
	for i, wantOK := range []bool{true, true, false, false, false, false, false, false, false, false} {
		if (shape[i] == "") != wantOK {
			t.Errorf("idShapeProblem #%d = %q", i, shape[i])
		}
	}
}

// TestHubSetupRequestBody: the form's POST /api/instances body for a
// first instance and a further one, groups new and existing (only the
// fields the manifest has), the hosts on the chosen domain, and setup
// values only when given.
func TestHubSetupRequestBody(t *testing.T) {
	got := setupJS(t, `(() => {
	  const ctx = {tid: "nextcloud", first: false, access: true, admin: true, setup: [], routers: [], domains: []};
	  const v = {label: "Family", id: "nextcloud-family", domain: "example.org", subs: {nextcloud: "Cloud-Family"}, mode: "new", users: "ignored", admins: "ignored", setup: {database: "mysql", default_quota: 20}};
	  const first = Object.assign({}, ctx, {first: true});
	  const usersOnly = Object.assign({}, ctx, {admin: false});
	  const none = Object.assign({}, ctx, {access: false, admin: false});
	  return [
	    setupRequestBody(ctx, v),
	    setupRequestBody(ctx, Object.assign({}, v, {mode: "existing", users: "family", admins: "lldap_admin", setup: {}})),
	    setupRequestBody(usersOnly, Object.assign({}, v, {mode: "existing", users: "family", admins: "x"})),
	    setupRequestBody(first, Object.assign({}, v, {id: "nextcloud", subs: {nextcloud: "", web: "files"}, domain: "team.example.net", setup: {}})),
	    setupRequestBody(none, Object.assign({}, v, {subs: {}, setup: {}})),
	  ];
	})()`)
	b, _ := json.Marshal(got)
	want := `[` +
		`{"template":"nextcloud","id":"nextcloud-family","label":"Family","hosts":{"nextcloud":"cloud-family.example.org"},"groups":{"mode":"new"},"setup":{"database":"mysql","default_quota":20}},` +
		`{"template":"nextcloud","id":"nextcloud-family","label":"Family","hosts":{"nextcloud":"cloud-family.example.org"},"groups":{"mode":"existing","users":"family","admins":"lldap_admin"}},` +
		`{"template":"nextcloud","id":"nextcloud-family","label":"Family","hosts":{"nextcloud":"cloud-family.example.org"},"groups":{"mode":"existing","users":"family"},"setup":{"database":"mysql","default_quota":20}},` +
		`{"template":"nextcloud","id":"nextcloud","label":"Family","hosts":{"nextcloud":"team.example.net","web":"files.team.example.net"},"groups":{"mode":"new"}},` +
		`{"template":"nextcloud","id":"nextcloud-family","label":"Family"}]`
	var w any
	json.Unmarshal([]byte(want), &w)
	if wb, _ := json.Marshal(w); string(b) != string(wb) {
		t.Errorf("bodies =\n%s\nwant\n%s", b, want)
	}
	// The body the Hub decodes strictly: every key one of the route's.
	var bodies []map[string]json.RawMessage
	json.Unmarshal(b, &bodies)
	for _, body := range bodies {
		for k := range body {
			if !strings.Contains("template id label hosts groups setup", k) {
				t.Errorf("unknown key %q", k)
			}
		}
	}

	// Checked before sending: label, id, hosts, missing groups, an
	// editor's own error.
	p := setupJS(t, `(() => {
	  const ctx = {tid: "nextcloud", first: false, access: true, admin: true, setup: [], routers: [{router: "nextcloud", subdomain: "cloud"}],
	    domains: [{name: "example.org", main: true, assignable: true}]};
	  return [
	    setupProblems(ctx, {label: "", id: "Bad_id", domain: "example.org", subs: {nextcloud: "a.b"}, mode: "existing", users: "", admins: "", setup: {}, bad: {"setup:default_quota": "at least 1"}}),
	    setupProblems(ctx, {label: "Family", id: "nextcloud-family", domain: "example.org", subs: {nextcloud: "cloud-family"}, mode: "new", users: "", admins: "", setup: {}, bad: {}}),
	    setupProblems(Object.assign({}, ctx, {first: true}), {label: "x".repeat(65), id: "anything", domain: "example.org", subs: {nextcloud: "cloud"}, mode: "existing", users: "family", admins: "", setup: {}, bad: {}}),
	  ].map(o => Object.keys(o).sort().join(","));
	})()`)
	if fmt.Sprint(p) != "[admins,hosts,id,label,setup:default_quota,users  admins,label]" {
		t.Errorf("problems = %q", p)
	}
}

// TestHubSetupErrorPlacement: every refusal the Hub answers a create
// with is shown next to its field — the real texts of the route — and
// the form has a slot for each field (the setup options' included); a
// hostile option label or key stays text.
func TestHubSetupErrorPlacement(t *testing.T) {
	e := newInstEnvWith(t, t.TempDir(), map[string][2]string{"dbapp": {dbappManifest, dbappCompose}}, nil)
	e.ll.AddGroup("family", "alice")
	if code, b := e.do(t, "root", "POST", "/api/instances", `{"template":"grafana","id":"grafana-taken","label":"Taken"}`); code != 202 {
		t.Fatalf("seed = %d %s", code, b)
	}
	waitIdle(t, e.s.Hub, "grafana-taken")
	cases := []struct{ body, field string }{
		{`{"template":"grafana","id":"grafana-x"}`, "label"},
		{`{"template":"grafana","id":"grafana-x","label":" x"}`, "label"},
		{`{"template":"grafana","id":"grafana-x","label":"x\u200b"}`, "label"},
		{`{"template":"grafana","id":"Bad_ID","label":"X"}`, "id"},
		{`{"template":"grafana","id":"grafana-portcullis","label":"X"}`, "id"},
		{`{"template":"grafana","id":"grafana-a--b","label":"X"}`, "id"},
		{`{"template":"grafana","id":"grafana-taken","label":"X"}`, "id"},
		{`{"template":"grafana","id":"home","label":"X"}`, "id"},
		{`{"template":"grafana","id":"grafana-x","label":"X","hosts":{"grafana":"a.b.example.org"}}`, "hosts"},
		{`{"template":"grafana","id":"grafana-x","label":"X","hosts":{"grafana":"grafana-taken.example.org"}}`, "hosts"},
		{`{"template":"grafana","id":"grafana-x","label":"X","hosts":{"grafana":"g.pending.example.net"}}`, "hosts"},
		{`{"template":"grafana","id":"grafana-x","label":"X","hosts":{"nope":"g.example.org"}}`, "hosts"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{"mode":"existing","users":"lldap_admin","admins":"lldap_admin"}}`, "users"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{"mode":"existing","users":"lldap_password_manager","admins":"lldap_admin"}}`, "users"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{"mode":"existing","users":"nope","admins":"lldap_admin"}}`, "users"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{"mode":"existing","users":"family","admins":"nope"}}`, "admins"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{"mode":"existing","admins":"lldap_admin"}}`, "users"},
		{`{"template":"grafana","id":"grafana-x","label":"X","groups":{"mode":"existing","users":"family"}}`, "admins"},
		{`{"template":"dbapp","id":"dbapp-x","label":"X","setup":{"database":"oracle"}}`, "setup:database"},
		{`{"template":"dbapp","id":"dbapp-x","label":"X","setup":{"trash_days":7}}`, "setup:trash_days"},
	}
	type sent struct {
		Msg string            `json:"msg"`
		V   map[string]string `json:"v"`
	}
	var in []sent
	for _, c := range cases {
		code, b := e.do(t, "root", "POST", "/api/instances", c.body)
		if code != 400 && code != 409 {
			t.Fatalf("%s = %d %s, want a refusal", c.body, code, b)
		}
		var body struct {
			Groups struct{ Users, Admins string } `json:"groups"`
		}
		json.Unmarshal([]byte(c.body), &body)
		in = append(in, sent{strings.TrimSpace(b), map[string]string{"users": body.Groups.Users, "admins": body.Groups.Admins}})
	}
	b, _ := json.Marshal(in)
	got, ok := setupJS(t, `(() => {
	  const ctx = {tid: "grafana", setup: [{key: "database", label: "Database"}, {key: "default_quota", label: "Default quota"}, {key: "trash_days", label: "Trash days"}]};
	  return `+string(b)+`.map(c => setupErrorField(c.msg, ctx, c.v));
	})()`).([]any)
	if !ok || len(got) != len(cases) {
		t.Fatalf("fields = %v", got)
	}
	for i, c := range cases {
		if got[i] != c.field {
			t.Errorf("%q → %v, want %s", in[i].Msg, got[i], c.field)
		}
	}
	// Not about one field: the general slot.
	if f := setupJS(t, `["busy: create is running on this app", "users & groups is not available: the groups to bind can't be checked", "the template changed while creating: try again"].map(m => setupErrorField(m, {setup: []}, {}))`); fmt.Sprint(f) != "[general general general]" {
		t.Errorf("general = %v", f)
	}
	// A fixed choice (a started default instance's) is its option's.
	if f := setupJS(t, `setupErrorField("Database is fixed after the first start: changing it would mean moving the data (create a new instance and restore a backup into it)", {setup: [{key: "database", label: "Database"}]}, {})`); f != "setup:database" {
		t.Errorf("fixed = %v", f)
	}

	// The form's slots: one per field it shows, the general one, the
	// lock on a fixed choice; markup escaped.
	html, _ := setupJS(t, `setupFormHtml({tid: "nextcloud", first: false, access: true, admin: true, accessName: "users_nextcloud", adminName: "admin_nextcloud",
	  setup: [{key: "database", label: "Data<b>base</b>", fixed_after_start: true}, {key: "q\"><img src=x>", label: "Quota", description: "<i>GiB</i>"}]})`).(string)
	for _, want := range []string{`data-setup-err="label"`, `data-setup-err="id"`, `data-setup-err="hosts"`, `data-setup-err="users"`, `data-setup-err="admins"`,
		`data-setup-err="groups"`, `data-setup-err="setup:database"`, `data-setup-err="general"`, `data-setup-go="start">Start</button>`,
		`data-setup-go="save">Save without starting</button>`, `data-inst-close="1">Cancel</button>`, "🔒 fixed after the first start (changing it would mean moving the data)",
		"Data&lt;b&gt;base&lt;/b&gt;", "&lt;i&gt;GiB&lt;/i&gt;", "Change it any time in Settings.", "Nothing starts until you press Start.", "Set up ☁️ Nextcloud",
		`value="new" data-setup-groups-mode checked> New groups from the label`, `value="existing" data-setup-groups-mode> Existing groups`, "users: <code>users_&lt;id&gt;</code>"} {
		if !strings.Contains(html, want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	for _, bad := range []string{"<b>base", "<img", "<i>GiB"} {
		if strings.Contains(html, bad) {
			t.Errorf("the form carries %q", bad)
		}
	}
	// The first instance: its id locked to the template's, the manifest's
	// groups; a template without groups asks nobody.
	first, _ := setupJS(t, `setupFormHtml({tid: "nextcloud", first: true, access: true, admin: false, accessName: "users_nextcloud", adminName: "", setup: []})`).(string)
	if !regexp.MustCompile(`id="setup-id" data-setup-id value="nextcloud" spellcheck="false" maxlength="31" readonly>`).MatchString(first) ||
		!strings.Contains(first, "users: <code>users_nextcloud</code>") || strings.Contains(first, "setup-admins") || strings.Contains(first, "Setup choices") {
		t.Errorf("first instance form = %s", first)
	}
	if bare, _ := setupJS(t, `setupFormHtml({tid: "nextcloud", first: false, access: false, admin: false, setup: []})`).(string); strings.Contains(bare, "Who can use it") {
		t.Error("a template without groups asks who can use it")
	}
	// Users choices: no built-in, administrator or permission group.
	if g := setupJS(t, `usersGroupChoices({groups: [{name: "family"}, {name: "lldap_admin", builtin: true}, {name: "it", admin: true}, {name: "inviters"}, {name: "team"}], permissions: {invite: "inviters"}}).map(g => g.name)`); fmt.Sprint(g) != "[family team]" {
		t.Errorf("users choices = %v", g)
	}
}
