package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// The person / group picker (directory.js PortcullisPicker), the settings
// panel's row group check (settings.js rowGroupError), the Add to group…
// refusal (directory.js addToGroupPick) and the hash routing run under
// node against the served assets, like TestSharedNav (skipped without
// node; CI has it).

// jsBlock answers src from the line starting with start up to and
// including the first end after it.
func jsBlock(t *testing.T, src, start, end string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("no %q", start)
	}
	j := strings.Index(src[i:], end)
	if j < 0 {
		t.Fatalf("no end %q after %q", end, start)
	}
	return src[i : i+j+len(end)]
}

const nodeEsc = "const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&#39;');\n"

func nodeJSON(t *testing.T, script string, v any) {
	t.Helper()
	out := runNode(t, script)
	if err := json.Unmarshal([]byte(out), v); err != nil {
		t.Fatalf("node said %q: %v", out, err)
	}
}

// TestPickerJS: matching, escaping, exclusions (a textarea's other lines
// too) and refused choices.
func TestPickerJS(t *testing.T) {
	js := webAsset(t, "directory.js")
	block := jsBlock(t, js, "  const PortcullisPicker = (function () {", "\n  })();\n")
	script := "global.window = { addEventListener() {} };\nglobal.document = { addEventListener() {} };\n" +
		"let dir = null;\nconst api = () => Promise.reject(new Error('no fetch in tests'));\n" + nodeEsc + block + `
const P = PortcullisPicker;
const users = [
  { username: '<img src=x onerror=alert(1)>', display_name: 'Mal "lory" <b>', email: 'x"y@e.org' },
  { username: 'alice', display_name: 'Alice Liddell', email: 'alice@example.org' },
  { username: 'bob', display_name: 'Bob', email: 'bob@example.org' },
  { username: 'carol', display_name: 'Carol', email: 'carol@example.org' },
];
const out = {};
out.byDisplay = P.matchItems('person', users, 'LIDD', new Set()).map(i => i.value);
out.byEmail = P.matchItems('person', users, 'bob@', new Set()).map(i => i.value);
const mal = P.matchItems('person', users, 'mal', new Set());
out.malHtml = P.optionsHtml('person', mal, 'pp-list-1');
const groups = [{ name: 'ops<script>', kind: 'manual', disabled: true, reason: 'can\'t "grant" <x>' }, { name: 'ops_b', rule: { text: 'x' } }, { name: 'ops_c', builtin: true }];
const g = P.matchItems('group', groups, 'OPS', new Set());
out.groupHtml = P.optionsHtml('group', g, 'pp-list-2');
out.groupKinds = g.map(i => i.kind);
out.excluded = P.matchItems('person', users, '', P.excludedSet(['BOB'], '', 0, false)).map(i => i.value);
const text = 'alice\nca\ncarol';
const ex = P.excludedSet(() => ['bob'], text, 7, true); // the caret on "ca"
out.lines = [...ex].sort();
out.multi = P.matchItems('person', users, 'ca', ex).map(i => i.value);
out.next = [P.nextActive(g, -1, true), P.nextActive(g, 1, true), P.nextActive(g, 2, true), P.nextActive(g, 1, false), P.nextActive([g[0]], -1, true)];
out.max = P.matchItems('person', Array.from({ length: 20 }, (_, i) => 'user' + i), 'user', new Set()).length;
console.log(JSON.stringify(out));
`
	var got struct {
		ByDisplay, ByEmail, GroupKinds, Excluded, Lines, Multi []string
		MalHTML                                                string `json:"malHtml"`
		GroupHTML                                              string `json:"groupHtml"`
		Next                                                   []int
		Max                                                    int
	}
	nodeJSON(t, script, &got)
	if strings.Join(got.ByDisplay, ",") != "alice" || strings.Join(got.ByEmail, ",") != "bob" {
		t.Errorf("matching: display %v, email %v", got.ByDisplay, got.ByEmail)
	}
	for _, raw := range []string{"<img", "<b>", `"lory"`, `x"y`} {
		if strings.Contains(got.MalHTML, raw) {
			t.Errorf("person option not escaped (%s): %s", raw, got.MalHTML)
		}
	}
	for _, want := range []string{"&lt;img src=x onerror=alert(1)&gt;", "Mal &quot;lory&quot; &lt;b&gt;", "x&quot;y@e.org"} {
		if !strings.Contains(got.MalHTML, want) {
			t.Errorf("person option lacks %s: %s", want, got.MalHTML)
		}
	}
	if strings.Contains(got.GroupHTML, "<script>") || strings.Contains(got.GroupHTML, "<x>") ||
		!strings.Contains(got.GroupHTML, "ops&lt;script&gt;") || !strings.Contains(got.GroupHTML, "can&#39;t &quot;grant&quot; &lt;x&gt;") ||
		!strings.Contains(got.GroupHTML, `aria-disabled="true"`) {
		t.Errorf("group options: %s", got.GroupHTML)
	}
	if strings.Join(got.GroupKinds, ",") != "manual,rule-based,built-in" {
		t.Errorf("kinds = %v", got.GroupKinds)
	}
	if strings.Contains(strings.Join(got.Excluded, ","), "bob") || len(got.Excluded) != 3 {
		t.Errorf("exclude BOB = %v", got.Excluded)
	}
	if strings.Join(got.Lines, ",") != "alice,bob,carol" {
		t.Errorf("a textarea's other lines = %v", got.Lines)
	}
	if len(got.Multi) != 0 {
		t.Errorf("ca with alice/carol on other lines = %v, want none (carol is on another line)", got.Multi)
	}
	// g: [refused, ops_b, ops_c]: ↓ from none → 1, 1 → 2, 2 → 1 (wraps past
	// the refused 0), ↑ from 1 → 2; only refused ones: stays.
	if want := []int{1, 2, 1, 2, -1}; len(got.Next) != 5 || got.Next[0] != want[0] || got.Next[1] != want[1] || got.Next[2] != want[2] || got.Next[3] != want[3] || got.Next[4] != want[4] {
		t.Errorf("nextActive = %v, want %v", got.Next, want)
	}
	if got.Max != 8 {
		t.Errorf("at most %d matches, want 8", got.Max)
	}
}

// TestRowGroupErrorJS: settings.js's row group check — empty, unknown
// (typed or stored), another case, refused (another row, privileged).
func TestRowGroupErrorJS(t *testing.T) {
	js := webAsset(t, "settings.js")
	rowList := jsBlock(t, js, "  function rowList(st, key) {", "\n  }\n")
	choices := jsBlock(t, js, "  function groupChoices(st, o, uid) {", "\n  }\n")
	check := jsBlock(t, js, "  function rowGroupError(st, o, uid, v, stored) {", "\n  }\n")
	script := rowList + choices + check + `
const st = { panel: { directory_groups: ['it_staff', 'Office_Milan', 'ops'] }, person: { size: { rows: [{ uid: 'a', group: 'it_staff' }, { uid: 'b', group: '' }] } }, groups: {} };
const o = { key: 'size' };
const p = { key: 'role', privileged: true, group_choices: [{ name: 'ops' }, { name: 'office_milan', disabled: true, reason: 'members can change it' }] };
st.person.role = { rows: [{ uid: 'c', group: '' }] };
const e = (oo, uid, v, stored) => rowGroupError(st, oo, uid, v, stored);
console.log(JSON.stringify([
  e(o, 'b', ''), e(o, 'b', 'ghost'), e(o, 'b', 'ghost', true), e(o, 'b', 'office_milan'), e(o, 'b', 'IT_STAFF'), e(o, 'a', 'it_staff'),
  e(p, 'c', 'ops'), e(p, 'c', 'Office_Milan'), e(p, 'c', 'it_staff'),
]));
`
	var got []*string
	nodeJSON(t, script, &got)
	str := func(i int) string {
		if got[i] == nil {
			return "<nil>"
		}
		return *got[i]
	}
	if len(got) != 9 {
		t.Fatalf("got %v", got)
	}
	for i, want := range []string{
		"choose a group",
		"no group of that name in the directory",
		"group ghost is no longer in the directory: choose another or remove the row",
		"<nil>", // another case: the directory's group
		"already has a row",
		"<nil>", // its own row's group
		"<nil>",
		"can't grant a privileged value: members can change it",
		"not one of the groups that can get this value",
	} {
		if str(i) != want {
			t.Errorf("case %d = %q, want %q", i, str(i), want)
		}
	}
}

// TestAddToGroupPickJS: Add to group… takes a candidate in any case and
// refuses anything else with the reason.
func TestAddToGroupPickJS(t *testing.T) {
	js := webAsset(t, "directory.js")
	fn := jsBlock(t, js, "  function addToGroupPick(cands, typed, user) {", "\n  }\n")
	script := fn + `
const c = [{ name: 'it_staff' }, { name: 'Office' }];
console.log(JSON.stringify([addToGroupPick(c, '  IT_STAFF ', 'carol'), addToGroupPick(c, 'office', 'carol'), addToGroupPick(c, 'lldap_admin', 'carol'), addToGroupPick(c, '  ', 'carol'), addToGroupPick([], 'x', 'admin')]));
`
	var got []map[string]string
	nodeJSON(t, script, &got)
	if len(got) != 5 || got[0]["group"] != "it_staff" || got[1]["group"] != "Office" ||
		got[2]["error"] != "lldap_admin isn't a group carol can be added to" || len(got[3]) != 0 || got[4]["error"] != "x isn't a group admin can be added to" {
		t.Errorf("picks = %v", got)
	}
}

// TestOnHashPersonJS: a #people/<name> hash change routes without
// throwing (onHash once reassigned a const there).
func TestOnHashPersonJS(t *testing.T) {
	js := webAsset(t, "directory.js")
	fn := jsBlock(t, js, "  function onHash() {", "\n  }\n")
	script := `
let root = {}, personPage = null, groupPage = null, tab = 'people', dir = {}, applied = [];
const extraTabs = [], BUILTIN_TABS = ['people', 'groups', 'org', 'setup'];
global.location = { hash: '#people/Carol' };
const legacyUser = () => null, setHash = () => {}, openAt = () => {}, clearRoutes = () => {}, selectTab = () => {};
const parseRoute = h => { const m = /^#people\/(.+)$/.exec(h); return m ? { person: m[1] } : null; };
const canonPerson = n => n.toLowerCase();
const applyRoute = r => applied.push(r);
` + fn + `
let err = null;
try { onHash(); } catch (e) { err = String(e); }
console.log(JSON.stringify({ err, applied }));
`
	var got struct {
		Err     *string
		Applied []map[string]string
	}
	nodeJSON(t, script, &got)
	if got.Err != nil || len(got.Applied) != 1 || got.Applied[0]["person"] != "carol" {
		t.Errorf("onHash #people/Carol: err %v, applied %v", got.Err, got.Applied)
	}
}
