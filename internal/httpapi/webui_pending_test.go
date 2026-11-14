package httpapi

import (
	"strings"
	"testing"
)

// The group page's Add people form stages picks; nothing is sent until
// Add (directory.js). These run its blocks under node (skipped without
// node; CI has it).

// pendingBlocks are the staged-pick functions of directory.js.
func pendingBlocks(t *testing.T) string {
	t.Helper()
	js := webAsset(t, "directory.js")
	var b strings.Builder
	for _, start := range []string{
		"  function pickCandidates(g) {", "  function addPeopleHtml(g) {", "  function pickAddLabel(n) {", "  function pendingNote(n) {",
		"  function pickChips(g) {", "  function redrawPicks() {", "  function pendingPicks() {", "  function leaveOk(next) {",
		"  function onBeforeUnload(e) {", "  function stampHistory() {", "  function undoMove() {", "  function onHash() {", "  function userSelectTab(name, focus) {",
	} {
		b.WriteString(jsBlock(t, js, start, "\n  }\n"))
	}
	return b.String()
}

const pendingStubs = nodeEsc + `
const lc = s => String(s == null ? '' : s).toLowerCase();
const enc = encodeURIComponent;
const groupHash = name => name ? '#groups/' + enc(name) : '#groups';
const all = [{ username: 'michele' }, { username: 'bob' }, { username: 'admin', protected: true }];
const users = () => all;
let pick = { group: null, users: [], reason: '', until: '' };
let groupPage = null, personPage = null, tab = 'groups', dir = {};
let confirms = [], answer = true, hashes = [], routes = [], tabs = [];
global.confirm = m => { confirms.push(m); return answer; };
global.location = { hash: '' };
let navSeq = 0, curSeq = 0, moves = [];
global.history = { state: null, back() { moves.push('back'); }, forward() { moves.push('forward'); }, replaceState(st) { this.state = st; } };
const setHash = (h, push) => hashes.push(h);
const legacyUser = () => null;
const parseRoute = h => { const m = /^#groups\/(.+)$/.exec(h || ''); return m ? { group: decodeURIComponent(m[1]) } : null; };
const applyRoute = r => routes.push(r);
const canonPerson = n => n;
const BUILTIN_TABS = ['people', 'groups'], extraTabs = [];
const clearRoutes = () => {}, selectTab = t => tabs.push(t), renderGroups = () => {};
// A fake page for redrawPicks: the chips box, the pending note, the Add button.
const els = { '.pd-gp-picks': { innerHTML: '' }, '.pd-gp-pending': { innerHTML: '' },
  '[data-act="pick-submit"]': { textContent: 'Add', cls: new Set(), classList: { toggle(c, on) { on ? els['[data-act="pick-submit"]'].cls.add(c) : els['[data-act="pick-submit"]'].cls.delete(c); } } } };
const root = { querySelector: sel => els[sel] || null };
const groupByName = n => ({ name: n, members: [] });
`

// TestPendingPicksShownJS: a staged person is labelled "Pending — press
// Add", the form says they are not added yet and the Add button counts
// them (highlighted); without picks it is plain "Add".
func TestPendingPicksShownJS(t *testing.T) {
	script := pendingStubs + pendingBlocks(t) + `
const g = { name: 'users_photocraft', members: [] };
const out = {};
out.empty = addPeopleHtml(g);
pick.users = ['michele'];
out.one = addPeopleHtml(g);
pick.users = ['michele', 'bob'];
pick.group = 'users_photocraft';
redrawPicks();
out.chips = els['.pd-gp-picks'].innerHTML;
out.note = els['.pd-gp-pending'].innerHTML;
out.btn = els['[data-act="pick-submit"]'].textContent;
out.attn = els['[data-act="pick-submit"]'].cls.has('pd-attn');
pick.users = [];
redrawPicks();
out.btn0 = els['[data-act="pick-submit"]'].textContent;
out.attn0 = els['[data-act="pick-submit"]'].cls.has('pd-attn');
out.note0 = els['.pd-gp-pending'].innerHTML;
out.labels = [pickAddLabel(0), pickAddLabel(1), pickAddLabel(3)];
console.log(JSON.stringify(out));
`
	var got struct {
		Empty, One, Chips, Note, Btn, Btn0, Note0 string
		Attn, Attn0                               bool
		Labels                                    []string
	}
	nodeJSON(t, script, &got)
	if strings.Contains(got.Empty, "pd-attn") || strings.Contains(got.Empty, "Pending") || !strings.Contains(got.Empty, ">Add</button>") {
		t.Errorf("no picks: %s", got.Empty)
	}
	for _, want := range []string{"Pending — press Add", "not added yet", ">Add 1 person</button>", "pd-attn", "michele"} {
		if !strings.Contains(got.One, want) {
			t.Errorf("one pick lacks %q: %s", want, got.One)
		}
	}
	if strings.Count(got.Chips, "Pending — press Add") != 2 || !strings.Contains(got.Note, "2 people are picked but not added yet") ||
		got.Btn != "Add 2 people" || !got.Attn {
		t.Errorf("two picks: chips %s, note %s, button %q (attn %v)", got.Chips, got.Note, got.Btn, got.Attn)
	}
	if got.Btn0 != "Add" || got.Attn0 || got.Note0 != "" {
		t.Errorf("after removing the picks: button %q (attn %v), note %q", got.Btn0, got.Attn0, got.Note0)
	}
	if strings.Join(got.Labels, "|") != "Add|Add 1 person|Add 3 people" {
		t.Errorf("labels = %v", got.Labels)
	}
}

// TestLeaveWithPendingPicksJS: leaving the group's page with people picked
// but not added asks (in the app: confirm; closing the page: the browser's
// beforeunload warning); No keeps the page and the picks, Yes drops them.
// Without picks, or on another page, nothing asks.
func TestLeaveWithPendingPicksJS(t *testing.T) {
	script := pendingStubs + pendingBlocks(t) + `
const out = {};
const ev = () => ({ prevented: false, returnValue: undefined, preventDefault() { this.prevented = true; } });
// No picks: no warning anywhere.
groupPage = 'users_photocraft'; pick = { group: 'users_photocraft', users: [], reason: '', until: '' };
let e = ev(); onBeforeUnload(e); out.unloadNone = e.prevented;
location.hash = '#people'; onHash(); out.confirmsNone = confirms.length;
// Picks staged on the shown page.
groupPage = 'users_photocraft'; pick.users = ['michele']; routes = []; hashes = [];
e = ev(); const rv = onBeforeUnload(e); out.unload = e.prevented && e.returnValue === '' && rv === '';
// The same page's hash: no question.
location.hash = '#groups/users_photocraft'; onHash(); out.sameAsks = confirms.length;
// No on a new navigation (an entry without a number): back to the group.
answer = false; history.state = null; location.hash = '#groups/other'; onHash();
out.noAsked = confirms.length; out.noMsg = confirms[confirms.length - 1]; out.noMoves = moves.slice(); out.noRoutes = routes.length; out.noPicks = pick.users.slice();
// No on Back (an older entry): forward again; on Forward (a newer one): back.
moves = []; curSeq = 5; history.state = { pdSeq: 2 }; location.hash = '#people'; onHash();
history.state = { pdSeq: 9 }; location.hash = '#people'; onHash();
out.dirMoves = moves.slice(); out.dirHashes = hashes.slice();
const tabsBefore = tabs.length; userSelectTab('people', false); out.tabNo = tabs.length - tabsBefore;
// Yes: leave, picks dropped.
answer = true; location.hash = '#groups/other'; onHash();
out.yesRoutes = routes; out.yesPicks = pick.users.slice();
e = ev(); onBeforeUnload(e); out.unloadAfter = e.prevented;
// Picks of a page not shown (a person page): nothing asks.
groupPage = null; pick = { group: 'users_photocraft', users: ['michele'], reason: '', until: '' };
const before = confirms.length; e = ev(); onBeforeUnload(e);
out.otherPage = e.prevented || confirms.length !== before;
console.log(JSON.stringify(out));
`
	var got struct {
		UnloadNone, Unload, UnloadAfter, OtherPage      bool
		ConfirmsNone, SameAsks, NoAsked, NoRoutes       int
		TabNo                                           int
		NoMsg                                           string
		NoMoves, DirMoves, DirHashes, NoPicks, YesPicks []string
		YesRoutes                                       []map[string]string
	}
	nodeJSON(t, script, &got)
	if got.UnloadNone || got.ConfirmsNone != 0 {
		t.Errorf("no picks: unload warned %v, confirms %d", got.UnloadNone, got.ConfirmsNone)
	}
	if !got.Unload {
		t.Error("closing the page with a pick doesn't warn")
	}
	if got.SameAsks != 0 {
		t.Errorf("the same group's hash asked (%d)", got.SameAsks)
	}
	if got.NoAsked != 1 || !strings.Contains(got.NoMsg, "michele is picked but not added to users_photocraft yet") ||
		strings.Join(got.NoMoves, ",") != "back" || got.NoRoutes != 0 || len(got.NoPicks) != 1 {
		t.Errorf("No: asked %d %q, moves %v, routes %d, picks %v", got.NoAsked, got.NoMsg, got.NoMoves, got.NoRoutes, got.NoPicks)
	}
	// The entry moved to is never rewritten: the move is undone instead.
	if strings.Join(got.DirMoves, ",") != "forward,back" || len(got.DirHashes) != 0 {
		t.Errorf("No after Back / Forward: moves %v, rewritten hashes %v", got.DirMoves, got.DirHashes)
	}
	if got.TabNo != 0 {
		t.Errorf("a tab switch answered No still switched (%d)", got.TabNo)
	}
	if len(got.YesRoutes) != 1 || got.YesRoutes[0]["group"] != "other" || len(got.YesPicks) != 0 || got.UnloadAfter {
		t.Errorf("Yes: routes %v, picks %v, unload after %v", got.YesRoutes, got.YesPicks, got.UnloadAfter)
	}
	if got.OtherPage {
		t.Error("picks of a group page not shown warned")
	}
}
