package httpapi

import (
	"strings"
	"testing"
)

// TestAnyFieldJS: the group page offers "Allow any profile field in this
// group's rule" only where the server sends allow_any_field (app admin
// and privileged-value groups, to admins), with the warning; the history
// words it; the Fields help names app admin groups.
func TestAnyFieldJS(t *testing.T) {
	js := webAsset(t, "directory.js")
	script := nodeEsc + "const enc = encodeURIComponent;\nconst fmtDate = s => s, untilWords = () => '', syncWords = () => '';\n" +
		jsBlock(t, js, "  const ANY_FIELD_LABEL =", ";\n") + jsBlock(t, js, "  const ANY_FIELD_WARN =", ";\n") +
		jsBlock(t, js, "  function anyFieldHtml(g) {", "\n  }\n") + jsBlock(t, js, "  function historyWords(e, group) {", "\n  }\n") + `
console.log(JSON.stringify({
  none: anyFieldHtml({ name: 'hr' }),
  off: anyFieldHtml({ name: 'admin_app', allow_any_field: false }),
  on: anyFieldHtml({ name: 'admin_app', allow_any_field: true }),
  histOn: historyWords({ action: 'group.allow_any_field', target: 'admin_app', detail: 'allow=true' }, 'admin_app'),
  histOff: historyWords({ action: 'group.allow_any_field', target: 'admin_app', detail: 'allow=false (unchanged)' }, 'admin_app'),
}));
`
	var got struct{ None, Off, On, HistOn, HistOff string }
	nodeJSON(t, script, &got)
	const warn = "A person who can edit these fields for others (a delegate with edit details) could then grant this group&#39;s rights."
	if got.None != "" {
		t.Errorf("offered without allow_any_field: %s", got.None)
	}
	for name, h := range map[string]string{"off": got.Off, "on": got.On} {
		if !strings.Contains(h, "Allow any profile field in this group&#39;s rule") || !strings.Contains(h, warn) || !strings.Contains(h, `data-act="any-field"`) {
			t.Errorf("%s: %s", name, h)
		}
	}
	if !strings.Contains(got.Off, `data-allow="true"`) || !strings.Contains(got.On, `data-allow="false"`) {
		t.Errorf("toggle directions: off %s / on %s", got.Off, got.On)
	}
	if !strings.HasPrefix(got.HistOn, "turned on") || !strings.HasPrefix(got.HistOff, "turned off") {
		t.Errorf("history: %q / %q", got.HistOn, got.HistOff)
	}
	if !strings.Contains(js, "app admin groups such as <code>admin_&lt;app&gt;</code>") {
		t.Error("the Fields help doesn't name app admin groups")
	}
}

// TestAnyFieldOffConfirmJS: turning the option off asks first, naming how
// many people the rule added would be removed — every member without an
// active "added by hand" entry, protected accounts left out (what the
// suspended rule's evaluation removes).
func TestAnyFieldOffConfirmJS(t *testing.T) {
	js := webAsset(t, "directory.js")
	script := "const lc = s => String(s == null ? '' : s).toLowerCase();\n" +
		jsBlock(t, js, "  const ANY_FIELD_LABEL =", ";\n") +
		jsBlock(t, js, "  function suspendRemovals(g, isProtected) {", "\n  }\n") + jsBlock(t, js, "  function anyFieldOffText(group, n) {", "\n  }\n") + `
const g = { name: 'admin_app', rule: { text: 'x' }, members: ['bob', 'Carol', 'dave', 'admin', 'erin'],
  exceptions: [{ user: 'dave', include: true }, { user: 'erin', include: true, expired: true }, { user: 'carol', include: false }] };
const gone = suspendRemovals(g, u => u === 'admin');
console.log(JSON.stringify({ gone, text: anyFieldOffText('admin_app', gone.length), one: anyFieldOffText('admin_app', 1), none: suspendRemovals({ members: [] }, () => false) }));
`
	var got struct {
		Gone, None []string
		Text, One  string
	}
	nodeJSON(t, script, &got)
	if strings.Join(got.Gone, ",") != "bob,Carol,erin" || len(got.None) != 0 {
		t.Errorf("removed = %v / %v", got.Gone, got.None)
	}
	if !strings.Contains(got.Text, "Turning this off removes 3 people the rule added from admin_app (people you added by hand stay)") ||
		!strings.Contains(got.One, "removes 1 person the rule added") {
		t.Errorf("texts: %q / %q", got.Text, got.One)
	}
}
