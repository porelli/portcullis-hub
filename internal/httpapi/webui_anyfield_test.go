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
