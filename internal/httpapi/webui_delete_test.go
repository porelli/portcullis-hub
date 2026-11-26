package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// deleteJS runs the instance page's delete and backup helpers in node
// (the served index's functions) and answers expr (JSON).
func deleteJS(t *testing.T, setup, expr string) any {
	t.Helper()
	page := hubIndex(t)
	var src strings.Builder
	src.WriteString(`let instancesCache = [], catalogCache = {grafana: {manifest: {name: "Grafana", instances: "multi"}}}, pageCtx = null;
const PortcullisPeople = { groupLink: g => '<a class="group-link">' + escapeHtml(g) + '</a>' };
`)
	for _, fn := range []string{"escapeHtml", "instName", "appName", "renderInstDelete", "deleteButtonText", "deleteBody", "deletedBackupLine", "deleteBackupPanelHtml"} {
		src.WriteString(hubFunc(t, page, fn))
	}
	var v any
	if err := json.Unmarshal([]byte(runNode(t, src.String()+setup+"\nprocess.stdout.write(JSON.stringify("+expr+"));\n")), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestHubDeleteWithoutBackupUI (user ruling 2026-11-26, §11.4): the
// Delete tab offers "Delete without a backup" as an unchecked checkbox
// with a hidden for-good warning; the body carries backup: false only
// when it is chosen; the button says which; the outcome says no backup
// was taken. A retry of an unfinished delete offers no choice.
func TestHubDeleteWithoutBackupUI(t *testing.T) {
	got := deleteJS(t, `const pane = {innerHTML: ''};
pageCtx = {id: 'grafana', inst: {id: 'grafana', template: 'grafana', state: 'enabled', groups_mode: 'new', access_group: 'users_grafana', admin_group: 'admin_grafana', default: true}};
renderInstDelete(pane);
const first = pane.innerHTML;
pageCtx.inst.state = 'deleting';
renderInstDelete(pane);`,
		`{first, retry: pane.innerHTML,
  on: deleteButtonText('grafana', true), off: deleteButtonText('grafana', false),
  bodyOn: deleteBody('grafana', true), bodyOff: deleteBody('grafana', false),
  lineNo: deletedBackupLine({result: {no_backup: 'true'}}), lineYes: deletedBackupLine({result: {backup: 'grafana/20261126T025030Z.tar'}}),
  esc: deleteButtonText('<b>', true)}`)
	m := got.(map[string]any)
	first := m["first"].(string)
	for _, want := range []string{`<input type="checkbox" data-inst-del-nobackup>`, `data-inst-del-nobackup-warn hidden`, "gone for good", ">Back up and delete grafana</button>", "unless you choose below to delete without one"} {
		if !strings.Contains(first, want) {
			t.Errorf("the delete pane lacks %q:\n%s", want, first)
		}
	}
	if strings.Contains(first, "checked") {
		t.Error("the no-backup checkbox is checked by default")
	}
	if strings.Contains(m["retry"].(string), "data-inst-del-nobackup") {
		t.Error("a retry offers the no-backup choice")
	}
	if m["on"] != "Delete grafana without a backup" || m["off"] != "Back up and delete grafana" || m["esc"] != "Delete &lt;b&gt; without a backup" {
		t.Errorf("button texts = %v / %v / %v", m["on"], m["off"], m["esc"])
	}
	if b, _ := json.Marshal(m["bodyOn"]); string(b) != `{"backup":false,"confirm":"grafana"}` {
		t.Errorf("body with no backup = %s", b)
	}
	if b, _ := json.Marshal(m["bodyOff"]); string(b) != `{"confirm":"grafana"}` {
		t.Errorf("default body = %s", b)
	}
	if !strings.Contains(m["lineNo"].(string), "No backup was taken") || !strings.Contains(m["lineYes"].(string), "grafana/20261126T025030Z.tar") {
		t.Errorf("outcome lines = %v / %v", m["lineNo"], m["lineYes"])
	}
}

// TestHubDeleteBackupUI (§11.5): each backup row has a Delete… button;
// its panel asks before deleting, warns when the instance is gone (the
// only copy), escapes the names, and the route call carries the typed
// confirmation; no inline handlers anywhere.
func TestHubDeleteBackupUI(t *testing.T) {
	got := deleteJS(t, ``, `{gone: deleteBackupPanelHtml('grafana-b/20261126T025030Z.tar', 'grafana-b', false),
  live: deleteBackupPanelHtml('grafana-b/20261126T025030Z.tar', 'grafana-b', true),
  esc: deleteBackupPanelHtml('<x>/y', '<x>', false)}`)
	m := got.(map[string]any)
	gone, live := m["gone"].(string), m["live"].(string)
	for _, want := range []string{`data-bk-go-delete="grafana-b/20261126T025030Z.tar"`, `data-bk-cancel="1"`, "for good", "only copy of its data"} {
		if !strings.Contains(gone, want) {
			t.Errorf("the panel lacks %q:\n%s", want, gone)
		}
	}
	if strings.Contains(live, "only copy") {
		t.Error("an existing instance's backup is called the only copy")
	}
	if strings.Contains(m["esc"].(string), "<x>") {
		t.Errorf("names not escaped: %s", m["esc"])
	}
	page := hubIndex(t)
	loadBackups := hubFunc(t, page, "loadBackups")
	if !strings.Contains(loadBackups, `data-bk-delete="`) || !strings.Contains(loadBackups, ">Delete…</button>") {
		t.Error("the backups table has no Delete… button")
	}
	run := hubFunc(t, page, "runDeleteBackup")
	if !strings.Contains(run, "'/api/backups/' + archive.split('/').map(encodeURIComponent).join('/'), 'DELETE', { confirm: archive }") {
		t.Errorf("runDeleteBackup's call:\n%s", run)
	}
	for _, fn := range []string{"renderInstDelete", "deleteBackupPanelHtml", "loadBackups"} {
		if strings.Contains(hubFunc(t, page, fn), " onclick=") || strings.Contains(hubFunc(t, page, fn), " onchange=") {
			t.Errorf("%s generates inline handlers", fn)
		}
	}
}
