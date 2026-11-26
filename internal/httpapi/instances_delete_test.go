package httpapi

import (
	"strings"
	"testing"
)

// TestDeleteWithoutBackupRoute (user ruling 2026-11-26, contract §11.4):
// DELETE /api/instances/{id} with "backup": false deletes without an
// archive (result no_backup, audit backup=none no_backup=true); the
// field must be a boolean and the typed id is still required; "backup":
// true is the default (a backup is taken); a forget refuses the field.
func TestDeleteWithoutBackupRoute(t *testing.T) {
	e := newInstEnv(t)
	e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-team-a","label":"Test"}`)
	e.engine.addVolume("portcullis_grafana-team-a-grafana-data", "portcullis-grafana-team-a", "grafana-data", map[string]string{"grafana.db": "rows"})
	for _, body := range []string{`{"confirm":"grafana","backup":false}`, `{"backup":false}`, `{"confirm":"grafana-team-a","backup":"false"}`,
		`{"confirm":"grafana-team-a","backup":0}`, `{"confirm":"grafana-team-a","no_backup":true}`} {
		if code, b := e.do(t, "root", "DELETE", "/api/instances/grafana-team-a", body); code != 400 {
			t.Errorf("%s = %d %s, want 400", body, code, b)
		}
	}
	if code, b := e.do(t, "root", "DELETE", "/api/instances/grafana-team-a?forget=1", `{"confirm":"grafana-team-a","backup":false}`); code != 400 || !strings.Contains(b, "forget never takes a backup") {
		t.Errorf("forget + backup = %d %s", code, b)
	}
	if _, ok := e.s.Hub.InstanceView("grafana-team-a"); !ok {
		t.Fatal("a refused delete removed the instance")
	}
	rec := e.runOp(t, "DELETE", "/api/instances/grafana-team-a", `{"confirm":"grafana-team-a","backup":false}`)
	if !rec.OK || rec.Op != "delete" || rec.Result["backup"] != "" || rec.Result["no_backup"] != "true" {
		t.Fatalf("delete op = %+v", rec)
	}
	if list, _ := e.s.Hub.ListBackups(""); len(list) != 0 {
		t.Errorf("a no-backup delete wrote an archive: %+v", list)
	}
	if _, ok := e.s.Hub.InstanceView("grafana-team-a"); ok {
		t.Error("instance still listed")
	}
	var detail string
	for _, a := range readAudit(t, e.audit) {
		if a.Action == "instance.delete" && a.Result == "ok" {
			detail = a.Detail
		}
	}
	if !strings.HasPrefix(detail, "backup=none no_backup=true") {
		t.Errorf("audit detail = %q", detail)
	}

	// "backup": true is the default: an archive is written.
	e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-team-b","label":"Test"}`)
	rec = e.runOp(t, "DELETE", "/api/instances/grafana-team-b", `{"confirm":"grafana-team-b","backup":true}`)
	if !rec.OK || !strings.HasPrefix(rec.Result["backup"], "grafana-team-b/") || rec.Result["no_backup"] != "" {
		t.Fatalf("delete op = %+v", rec)
	}
}

// TestDeleteBackupRoute (user ruling 2026-11-26, contract §11.5): DELETE
// /api/backups/{id}/{name} {"confirm": "<id>/<name>"} → 204, the archive
// gone and audited instance.backup_delete; a wrong confirmation, an
// unknown archive and a bad name are refused (400 / 404), nothing
// removed; non-admins get 403 (TestInstanceRoutesAdminOnly) and the
// people listener doesn't have the route.
func TestDeleteBackupRoute(t *testing.T) {
	e := newInstEnv(t)
	e.runOp(t, "POST", "/api/instances", `{"template":"grafana","id":"grafana-team-a","label":"Test"}`)
	e.engine.addVolume("portcullis_grafana-team-a-grafana-data", "portcullis-grafana-team-a", "grafana-data", map[string]string{"grafana.db": "v1"})
	rec := e.runOp(t, "POST", "/api/instances/grafana-team-a/backups", "")
	archive := rec.Result["archive"]
	if !rec.OK || archive == "" {
		t.Fatalf("backup = %+v", rec)
	}
	path := "/api/backups/" + archive
	for _, c := range []struct {
		path, body string
		code       int
	}{
		{path, `{}`, 400},
		{path, `{"confirm":"grafana-team-a"}`, 400},
		{path, `{"confirm":"` + archive + `","x":1}`, 400},
		{path, ``, 400},
		{"/api/backups/grafana-team-a/20990101T000000Z.tar", `{"confirm":"grafana-team-a/20990101T000000Z.tar"}`, 404},
		{"/api/backups/grafana-team-a/state.yaml", `{"confirm":"grafana-team-a/state.yaml"}`, 400},
		{"/api/backups/..%2f..%2fstate.yaml/x.tar", `{"confirm":"../../state.yaml/x.tar"}`, 400},
	} {
		if code, b := e.do(t, "root", "DELETE", c.path, c.body); code != c.code {
			t.Errorf("DELETE %s %s = %d %s, want %d", c.path, c.body, code, b, c.code)
		}
	}
	if resp, _ := doAs(t, e.ppl, "root", "DELETE", path, `{"confirm":"`+archive+`"}`); resp.StatusCode != 404 && resp.StatusCode != 405 {
		t.Errorf("people listener = %d, want 404", resp.StatusCode)
	}
	if list, _ := e.s.Hub.ListBackups(""); len(list) != 1 {
		t.Fatalf("a refused delete removed the archive: %+v", list)
	}
	if code, b := e.do(t, "root", "DELETE", path, `{"confirm":"`+archive+`"}`); code != 204 {
		t.Fatalf("delete = %d %s", code, b)
	}
	if list, _ := e.s.Hub.ListBackups(""); len(list) != 0 {
		t.Errorf("still listed: %+v", list)
	}
	got := strings.Join(e.auditActions(t, "instance.backup_delete"), ",")
	if !strings.HasSuffix(got, "instance.backup_delete:ok:root:grafana-team-a") || !strings.Contains(got, "instance.backup_delete:refused:root:grafana-team-a") {
		t.Errorf("audit = %s", got)
	}
}
