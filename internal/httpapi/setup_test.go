package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A Nextcloud-shaped template: the database is a setup choice selecting
// a compose profile (contract §13.18).
const dbappManifest = `name: DB App
category: storage
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
settings:
  options:
    - key: database
      label: Database
      type: enum
      scope: instance
      options:
        - {value: mysql, label: MySQL}
        - {value: postgres, label: PostgreSQL}
      default: mysql
      setup: true
      fixed_after_start: true
      profiles:
        mysql: [db-mysql]
        postgres: [db-postgres]
    - key: trash_days
      label: Trash days
      type: int
      scope: instance
      default: 30
`

const dbappCompose = "services:\n" +
	"  app:\n    image: example.org/app:1\n    environment:\n      DB_TYPE: ${DATABASE:-mysql}\n      TRASH_DAYS: ${TRASH_DAYS:-30}\n" +
	"    labels:\n      traefik.http.routers.dbapp.rule: Host(`${PORTCULLIS_HOST_DBAPP:-dbapp.portcullis.local}`)\n" +
	"  db-mysql:\n    image: example.org/mariadb:11\n    profiles: [db-mysql]\n" +
	"  db-postgres:\n    image: example.org/postgres:17\n    profiles: [db-postgres]\n"

// TestCreateSetupRouteAndTool: POST /api/instances and create_instance
// take setup (§11.9); a non-setup key is 400 on both; the instance view
// carries setup.locked.
func TestCreateSetupRouteAndTool(t *testing.T) {
	e := newToolEnv(t, map[string][2]string{"dbapp": {dbappManifest, dbappCompose}}, nil)
	stored := func(id string) any {
		p, err := e.s.Hub.SettingsPanel(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		return p.Instance["database"]
	}
	code, b := e.do(t, "root", "POST", "/api/instances", `{"template":"dbapp","id":"dbapp-x","label":"X","setup":{"trash_days":7}}`)
	if code != 400 || !strings.Contains(b, "trash_days is not a setup option") {
		t.Errorf("non-setup key = %d %s", code, b)
	}
	code, b = e.do(t, "root", "POST", "/api/instances", `{"template":"dbapp","id":"dbapp-x","label":"X","setup":{"database":"oracle"}}`)
	if code != 400 || !strings.Contains(b, "database") {
		t.Errorf("bad value = %d %s", code, b)
	}
	code, b = e.do(t, "root", "POST", "/api/instances", `{"template":"dbapp","id":"dbapp-a","label":"A","setup":{"database":"postgres"}}`)
	if code != 202 {
		t.Fatalf("create = %d %s", code, b)
	}
	waitIdle(t, e.s.Hub, "dbapp-a")
	if v := stored("dbapp-a"); v != "postgres" {
		t.Errorf("route: database = %v", v)
	}
	code, b = e.do(t, "root", "GET", "/api/instances", "")
	if code != 200 || !strings.Contains(b, `"setup":{"locked":false}`) {
		t.Errorf("list = %d %s", code, b)
	}

	// The tool: the same body, the same refusal.
	if txt, isErr, _ := e.tool(t, "create_instance", map[string]any{"template": "dbapp", "id": "dbapp-y", "label": "Y", "setup": map[string]any{"trash_days": 7}}); !isErr || !strings.Contains(txt, "400") || !strings.Contains(txt, "trash_days is not a setup option") {
		t.Errorf("tool non-setup key = %q %v", txt, isErr)
	}
	if txt, isErr, _ := e.tool(t, "create_instance", map[string]any{"template": "dbapp", "id": "dbapp-b", "label": "B", "setup": map[string]any{"database": "postgres"}}); isErr {
		t.Fatalf("tool create = %q", txt)
	}
	waitIdle(t, e.s.Hub, "dbapp-b")
	if v := stored("dbapp-b"); v != "postgres" {
		t.Errorf("tool: database = %v", v)
	}
	if v, ok := e.s.Hub.InstanceView("dbapp-b"); !ok || v.Setup.Locked {
		t.Errorf("view = %+v", v)
	}
	// The confirmation's consequences show the choices decoded.
	got := strings.Join(e.s.createConsequences(context.Background(), json.RawMessage(`{"template":"dbapp","id":"dbapp-c","label":"C","setup":{"database":"postgres"}}`)), " ")
	if !strings.Contains(got, "Setup choices: database = postgres.") {
		t.Errorf("consequences = %q", got)
	}
}
