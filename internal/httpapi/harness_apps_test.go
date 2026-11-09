//go:build harness

package httpapi

import (
	"fmt"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
)

// The Apps page and the instance page (apps & instances Task 6):
//
//   - guacamole (multi; web, guacd and the one-off job init that web waits
//     for with service_completed_successfully): its default instance
//     "guacamole" (label Office) and the extra instance "guacamole-lab"
//     (label Lab), both enabled — they look alike on Apps. Office's init
//     exited 0 ("running · 3 of 3 · setup job done"), Lab's exited 1
//     ("running · 2 of 3 · setup job failed", drift job_failed).
//     users_guacamole holds 12 people (first names + "+N").
//   - gitea-ops (label Ops): bound to existing groups — users office_milan
//     (rule-based, seedGroupPages), admins lldap_admin (built-in) —, so
//     its Groups tab says "existing group".

const harnessGuacManifest = `name: Guacamole
category: remote access
icon: "🥑"
description: "Remote desktop gateway (the Apps fixture: a one-off setup job)"
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: header-auth
  group_access: true
  access_group: users_guacamole
  admin_group: admin_guacamole
  notes: "Guacamole trusts the Portcullis identity headers; its own login is off."
`

const harnessGuacCompose = "services:\n" +
	"  web:\n    image: guacamole/guacamole:1.6\n    depends_on:\n      init:\n        condition: service_completed_successfully\n      guacd:\n        condition: service_started\n" +
	"    environment:\n      GUAC_LOG_LEVEL: ${GUAC_LOG_LEVEL:-info}\n      GUAC_TOTP: ${GUAC_TOTP:-false}\n" +
	"    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.guacamole.rule: Host(`${PORTCULLIS_HOST_GUACAMOLE:-guac.portcullis.local}`)\n" +
	"      traefik.http.services.guacamole.loadbalancer.server.port: \"8080\"\n" +
	"  guacd:\n    image: guacamole/guacd:1.6\n" +
	"  init:\n    image: guacamole/guacamole:1.6\n    command: [\"/opt/guacamole/bin/initdb.sh\"]\n    restart: \"no\"\n"

// seedApps creates and enables the guacamole instances, their running
// services and job exits, and the bound gitea-ops.
func seedApps(t *testing.T, e *instEnv, eng *harnessEngine) {
	t.Helper()
	h := e.s.Hub
	twelve := []string{"alice", "bob", "carol", "dave", "erin"}
	for i := 1; i <= 7; i++ {
		twelve = append(twelve, fmt.Sprintf("user%02d", i))
	}
	e.ll.AddGroup("users_guacamole", twelve...)
	e.ll.AddGroup("admin_guacamole", "root", "dave")
	eng.runMu.Lock()
	for id, exit := range map[string]int{"guacamole": 0, "guacamole-lab": 1} {
		eng.prog.services[id] = []string{"guacd", "web"}
		eng.jobs[id] = map[string]int{"init": exit}
	}
	eng.runMu.Unlock()
	for _, c := range []hub.CreateRequest{
		{Template: "guacamole", ID: "guacamole", Label: "Office"},
		{Template: "guacamole", ID: "guacamole-lab", Label: "Lab"},
		{Template: "gitea", ID: "gitea-ops", Label: "Ops", Groups: hub.GroupChoice{Mode: hub.GroupsExisting, Users: "office_milan", Admins: "lldap_admin"}},
	} {
		if _, err := h.CreateInstanceAs(c, directory.Human("root")); err != nil {
			t.Fatalf("creating %s: %v", c.ID, err)
		}
	}
	for _, u := range []string{"alice", "user01", "user02"} {
		e.ll.AddMember("users_guacamole-lab", u) // the create made the group
	}
	for _, id := range []string{"guacamole", "guacamole-lab"} {
		if err := h.Enable(id); err != nil {
			t.Fatalf("enabling %s: %v", id, err)
		}
	}
}

// jobContainers: the jobs of a running instance, exited with their code.
// Caller holds runMu.
func (e *harnessEngine) jobContainers(id string) map[string]int {
	if _, up := e.running[id]; !up {
		return nil
	}
	return e.jobs[id]
}
