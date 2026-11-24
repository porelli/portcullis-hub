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

// Bypass badges (contract §11.7 "bypass"):
//
//   - firefox-sync (ENABLED): method custom, no Portcullis sign-in,
//     group_access false with an access group — the whole host is open
//     ("Open to the internet: whole host"), and the portal shows its tile
//     to users_firefox-sync only.
//   - sharecloud (ENABLED): forward-auth with a public exception in "all"
//     mode ("Public paths: /s/… +1") and an ungated /status router.
const harnessSyncManifest = `name: Firefox Sync
category: productivity
icon: "🦊"
description: "Firefox Sync storage (the bypass fixture: an open host)"
ai: {unsupported: "test fixture"}
auth:
  method: custom
  sso: false
  group_access: false
  access_group: users_firefox-sync
  notes: |
    A self-hosted Firefox Sync server; the host is open to the internet, with no Portcullis sign-in, because Firefox can't pass one.

    Only the Mozilla accounts on the allowlist can sync.
`

const harnessSyncCompose = "services:\n  firefox-sync:\n    image: x\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.firefox-sync.rule: Host(`${PORTCULLIS_HOST_FIREFOX_SYNC:-firefox-sync.portcullis.local}`)\n" +
	"      traefik.http.routers.firefox-sync.tls.options: public@file\n" +
	"      traefik.http.routers.firefox-sync.middlewares: rate-limit@file,security-headers@file\n" +
	"      traefik.http.services.firefox-sync.loadbalancer.server.port: \"8000\"\n"

const harnessShareCloudManifest = `name: Share Cloud
category: storage
icon: "📤"
description: "Files with public share links (the bypass fixture: public paths)"
ai: {unsupported: "test fixture"}
auth:
  method: forward-auth
  group_access: true
  access_group: users_sharecloud
  public_access:
    enabled_by_default: true
    description: Share links people send to outside guests
    token_pattern: '^[A-Za-z0-9-]{1,32}$'
    paths:
      - prefix: "/s/{token}"
        description: Share page
      - prefix: /dist
        description: Assets
        supporting: true
`

const harnessShareCloudCompose = "services:\n  cloud:\n    image: nc\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.sharecloud.rule: Host(`${PORTCULLIS_HOST_SHARECLOUD:-sharecloud.portcullis.local}`)\n" +
	"      traefik.http.routers.sharecloud.middlewares: portcullis-auth@docker,portcullis-groups@docker,security-headers@file\n" +
	"      traefik.http.routers.sharecloud-status.rule: Host(`${PORTCULLIS_HOST_SHARECLOUD:-sharecloud.portcullis.local}`) && Path(`/status.php`)\n" +
	"      traefik.http.routers.sharecloud-status.priority: \"100\"\n" +
	"      traefik.http.services.sharecloud.loadbalancer.server.port: \"80\"\n"

// seedBypass enables firefox-sync and sharecloud (public exception in
// "all" mode).
func seedBypass(t *testing.T, e *instEnv) {
	t.Helper()
	h := e.s.Hub
	e.ll.AddGroup("users_firefox-sync", "alice")
	e.ll.AddGroup("users_sharecloud", "alice", "bob")
	all := "all"
	if _, err := h.SaveSettings("sharecloud", hub.SettingsUpdate{PublicMode: &all}, directory.Human("root")); err != nil {
		t.Fatalf("sharecloud public mode: %v", err)
	}
	for _, id := range []string{"firefox-sync", "sharecloud"} {
		if err := h.Enable(id); err != nil {
			t.Fatalf("enabling %s: %v", id, err)
		}
	}
}

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

// The setup form (apps & instances Task 7): a Nextcloud-shaped template
// with a database choice (setup, fixed after the first start, compose
// profiles), a storage quota asked at setup (changeable later) and a
// setting that isn't asked (trash days). Nothing of it is installed: the
// Marketplace offers Install….
const harnessNextcloudManifest = `name: Nextcloud
category: storage
icon: "☁️"
description: "Files and calendars (the setup form fixture: a database choice)"
instances: multi
ai: {unsupported: "test fixture"}
auth:
  method: header-auth
  group_access: true
  access_group: users_nextcloud
  admin_group: admin_nextcloud
settings:
  options:
    - key: database
      label: Database
      type: enum
      options:
        - {value: mysql, label: MySQL / MariaDB}
        - {value: postgres, label: PostgreSQL}
      default: postgres
      setup: true
      fixed_after_start: true
      profiles:
        mysql: [db-mysql]
        postgres: [db-postgres]
    - key: default_quota
      label: Default storage quota
      type: int
      unit: GiB
      min: 1
      default: 10
      setup: true
    - key: trash_days
      label: Trash days
      type: int
      default: 30
`

const harnessNextcloudCompose = "services:\n" +
	"  app:\n    image: nextcloud:31\n    environment:\n      DB_TYPE: ${DATABASE:-postgres}\n      QUOTA_GB: ${DEFAULT_QUOTA:-10}\n      TRASH_DAYS: ${TRASH_DAYS:-30}\n" +
	"    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.nextcloud.rule: Host(`${PORTCULLIS_HOST_NEXTCLOUD:-cloud.portcullis.local}`)\n" +
	"      traefik.http.services.nextcloud.loadbalancer.server.port: \"80\"\n" +
	"  db-mysql:\n    image: mariadb:11.8\n    profiles: [db-mysql]\n" +
	"  db-postgres:\n    image: postgres:17\n    profiles: [db-postgres]\n"
