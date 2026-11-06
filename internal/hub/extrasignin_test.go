package hub

import (
	"github.com/portcullis/hub/internal/directory"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/state"
)

// TestExtraDomainSignInRendered: on an extra-domain host, the override
// swaps portcullis-auth@docker for portcullis-auth-ext@docker and adds the
// Host()-scoped /oauth2/ router to forward-auth-ext (contract §5); on the
// main domain nothing of it is rendered, and moving back removes it.
func TestExtraDomainSignInRendered(t *testing.T) {
	f := newInstanceFixtureWith(t, nil, nil)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	f.h.SetAudit(&fakeAudit{})

	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "grafana.team-b.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	ov := readFile(t, f.h.overridePath("grafana-b"))
	for _, want := range []string{
		`"traefik.http.routers.grafana-b_grafana.middlewares": "portcullis-auth-ext@docker,portcullis-groups@docker,grafana-b_grafana-headers@docker,security-headers@file"`,
		"\"traefik.http.routers.portcullis-oauth2-grafana-b_grafana.rule\": \"Host(`grafana.team-b.example.org`) && PathPrefix(`/oauth2/`)\"",
		`"traefik.http.routers.portcullis-oauth2-grafana-b_grafana.service": "forward-auth-ext@docker"`,
		`"traefik.http.routers.portcullis-oauth2-grafana-b_grafana.entrypoints": "websecure"`,
		`"traefik.http.routers.portcullis-oauth2-grafana-b_grafana.tls.options": "`,
		`"traefik.http.routers.portcullis-oauth2-grafana-b_grafana.priority": "`,
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("override lacks %s:\n%s", want, ov)
		}
	}
	if strings.Contains(ov, "portcullis-auth@docker") {
		t.Errorf("override still uses portcullis-auth@docker on an extra-domain host:\n%s", ov)
	}
	// grafana-api has no Portcullis sign-in of its own: no sign-in router.
	if strings.Contains(ov, "portcullis-oauth2-grafana-b_grafana-api") {
		t.Errorf("sign-in router for a router without portcullis-auth:\n%s", ov)
	}
	// The sign-in router outranks every router of the instance.
	h := f.h
	h.mu.RLock()
	tmpl := h.findLocked("grafana-b")
	rl, err := h.routeLabelsLocked(tmpl)
	desired, derr := h.desiredRouteLabelsLocked(tmpl)
	hosts := h.signInExtraHostsLocked(tmpl)
	h.mu.RUnlock()
	if err != nil || derr != nil {
		t.Fatal(err, derr)
	}
	prio := rl.signInLabels["traefik.http.routers.portcullis-oauth2-grafana-b_grafana.priority"]
	for name, ri := range rl.routes.Info {
		if bound := len(ri.Rule) + strings.Count(ri.Rule, "${")*253; len(prio) == 0 || atoi(prio) <= bound {
			t.Errorf("sign-in priority %s not above router %s (%d)", prio, name, bound)
		}
	}
	if strings.Join(hosts, ",") != "grafana.team-b.example.org" {
		t.Errorf("sign-in hosts = %v", hosts)
	}
	// Exposure drift covers the sign-in router and the swapped chain.
	if desired["web"]["traefik.http.routers.portcullis-oauth2-grafana-b_grafana.service"] != "forward-auth-ext@docker" ||
		!strings.HasPrefix(desired["web"]["traefik.http.routers.grafana-b_grafana.middlewares"], "portcullis-auth-ext@docker,") {
		t.Errorf("desired exposure labels = %v", desired["web"])
	}
	if !exposureLabel("grafana-b", "traefik.http.routers.portcullis-oauth2-grafana-b_x.rule", false) ||
		exposureLabel("grafana-b", "traefik.http.routers.portcullis-oauth2-grafana-bb_x.rule", false) {
		t.Error("exposureLabel: sign-in router keys")
	}

	// The default instance on the main domain: unchanged.
	h.mu.RLock()
	defOv, err := h.renderOverrideLocked(h.findLocked("grafana"), state.InstanceSettings{})
	h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	if ov := defOv; strings.Contains(ov, "oauth2") || strings.Contains(ov, "auth-ext") {
		t.Errorf("main-domain override renders the extra-domain sign-in:\n%s", ov)
	}

	// Back to the main domain: no sign-in router, portcullis-auth again.
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "grafana-b.example.org"}, directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	ov = readFile(t, f.h.overridePath("grafana-b"))
	if strings.Contains(ov, "oauth2") || strings.Contains(ov, "auth-ext") {
		t.Errorf("override after the move back:\n%s", ov)
	}

	// The default instance moved to the extra domain: its override (no
	// label replacement) adds the same labels on the template's names.
	if err := f.h.SetHosts("grafana", map[string]string{"grafana": "g.team-b.example.org"}, directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	h.mu.RLock()
	defOv, err = h.renderOverrideLocked(h.findLocked("grafana"), state.InstanceSettings{})
	h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"traefik.http.routers.grafana.middlewares: portcullis-auth-ext@docker,portcullis-groups@docker,grafana-headers@docker,security-headers@file",
		"\"traefik.http.routers.portcullis-oauth2-grafana_grafana.rule\": \"Host(`g.team-b.example.org`) && PathPrefix(`/oauth2/`)\"",
		`"traefik.http.routers.portcullis-oauth2-grafana_grafana.service": "forward-auth-ext@docker"`,
	} {
		if !strings.Contains(defOv, want) {
			t.Errorf("default-instance override lacks %s:\n%s", want, defOv)
		}
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
