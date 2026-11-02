package hub

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/state"
)

// fakeDomains is a DomainSource with enrolled domains.
type fakeDomains struct {
	mu   sync.Mutex
	list []Domain
}

func (d *fakeDomains) Domains() []Domain {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Domain{{Name: "example.org", State: DomainReady}}, d.list...)
}

func (d *fakeDomains) set(list ...Domain) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.list = list
}

// fakeAudit records audit entries.
type fakeAudit struct {
	mu      sync.Mutex
	entries []directory.AuditEntry
}

func (a *fakeAudit) Append(e directory.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *fakeAudit) last() directory.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) == 0 {
		return directory.AuditEntry{}
	}
	return a.entries[len(a.entries)-1]
}

func TestDefaultHosts(t *testing.T) {
	f := newInstanceFixture(t, nil)
	for _, c := range []struct {
		tmpl, id, domain string
		want             map[string]string
	}{
		{"grafana", "grafana-team-a", "", map[string]string{"grafana": "grafana-team-a.example.org"}},
		{"grafana", "lab", "", map[string]string{"grafana": "grafana-lab.example.org"}},
		{"grafana", "grafana", "", map[string]string{"grafana": "grafana.example.org"}},
		{"grafana", "grafana-team-b", "Team-B.Example.net.", map[string]string{"grafana": "grafana-team-b.team-b.example.net"}},
		{"chat", "chat-x", "", map[string]string{"chat": "chat-x.example.org"}},
	} {
		if got := f.h.DefaultHosts(c.tmpl, c.id, c.domain); !reflect.DeepEqual(got, c.want) {
			t.Errorf("DefaultHosts(%s, %s, %q) = %v, want %v", c.tmpl, c.id, c.domain, got, c.want)
		}
	}
	if got := f.h.DefaultHosts("nope", "nope-a", ""); got != nil {
		t.Errorf("unknown template: %v", got)
	}
	// Truncation (§11.3): the label stays within 63 characters, a trailing
	// "-" dropped; no room at all = no default.
	sub := strings.Repeat("s", 40)
	if h, ok := defaultHost(sub, "abcdefghijklmnopqrstu-wxyz", "example.org"); !ok || h != sub+"-abcdefghijklmnopqrstu.example.org" {
		t.Errorf("truncated = %s %v", h, ok)
	}
	if _, ok := defaultHost(strings.Repeat("s", 62), "x", "example.org"); ok {
		t.Error("a 62-character subdomain leaves no room for a suffix")
	}
	if _, ok := defaultHost("a", "b", strings.Repeat("d.", 130)+"org"); ok {
		t.Error("a hostname over 253 characters is no default")
	}
}

func TestHostCollisions(t *testing.T) {
	f := newInstanceFixture(t, nil)
	doms := &fakeDomains{}
	f.h.SetDomainSource(doms)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	for _, id := range []string{"grafana-b", "grafana-c"} {
		if err := f.h.CreateInstance("grafana", id, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.h.Enable("grafana-c"); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(f.data, "state.yaml")
	envBefore := readFile(t, f.h.envPath("grafana-c"))
	ovBefore := readFile(t, f.h.overridePath("grafana-c"))
	policyBefore := readFile(t, f.h.policyPath())
	callsBefore := len(f.runner.Calls())

	doms.set(Domain{Name: "team-b.example.org", State: "pending"}, Domain{Name: "team-c.example.net", State: DomainReady})
	for host, want := range map[string]struct {
		status int
		why    string
	}{
		"grafana-b.example.org":          {409, "already used by instance grafana-b"},
		"Grafana-B.Example.org.":         {409, "already used by instance grafana-b"},
		"grafana.example.org":            {409, "already used by instance grafana"},
		"chat.example.org":               {409, "already used by instance chat"},
		"auth.example.org":               {409, "core hostname"},
		"hub.example.org":                {409, "core hostname"},
		"AUTH.example.org.":              {409, "core hostname"},
		"example.org":                    {409, "core hostname"},
		"grafana.not-enrolled.org":       {400, "nor on an enrolled domain"},
		"x.y.example.org":                {400, "deeper names need an enrolled domain"},
		"grafana.team-b.example.org":     {409, "not assignable"},
		"a.b.team-c.example.net":         {400, "certificate covers one label"},
		"grafana-c2.example.org:443":     {400, "not a valid hostname"},
		"https://grafana-c2.example.org": {400, "not a valid hostname"},
		"*.example.org":                  {400, "not a valid hostname"},
		"grafana_c2.example.org":         {400, "not a valid hostname"},
		"":                               {400, "not a valid hostname"},
	} {
		err := f.h.SetHosts("grafana-c", map[string]string{"grafana": host}, "alice")
		if statusOf(err) != want.status || !strings.Contains(err.Error(), want.why) {
			t.Errorf("host %q: %v, want %d %q", host, err, want.status, want.why)
		}
		if e := audit.last(); e.Action != "instance.update" || e.Result != "refused" || e.Actor != "alice" || e.Target != "grafana-c" {
			t.Errorf("host %q: audit %+v", host, e)
		}
	}
	// Other refusals: unknown host router, a missing one, no actor, a
	// legacy template.
	if err := f.h.SetHosts("grafana-c", map[string]string{"grafana": "ok.example.org", "nope": "x.example.org"}, "alice"); statusOf(err) != 400 {
		t.Errorf("unknown host router: %v", err)
	}
	if err := f.h.SetHosts("grafana-c", map[string]string{}, "alice"); statusOf(err) != 400 {
		t.Errorf("no hosts: %v", err)
	}
	if err := f.h.SetHosts("grafana-c", map[string]string{"grafana": "ok.example.org"}, ""); statusOf(err) != 400 {
		t.Errorf("no actor: %v", err)
	}
	if err := f.h.SetHosts("nope", map[string]string{"grafana": "ok.example.org"}, "alice"); statusOf(err) != 404 {
		t.Errorf("unknown instance: %v", err)
	}
	// Refused before anything changes: state, files, policy, Keycloak,
	// compose.
	st, _ := state.Load(statePath)
	if h := st.Instances["grafana-c"].Hosts["grafana"]; h != "grafana-c.example.org" {
		t.Errorf("state host = %s", h)
	}
	if readFile(t, f.h.envPath("grafana-c")) != envBefore || readFile(t, f.h.overridePath("grafana-c")) != ovBefore || readFile(t, f.h.policyPath()) != policyBefore {
		t.Error("a refused change rewrote files")
	}
	if len(f.runner.Calls()) != callsBefore || len(f.idp.hostUpdates)+len(f.idp.callbacks) != 0 {
		t.Errorf("a refused change ran compose %v or Keycloak %v %v", f.runner.Calls()[callsBefore:], f.idp.hostUpdates, f.idp.callbacks)
	}
	if lo := f.h.LastOp("grafana-c"); lo == nil || lo.Op != OpEnable || !lo.OK {
		t.Errorf("a refusal was recorded as an op: %+v", lo)
	}

	// Accepted: normalised spelling; an enrolled, assignable domain (its
	// apex and one label under it) is an extra-domain host.
	for _, c := range [][2]string{
		{"  Dash-C.Example.ORG. ", "dash-c.example.org"},
		{"team-c.example.net", "team-c.example.net"},
		{"g.team-c.example.net", "g.team-c.example.net"},
	} {
		host, want := c[0], c[1]
		if err := f.h.SetHosts("grafana-c", map[string]string{"grafana": host}, "alice"); err != nil {
			t.Fatalf("host %q: %v", host, err)
		}
		v := f.h.Template("grafana-c")
		if v.Hosts["grafana"] != want {
			t.Errorf("host %q stored as %s", host, v.Hosts["grafana"])
		}
		extra := strings.HasSuffix(want, "team-c.example.net")
		if extra != (len(v.ExtraHosts) == 1) || extra != (len(v.Subdomains) == 0) {
			t.Errorf("host %s: extra %v, view extra %v subdomains %v", want, extra, v.ExtraHosts, v.Subdomains)
		}
	}
	// A domain that stops being assignable keeps its hostnames (§12.3),
	// but receives no new ones.
	doms.set(Domain{Name: "team-c.example.net", State: "error"})
	if err := f.h.SetHosts("grafana-c", map[string]string{"grafana": "h.team-c.example.net"}, "alice"); statusOf(err) != 409 {
		t.Errorf("non-assignable domain: %v", err)
	}
	if v := f.h.Template("grafana-c"); v == nil || v.Hosts["grafana"] != "g.team-c.example.net" {
		t.Errorf("existing host on a non-assignable domain lost: %+v", v)
	}
	// Created instances collide with the current hosts too, extra ones
	// included.
	doms.set(Domain{Name: "team-c.example.net", State: DomainReady})
	if err := f.h.CreateInstance("grafana", "grafana-d", map[string]string{"grafana": "G.team-c.example.net"}); statusOf(err) != 409 {
		t.Errorf("create on a taken extra host: %v", err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-d", map[string]string{"grafana": "dash-c.example.org"}); err != nil {
		t.Errorf("an old hostname is free again: %v", err)
	}
}

func TestSetHostsUpdatesKeycloakRedirects(t *testing.T) {
	kc := kctest.New(t)
	idp := keycloak.New(kc.HTTP.URL, "admin", "admin")
	f := newInstanceFixtureWith(t, nil, idp)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	f.h.SetAudit(&fakeAudit{})

	// Core's and other owners' entries that must stay untouched.
	fa := kc.AddClient(keycloak.ForwardAuthClient, nil)
	coreCB := []string{"https://auth.example.org/oauth2/callback", "https://other.team-b.example.org/oauth2/callback"}
	kc.SetClientURIs(fa, coreCB, nil)
	def := kc.AddClient("chat", map[string]string{keycloak.OwnerAttr: "chat"})
	kc.SetClientURIs(def, []string{"https://chat.example.org/cb"}, []string{"https://chat.example.org"})

	for _, id := range []string{"chat-b", "grafana-b"} {
		if err := f.h.CreateInstance(id[:strings.Index(id, "-")], id, nil); err != nil {
			t.Fatal(err)
		}
		if err := f.h.Enable(id); err != nil {
			t.Fatal(err)
		}
	}
	main, admin := kc.ClientByClientID("chat-b"), kc.ClientByClientID("chat-b-chat-admin")
	if main == nil || admin == nil || strings.Join(main.RedirectURIs, ",") != "https://chat-b.example.org/cb" {
		t.Fatalf("clients after enable: %+v %+v", main, admin)
	}
	// An admin-added redirect and origins on the instance's client.
	kc.SetClientURIs(main.ID, []string{"https://chat-b.example.org/cb", "https://chat-b.example.org/extra"},
		[]string{"https://chat-b.example.org", "+", "https://chat-b.example.org:8443"})

	if err := f.h.SetHosts("chat-b", map[string]string{"chat": "talk.team-b.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	main, admin = kc.ClientByClientID("chat-b"), kc.ClientByClientID("chat-b-chat-admin")
	if got := strings.Join(main.RedirectURIs, ","); got != "https://chat-b.example.org/extra,https://talk.team-b.example.org/cb" {
		t.Errorf("chat-b redirects = %s", got)
	}
	if got := strings.Join(main.WebOrigins, ","); got != "https://talk.team-b.example.org,+,https://talk.team-b.example.org:8443" {
		t.Errorf("chat-b web origins = %s", got)
	}
	if got := strings.Join(admin.RedirectURIs, ","); got != "https://talk.team-b.example.org/admin/cb" {
		t.Errorf("chat-b-chat-admin redirects = %s", got)
	}
	if c := kc.ClientByClientID("chat"); strings.Join(c.RedirectURIs, ",") != "https://chat.example.org/cb" || strings.Join(c.WebOrigins, ",") != "https://chat.example.org" {
		t.Errorf("default instance's client touched: %+v", c)
	}
	// chat's routers have no Portcullis sign-in: no callback.
	if got := kc.ClientByClientID(keycloak.ForwardAuthClient).RedirectURIs; !reflect.DeepEqual(got, coreCB) {
		t.Errorf("forward-auth callbacks = %v", got)
	}

	// grafana's router uses portcullis-auth: an extra-domain host gets its
	// callback on portcullis-forward-auth, and loses it when it leaves.
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "grafana.team-b.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	want := append(append([]string{}, coreCB...), "https://grafana.team-b.example.org/oauth2/callback")
	if got := kc.ClientByClientID(keycloak.ForwardAuthClient).RedirectURIs; !reflect.DeepEqual(got, want) {
		t.Errorf("forward-auth callbacks = %v, want %v", got, want)
	}
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "dash.team-b.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	want = append(append([]string{}, coreCB...), "https://dash.team-b.example.org/oauth2/callback")
	if got := kc.ClientByClientID(keycloak.ForwardAuthClient).RedirectURIs; !reflect.DeepEqual(got, want) {
		t.Errorf("forward-auth callbacks after a move = %v, want %v", got, want)
	}
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "grafana-b2.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if got := kc.ClientByClientID(keycloak.ForwardAuthClient).RedirectURIs; !reflect.DeepEqual(got, coreCB) {
		t.Errorf("forward-auth callbacks after leaving the extra domain = %v", got)
	}

	// A Keycloak failure mid-apply (the second client) leaves everything
	// fully old: the first client is moved back, state, env, override and
	// policy unchanged, no restart. The op is recorded.
	envBefore, ovBefore := readFile(t, f.h.envPath("chat-b")), readFile(t, f.h.overridePath("chat-b"))
	policyBefore := readFile(t, f.h.policyPath())
	callsBefore := len(f.runner.Calls())
	beforeMain := kc.ClientByClientID("chat-b")
	kc.SetFailPrefix("PUT /admin/realms/portcullis/clients/" + admin.ID)
	err := f.h.SetHosts("chat-b", map[string]string{"chat": "chat-new.example.org"}, "alice")
	kc.SetFailPrefix("")
	if statusOf(err) != 502 {
		t.Fatalf("Keycloak failure: %v", err)
	}
	if lo := f.h.LastOp("chat-b"); lo == nil || lo.Op != OpHosts || lo.OK {
		t.Errorf("last op = %+v", lo)
	}
	if c := kc.ClientByClientID("chat-b"); !reflect.DeepEqual(c.RedirectURIs, beforeMain.RedirectURIs) || !reflect.DeepEqual(c.WebOrigins, beforeMain.WebOrigins) {
		t.Errorf("first client not moved back: %v %v", c.RedirectURIs, c.WebOrigins)
	}
	if v := f.h.Template("chat-b"); v.Hosts["chat"] != "talk.team-b.example.org" {
		t.Errorf("hosts after a failed change = %v", v.Hosts)
	}
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	if st.Instances["chat-b"].Hosts["chat"] != "talk.team-b.example.org" {
		t.Errorf("state after a failed change = %v", st.Instances["chat-b"].Hosts)
	}
	if readFile(t, f.h.envPath("chat-b")) != envBefore || readFile(t, f.h.overridePath("chat-b")) != ovBefore || readFile(t, f.h.policyPath()) != policyBefore {
		t.Error("a failed change rewrote files")
	}
	if len(f.runner.Calls()) != callsBefore {
		t.Errorf("a failed change ran compose: %v", f.runner.Calls()[callsBefore:])
	}
	// A failing forward-auth update is undone the same way.
	kc.SetFailPrefix("PUT /admin/realms/portcullis/clients/" + fa)
	err = f.h.SetHosts("grafana-b", map[string]string{"grafana": "g.team-b.example.org"}, "alice")
	kc.SetFailPrefix("")
	if statusOf(err) != 502 || f.h.Template("grafana-b").Hosts["grafana"] != "grafana-b2.example.org" {
		t.Errorf("forward-auth failure: %v, hosts %v", err, f.h.Template("grafana-b").Hosts)
	}
	// Retrying converges.
	if err := f.h.SetHosts("chat-b", map[string]string{"chat": "chat-new.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(kc.ClientByClientID("chat-b-chat-admin").RedirectURIs, ","); got != "https://chat-new.example.org/admin/cb" {
		t.Errorf("after retry: %s", got)
	}
	if lo := f.h.LastOp("chat-b"); lo == nil || lo.Op != OpHosts || !lo.OK {
		t.Errorf("last op after retry = %+v", lo)
	}
}

// v2 cloud: public share links (listed tokens) on a multi template.
const v2CloudManifest = `name: Cloud
category: productivity
instances: multi
auth:
  method: forward-auth
  group_access: true
  access_group: users_cloud
  public_access:
    enabled_by_default: true
    description: Public share links
    token_pattern: '^[A-Za-z0-9-]{1,32}$'
    paths:
      - prefix: "/s/{token}"
        description: Share page
urls:
  - label: Files
    url: "https://{{HOST_CLOUD}}"
`

const v2CloudCompose = "services:\n  cloud:\n    image: nc\n    environment:\n" +
	"      OVERWRITEHOST: ${PORTCULLIS_HOST_CLOUD:-cloud.portcullis.local}\n    labels:\n" +
	"      traefik.enable: \"true\"\n" +
	"      traefik.http.routers.cloud.rule: Host(`${PORTCULLIS_HOST_CLOUD:-cloud.portcullis.local}`)\n" +
	"      traefik.http.routers.cloud.middlewares: portcullis-auth@docker,portcullis-groups@docker\n" +
	"      traefik.http.services.cloud.loadbalancer.server.port: \"80\"\n"

func TestSetHostsRewritesPublicShareHosts(t *testing.T) {
	f := newInstanceFixture(t, nil)
	writeFile(t, filepath.Join(f.src, "cloud", "manifest.yaml"), v2CloudManifest)
	writeFile(t, filepath.Join(f.src, "cloud", "compose.yml"), v2CloudCompose)
	f.h.Discover()
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	if err := f.h.CreateInstance("cloud", "cloud-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("cloud-b"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SaveSettings("cloud-b", SettingsUpdate{Values: map[string]string{}, PublicTokens: listp("AbC123")}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	publicRule := func() string {
		f.h.mu.RLock()
		defer f.h.mu.RUnlock()
		labels, err := f.h.desiredRouteLabelsLocked(f.h.findLocked("cloud-b"))
		if err != nil {
			t.Fatal(err)
		}
		return labels["cloud"]["traefik.http.routers."+PublicRouterName("cloud-b")+".rule"]
	}
	if r := publicRule(); !strings.Contains(r, "Host(`cloud-b.example.org`)") || !strings.Contains(r, "/s/AbC123") {
		t.Fatalf("public rule before = %s", r)
	}
	if doc := readPolicy(t, f); len(doc.PublicPaths["cloud-b"].Paths) == 0 {
		t.Fatalf("public_paths before = %v", doc.PublicPaths)
	}
	callsBefore := len(f.runner.Calls())

	if err := f.h.SetHosts("cloud-b", map[string]string{"cloud": "files.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	// The share link keeps its token and moves to the new host; the old
	// host vanishes from the router, policy, portal and env at once.
	if r := publicRule(); !strings.Contains(r, "Host(`files.example.org`)") || !strings.Contains(r, "/s/AbC123") || strings.Contains(r, "cloud-b.example.org") {
		t.Errorf("public rule after = %s", r)
	}
	doc := readPolicy(t, f)
	if _, old := doc.PublicPaths["cloud-b"]; old || len(doc.PublicPaths["files"].Paths) == 0 || doc.Groups["files"] != "users_cloud-b" {
		t.Errorf("policy after: public %v groups %v", doc.PublicPaths, doc.Groups)
	}
	if _, old := doc.Groups["cloud-b"]; old {
		t.Errorf("old host still in groups: %v", doc.Groups)
	}
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	if strings.Join(st.PublicTokens["cloud-b"], ",") != "AbC123" || strings.Join(st.Published["cloud-b"].PublicHosts, ",") != "files.example.org" {
		t.Errorf("state tokens %v snapshot %+v", st.PublicTokens["cloud-b"], st.Published["cloud-b"])
	}
	env := readFile(t, f.h.envPath("cloud-b"))
	if !strings.Contains(env, "\nPORTCULLIS_HOST_CLOUD=files.example.org\n") || strings.Contains(env, "cloud-b.example.org") {
		t.Errorf("env after:\n%s", env)
	}
	portal := readFile(t, filepath.Join(f.data, "portal-apps.json"))
	if !strings.Contains(portal, "https://files.example.org") || strings.Contains(portal, "cloud-b.example.org") {
		t.Errorf("portal after: %s", portal)
	}
	// Restarted (down + up) to apply it.
	calls := strings.Join(f.runner.Calls()[callsBefore:], " ")
	if !strings.Contains(calls, "down:portcullis-cloud-b") || !strings.Contains(calls, "up:portcullis-cloud-b") {
		t.Errorf("compose calls = %s", calls)
	}
	if e := audit.last(); e.Action != "instance.update" || e.Result != "ok" || e.Detail != "hosts cloud: cloud-b.example.org -> files.example.org" {
		t.Errorf("audit = %+v", e)
	}
	// Same hosts again: nothing to do.
	callsBefore = len(f.runner.Calls())
	if err := f.h.SetHosts("cloud-b", map[string]string{"cloud": "FILES.example.org"}, "alice"); err != nil || len(f.runner.Calls()) != callsBefore {
		t.Errorf("no-op change: %v, calls %v", err, f.runner.Calls()[callsBefore:])
	}
}

func TestSetHostsDefaultInstance(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.SetHosts("grafana", map[string]string{"grafana": "dash.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	if e := st.Instances["grafana"]; e.Template != "grafana" || e.Hosts["grafana"] != "dash.example.org" {
		t.Errorf("default instance entry = %+v", e)
	}
	// Back to its default: no entry needed any more.
	if err := f.h.SetHosts("grafana", map[string]string{"grafana": "grafana.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	st, _ = state.Load(filepath.Join(f.data, "state.yaml"))
	if _, ok := st.Instances["grafana"]; ok {
		t.Errorf("default instance entry kept: %+v", st.Instances)
	}
	// A legacy (${PORTCULLIS_DOMAIN}) template's hostnames are fixed.
	g := newFixture(t)
	if err := g.h.SetHosts("grafana", map[string]string{"grafana": "dash.example.org"}, "alice"); statusOf(err) != 409 {
		t.Errorf("legacy template: %v", err)
	}
}

// v2 template whose default subdomain is team-a.
const v2TeamManifest = `name: Team
category: misc
instances: multi
auth:
  method: forward-auth
`

const v2TeamCompose = "services:\n  web:\n    image: x\n    labels:\n" +
	"      traefik.http.routers.team.rule: Host(`${PORTCULLIS_HOST_TEAM:-team-a.portcullis.local}`)\n"

func TestHostRulesWhateverTheClassification(t *testing.T) {
	f := newInstanceFixture(t, nil)
	writeFile(t, filepath.Join(f.src, "team", "manifest.yaml"), v2TeamManifest)
	writeFile(t, filepath.Join(f.src, "team", "compose.yml"), v2TeamCompose)
	f.h.Discover()
	if f.h.Template("team") == nil {
		t.Fatal("team template not loaded")
	}
	doms := &fakeDomains{}
	// team-a.<main> enrolled (allowed by §12.3), and a source that wrongly
	// lists core hosts.
	doms.set(Domain{Name: "team-a.example.org", State: DomainReady}, Domain{Name: "auth.example.org", State: DomainReady},
		Domain{Name: "x.hub.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	if err := f.h.CreateInstance("grafana", "grafana-c", nil); err != nil {
		t.Fatal(err)
	}
	for host, why := range map[string]string{
		"team-a.example.org":  "already used by instance team",
		"auth.example.org":    "core hostname auth.example.org",
		"x.auth.example.org":  "core hostname auth.example.org",
		"x.hub.example.org":   "core hostname hub.example.org",
		"a.x.hub.example.org": "core hostname hub.example.org",
		"people.example.org":  "core hostname people.example.org",
		"Team-A.Example.org.": "already used by instance team",
	} {
		err := f.h.SetHosts("grafana-c", map[string]string{"grafana": host}, "alice")
		if statusOf(err) != 409 || !strings.Contains(err.Error(), why) {
			t.Errorf("host %s: %v, want 409 %q", host, err, why)
		}
		if err := f.h.CreateInstance("grafana", "grafana-z", map[string]string{"grafana": host}); statusOf(err) != 409 {
			t.Errorf("create on %s: %v", host, err)
		}
	}
	// Moved away, the team template's default hostname stays reserved —
	// also for an extra-domain host on the enrolled team-a.<main>.
	if err := f.h.SetHosts("team", map[string]string{"team": "t.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.SetHosts("grafana-c", map[string]string{"grafana": "team-a.example.org"}, "alice"); statusOf(err) != 409 || !strings.Contains(err.Error(), "default hostname of template team") {
		t.Errorf("reserved default on an enrolled apex: %v", err)
	}
	// Other names on the enrolled team-a.<main> are fine (extra hosts).
	if err := f.h.SetHosts("grafana-c", map[string]string{"grafana": "g.team-a.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if v := f.h.Template("grafana-c"); len(v.ExtraHosts) != 1 || len(v.Subdomains) != 0 {
		t.Errorf("view = %v %v", v.ExtraHosts, v.Subdomains)
	}
}

// chatB returns an enabled chat-b (two Keycloak clients) on the fakeIdP.
func chatB(t *testing.T) *fixture {
	t.Helper()
	f := newInstanceFixture(t, nil)
	f.h.SetAudit(&fakeAudit{})
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	return f
}

func onDisk(t *testing.T, f *fixture, id string) string {
	t.Helper()
	st, err := state.Load(filepath.Join(f.data, "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return st.Instances[id].Hosts["chat"]
}

func TestSetHostsFileFailureBeforeCommit(t *testing.T) {
	f := chatB(t)
	envBefore, ovBefore := readFile(t, f.h.envPath("chat-b")), readFile(t, f.h.overridePath("chat-b"))
	policyBefore := readFile(t, f.h.policyPath())
	calls := len(f.runner.Calls())
	envDir := filepath.Dir(f.h.envPath("chat-b"))
	if err := os.Chmod(envDir, 0500); err != nil {
		t.Fatal(err)
	}
	err := f.h.SetHosts("chat-b", map[string]string{"chat": "talk.example.org"}, "alice")
	os.Chmod(envDir, 0755)
	if statusOf(err) != 500 || !strings.Contains(err.Error(), "nothing changed") {
		t.Fatalf("file failure: %v", err)
	}
	// Fully old: Keycloak moved back, state, files, policy untouched.
	if got := strings.Join(f.idp.hostUpdates, " | "); got != "chat-b:https://chat-b.example.org/cb -> https://talk.example.org/cb | "+
		"chat-b-chat-admin:https://chat-b.example.org/admin/cb -> https://talk.example.org/admin/cb | "+
		"chat-b:https://talk.example.org/cb -> https://chat-b.example.org/cb | "+
		"chat-b-chat-admin:https://talk.example.org/admin/cb -> https://chat-b.example.org/admin/cb" {
		t.Errorf("Keycloak calls = %s", got)
	}
	if f.h.Template("chat-b").Hosts["chat"] != "chat-b.example.org" || onDisk(t, f, "chat-b") != "chat-b.example.org" {
		t.Error("state changed")
	}
	if readFile(t, f.h.envPath("chat-b")) != envBefore || readFile(t, f.h.overridePath("chat-b")) != ovBefore || readFile(t, f.h.policyPath()) != policyBefore {
		t.Error("files changed")
	}
	if len(f.runner.Calls()) != calls {
		t.Error("restarted")
	}
}

func TestSetHostsFailuresAfterCommit(t *testing.T) {
	for _, c := range []struct {
		name    string
		breakIt func(f *fixture) (fix func())
		want    string
	}{
		{"state save", func(f *fixture) func() {
			p := filepath.Join(f.data, "state.yaml")
			os.Remove(p)
			os.Mkdir(p, 0755)
			return func() { os.Remove(p) }
		}, "state.yaml"},
		{"policy write", func(f *fixture) func() {
			p := f.h.policyPath()
			os.Remove(p)
			os.Mkdir(p, 0755)
			return func() { os.Remove(p) }
		}, "policy file"},
		{"restart", func(f *fixture) func() {
			f.runner.upErr = errors.New("boom")
			return func() { f.runner.upErr = nil }
		}, "boom"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := chatB(t)
			fix := c.breakIt(f)
			calls := len(f.runner.Calls())
			err := f.h.SetHosts("chat-b", map[string]string{"chat": "talk.example.org"}, "alice")
			var oe *OpError
			if !errors.As(err, &oe) || oe.Record.Op != OpHosts || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v", err)
			}
			// Committed: the new hostnames are in force, Keycloak is not
			// moved back, and every later step still ran.
			if len(f.idp.hostUpdates) != 2 {
				t.Errorf("Keycloak calls = %v", f.idp.hostUpdates)
			}
			if f.h.Template("chat-b").Hosts["chat"] != "talk.example.org" || !strings.Contains(readFile(t, f.h.envPath("chat-b")), "PORTCULLIS_HOST_CHAT=talk.example.org") {
				t.Error("not committed")
			}
			if after := strings.Join(f.runner.Calls()[calls:], " "); !strings.Contains(after, "up:portcullis-chat-b") {
				t.Errorf("not restarted: %s", after)
			}
			if c.name != "policy write" {
				if doc := readPolicy(t, f); doc.Groups["talk"] != "users_chat-b" {
					t.Errorf("policy not written: %v", doc.Groups)
				}
			}
			// The same hostnames again re-apply everything.
			fix()
			calls = len(f.runner.Calls())
			if err := f.h.SetHosts("chat-b", map[string]string{"chat": "talk.example.org"}, "alice"); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if len(f.idp.hostUpdates) != 4 || !strings.Contains(strings.Join(f.runner.Calls()[calls:], " "), "up:portcullis-chat-b") {
				t.Errorf("retry did not re-apply: Keycloak %v compose %v", f.idp.hostUpdates, f.runner.Calls()[calls:])
			}
			if onDisk(t, f, "chat-b") != "talk.example.org" || readPolicy(t, f).Groups["talk"] != "users_chat-b" {
				t.Error("retry did not converge")
			}
			if lo := f.h.LastOp("chat-b"); lo == nil || !lo.OK || lo.Op != OpHosts {
				t.Errorf("last op = %+v", lo)
			}
			// Now it is a no-op again.
			calls = len(f.runner.Calls())
			if err := f.h.SetHosts("chat-b", map[string]string{"chat": "talk.example.org"}, "alice"); err != nil || len(f.runner.Calls()) != calls || len(f.idp.hostUpdates) != 4 {
				t.Errorf("no-op: %v", err)
			}
		})
	}
}

func TestSetHostsLostRaceKeepsOthersCallbacks(t *testing.T) {
	f := newInstanceFixture(t, nil)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	f.h.SetAudit(&fakeAudit{})
	if err := f.h.CreateInstance("grafana", "grafana-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("grafana-b"); err != nil {
		t.Fatal(err)
	}
	// While grafana-b's change is in Keycloak, grafana-x takes the host.
	f.idp.mu.Lock()
	f.idp.onCallbacks = func() {
		if err := f.h.CreateInstance("grafana", "grafana-x", map[string]string{"grafana": "g.team-b.example.org"}); err != nil {
			t.Error(err)
		}
	}
	f.idp.mu.Unlock()
	err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "g.team-b.example.org"}, "alice")
	if statusOf(err) != 409 {
		t.Fatalf("lost race: %v", err)
	}
	// The callback was added, and is not removed: its host is grafana-x's.
	if got := strings.Join(f.idp.callbacks, " | "); got != "+https://g.team-b.example.org/oauth2/callback -" {
		t.Errorf("callbacks = %s", got)
	}
	if f.h.Template("grafana-b").Hosts["grafana"] != "grafana-b.example.org" {
		t.Error("lost race changed hosts")
	}
	if lo := f.h.LastOp("grafana-b"); lo == nil || lo.Op != OpEnable {
		t.Errorf("a refusal was recorded: %+v", lo)
	}
}

func TestSetHostsConcurrentCallbacks(t *testing.T) {
	kc := kctest.New(t)
	idp := keycloak.New(kc.HTTP.URL, "admin", "admin")
	f := newInstanceFixtureWith(t, nil, idp)
	doms := &fakeDomains{}
	doms.set(Domain{Name: "team-b.example.org", State: DomainReady})
	f.h.SetDomainSource(doms)
	fa := kc.AddClient(keycloak.ForwardAuthClient, nil)
	kc.SetClientURIs(fa, []string{"https://auth.example.org/oauth2/callback"}, nil)
	ids := []string{"grafana-b", "grafana-c", "grafana-d", "grafana-e"}
	for i, id := range ids {
		if err := f.h.CreateInstance("grafana", id, nil); err != nil {
			t.Fatal(err)
		}
		f.h.SaveSettings(id, SettingsUpdate{Values: map[string]string{"GRAFANA_PORT": fmt.Sprint(4000 + i)}})
		if err := f.h.Enable(id); err != nil {
			t.Fatal(err)
		}
	}
	f.h.Wait()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if err := f.h.SetHosts(id, map[string]string{"grafana": id + ".team-b.example.org"}, "alice"); err != nil {
				t.Error(err)
			}
		}(id)
	}
	wg.Wait()
	got := map[string]bool{}
	for _, u := range kc.ClientByClientID(keycloak.ForwardAuthClient).RedirectURIs {
		got[u] = true
	}
	for _, id := range ids {
		if !got["https://"+id+".team-b.example.org/oauth2/callback"] {
			t.Errorf("callback of %s lost: %v", id, got)
		}
	}
	if !got["https://auth.example.org/oauth2/callback"] || len(got) != len(ids)+1 {
		t.Errorf("callbacks = %v", got)
	}
}
