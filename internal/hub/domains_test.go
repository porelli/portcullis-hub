package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/domains"
)

const secretToken = "cf-SECRET-token-0123456789abcdef"

// fakeDomainsAPI is core's domains service in memory.
type fakeDomainsAPI struct {
	mu       sync.Mutex
	list     map[string]domains.Domain
	down     bool
	enrolled []string // names, in order
	deleted  []string
	creds    []map[string]string // every credentials map received
	warning  string
}

func newFakeDomainsAPI() *fakeDomainsAPI { return &fakeDomainsAPI{list: map[string]domains.Domain{}} }

func (f *fakeDomainsAPI) Available() error { return nil }

func (f *fakeDomainsAPI) List(context.Context) ([]domains.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, fmt.Errorf("%w (dial tcp: connection refused)", domains.ErrUnreachable)
	}
	out := []domains.Domain{}
	for _, d := range f.list {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeDomainsAPI) Enroll(_ context.Context, name, provider string, creds map[string]string) (domains.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return domains.Domain{}, domains.ErrUnreachable
	}
	if _, ok := f.list[name]; ok {
		return domains.Domain{}, &domains.APIError{Status: 409, Message: name + " is already enrolled"}
	}
	f.creds = append(f.creds, creds)
	d := domains.Domain{Name: name, Provider: provider, State: "pending"}
	f.list[name] = d
	f.enrolled = append(f.enrolled, name)
	return d, nil
}

func (f *fakeDomainsAPI) SetToken(_ context.Context, name, provider string, creds map[string]string) (domains.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.list[name]
	if !ok {
		return domains.Domain{}, &domains.APIError{Status: 404, Message: name + " is not enrolled"}
	}
	f.creds = append(f.creds, creds)
	d.Provider, d.State = provider, "pending"
	f.list[name] = d
	return d, nil
}

func (f *fakeDomainsAPI) Delete(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.list[name]; !ok {
		return "", &domains.APIError{Status: 404, Message: name + " is not enrolled"}
	}
	delete(f.list, name)
	f.deleted = append(f.deleted, name)
	return f.warning, nil
}

// ready makes a domain assignable (records OK, certificate valid until).
func (f *fakeDomainsAPI) set(name string, recordsOK bool, notAfter time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.list[name]
	d.Name, d.RecordsOK, d.State = name, recordsOK, "ready"
	if notAfter.IsZero() {
		d.CertNotAfter = nil
	} else {
		d.CertNotAfter = &notAfter
	}
	f.list[name] = d
}

func (f *fakeDomainsAPI) setDown(down bool) {
	f.mu.Lock()
	f.down = down
	f.mu.Unlock()
}

func newDomainsFixture(t *testing.T) (*fixture, *fakeDomainsAPI, *fakeAudit) {
	t.Helper()
	f := newInstanceFixture(t, nil)
	api := newFakeDomainsAPI()
	f.h.SetDomainsAPI(api)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	return f, api, audit
}

func creds() map[string]string { return map[string]string{"api_token": secretToken} }

// assertNoSecret: the token is nowhere the Hub writes or answers.
func assertNoSecret(t *testing.T, f *fixture, audit *fakeAudit, extra ...string) {
	t.Helper()
	filepath.Walk(f.data, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), secretToken) {
				t.Errorf("the DNS token is in %s", p)
			}
		}
		return nil
	})
	b, _ := json.Marshal(audit.entries)
	if strings.Contains(string(b), secretToken) {
		t.Error("the DNS token is in the audit log")
	}
	for _, s := range extra {
		if strings.Contains(s, secretToken) {
			t.Errorf("the DNS token is in %q", s)
		}
	}
}

func TestEnrollDomain(t *testing.T) {
	f, api, audit := newDomainsFixture(t)
	ctx := context.Background()
	d, err := f.h.EnrollDomain(ctx, "alice", "Team-B.Example.net.", "cloudflare", creds())
	if err != nil || d.Name != "team-b.example.net" || d.State != "pending" {
		t.Fatalf("enroll = %+v, %v", d, err)
	}
	if e := audit.last(); e.Action != "domain.enroll" || e.Target != "team-b.example.net" || e.Result != "ok" || e.Detail != "provider cloudflare" || e.Actor != "alice" {
		t.Fatalf("audit %+v", e)
	}
	// Known list in state.yaml (no credentials), extra_domains published.
	if doc := readPolicy(t, f); strings.Join(doc.ExtraDomains, ",") != "team-b.example.net" {
		t.Fatalf("extra_domains %v", doc.ExtraDomains)
	}
	if st := readFile(t, filepath.Join(f.data, "state.yaml")); !strings.Contains(st, "team-b.example.net") || strings.Contains(st, "api_token") {
		t.Fatalf("state.yaml:\n%s", st)
	}
	// Refusals, before anything is forwarded.
	f.h.CreateInstance("grafana", "grafana-x", nil)
	for name, want := range map[string]struct {
		status int
		why    string
	}{
		"example.org":              {400, "main domain"},
		"org":                      {400, "not a valid hostname"},
		"auth.example.org":         {409, "core host"},
		"x.hub.example.org":        {409, "core host"},
		"team-b.example.net":       {409, "already enrolled"},
		"a.team-b.example.net":     {409, "under the enrolled domain"},
		"example.net":              {409, "above the enrolled domain"},
		"grafana.example.org":      {409, "take over the hostname grafana.example.org"},   // a template's default host
		"grafana-x.example.org":    {409, "take over the hostname grafana-x.example.org"}, // an instance's host
		"chat.example.org":         {409, "take over the hostname chat.example.org"},
		"*.example.com":            {400, "not a valid hostname"},
		"https://team-c.example.n": {400, "not a valid hostname"},
	} {
		_, err := f.h.EnrollDomain(ctx, "alice", name, "cloudflare", creds())
		if statusOf(err) != want.status || !strings.Contains(err.Error(), want.why) {
			t.Errorf("enroll %s: %v, want %d %q", name, err, want.status, want.why)
		}
	}
	if len(api.enrolled) != 1 {
		t.Fatalf("refused enrollments reached the service: %v", api.enrolled)
	}
	if e := audit.last(); e.Result != "refused" || e.Action != "domain.enroll" {
		t.Fatalf("refusal audit %+v", e)
	}
	// Allowed: other names under the main domain, deeper ones too.
	if _, err := f.h.EnrollDomain(ctx, "alice", "lab.team-a.example.org", "cloudflare", creds()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.EnrollDomain(ctx, "", "z.example.net", "cloudflare", creds()); statusOf(err) != 400 {
		t.Fatalf("no actor: %v", err)
	}
	assertNoSecret(t, f, audit)
}

// TestEnrollReclassify: a domain that would turn existing hosts into
// extra-domain hosts is refused (team-a.<main> while an instance routes
// x.team-a.<main>, or published snapshots / running projects do).
func TestEnrollReclassify(t *testing.T) {
	f, _, _ := newDomainsFixture(t)
	f.h.mu.Lock()
	f.h.st.Published["ghost"] = f.h.st.Published["ghost"]
	snap := f.h.st.Published["ghost"]
	snap.Hosts = []string{"app.team-q.example.org"}
	f.h.st.Published["ghost"] = snap
	f.h.mu.Unlock()
	f.h.driftMu.Lock()
	f.h.runtimeHosts = map[string][]string{"portcullis-old": {"svc.team-r.example.org"}}
	f.h.driftMu.Unlock()
	for name, why := range map[string]string{"team-q.example.org": "published", "team-r.example.org": "running project"} {
		if _, err := f.h.EnrollDomain(context.Background(), "alice", name, "cloudflare", creds()); statusOf(err) != 409 || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAssignRequiresValidCert(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	ctx := context.Background()
	if _, err := f.h.EnrollDomain(ctx, "alice", "team-b.example.net", "cloudflare", creds()); err != nil {
		t.Fatal(err)
	}
	host := map[string]string{"grafana": "grafana.team-b.example.net"}
	create := func(id string) error { return f.h.CreateInstance("grafana", id, host) }
	// pending: no certificate yet.
	if err := create("grafana-p"); statusOf(err) != 409 || !strings.Contains(err.Error(), "not assignable") {
		t.Fatalf("pending domain: %v", err)
	}
	// records OK but the certificate expired; certificate valid but records not OK.
	api.set("team-b.example.net", true, time.Now().Add(-time.Hour))
	f.h.RefreshDomains(ctx)
	if err := create("grafana-p"); statusOf(err) != 409 {
		t.Fatalf("expired certificate: %v", err)
	}
	api.set("team-b.example.net", false, time.Now().Add(60*24*time.Hour))
	f.h.RefreshDomains(ctx)
	if err := create("grafana-p"); statusOf(err) != 409 {
		t.Fatalf("records not OK: %v", err)
	}
	// Assignable.
	api.set("team-b.example.net", true, time.Now().Add(60*24*time.Hour))
	f.h.RefreshDomains(ctx)
	if err := create("grafana-p"); err != nil {
		t.Fatalf("assignable domain: %v", err)
	}
	// Service down: new assignments 503, the known list keeps feeding
	// extra_domains, existing hosts stay.
	api.setDown(true)
	if _, err := f.h.RefreshDomains(ctx); statusOf(err) != 503 {
		t.Fatalf("refresh while down: %v", err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-q", map[string]string{"grafana": "other.team-b.example.net"}); statusOf(err) != 503 {
		t.Fatalf("new host while down: %v", err)
	}
	if _, err := f.h.EnrollDomain(ctx, "alice", "team-z.example.net", "cloudflare", creds()); statusOf(err) != 503 {
		t.Fatalf("enroll while down: %v", err)
	}
	if _, err := f.h.DeleteDomain(ctx, "alice", "team-b.example.net"); statusOf(err) != 503 {
		t.Fatalf("delete while down: %v", err)
	}
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	if doc := readPolicy(t, f); strings.Join(doc.ExtraDomains, ",") != "team-b.example.net" {
		t.Fatalf("extra_domains while down: %v", doc.ExtraDomains)
	}
	f.h.mu.RLock()
	v := f.h.findLocked("grafana-p")
	f.h.mu.RUnlock()
	if v == nil || v.Hosts["grafana"] != "grafana.team-b.example.net" {
		t.Fatal("existing host lost while the service is down")
	}
	// Main-domain hosts still work.
	if err := f.h.CreateInstance("grafana", "grafana-m", nil); err != nil {
		t.Fatalf("main-domain host while down: %v", err)
	}
}

func TestDeleteRefusedWhileAssigned(t *testing.T) {
	f, api, audit := newDomainsFixture(t)
	ctx := context.Background()
	f.h.EnrollDomain(ctx, "alice", "team-b.example.net", "cloudflare", creds())
	api.set("team-b.example.net", true, time.Now().Add(60*24*time.Hour))
	f.h.RefreshDomains(ctx)
	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "team-b.example.net"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.h.DeleteDomain(ctx, "alice", "team-b.example.net")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "grafana-b") {
		t.Fatalf("delete while assigned: %v", err)
	}
	if len(api.deleted) != 0 {
		t.Fatal("the service was asked to delete an assigned domain")
	}
	if e := audit.last(); e.Action != "domain.delete" || e.Result != "refused" {
		t.Fatalf("audit %+v", e)
	}
	// Moved to the main domain: the delete goes through (warning passed on).
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "grafana-b.example.org"}, "alice"); err != nil {
		t.Fatal(err)
	}
	api.warning = "some DNS records couldn't be removed"
	w, err := f.h.DeleteDomain(ctx, "alice", "team-b.example.net")
	if err != nil || w != api.warning {
		t.Fatalf("delete = %q, %v", w, err)
	}
	if e := audit.last(); e.Result != "ok" || e.Detail != api.warning {
		t.Fatalf("audit %+v", e)
	}
	if doc := readPolicy(t, f); len(doc.ExtraDomains) != 0 {
		t.Fatalf("extra_domains after delete: %v", doc.ExtraDomains)
	}
	if _, err := f.h.DeleteDomain(ctx, "alice", "team-b.example.net"); statusOf(err) != 404 {
		t.Fatalf("delete unknown: %v", err)
	}
}

func TestReplaceDomainToken(t *testing.T) {
	f, api, audit := newDomainsFixture(t)
	ctx := context.Background()
	f.h.EnrollDomain(ctx, "alice", "team-b.example.net", "cloudflare", creds())
	d, err := f.h.ReplaceDomainToken(ctx, "alice", "team-b.example.net", "porkbun", map[string]string{"api_key": secretToken, "secret_api_key": secretToken + "2"})
	if err != nil || d.Provider != "porkbun" {
		t.Fatalf("token = %+v, %v", d, err)
	}
	if e := audit.last(); e.Action != "domain.token" || e.Detail != "provider porkbun" || e.Result != "ok" {
		t.Fatalf("audit %+v", e)
	}
	if _, err := f.h.ReplaceDomainToken(ctx, "alice", "nope.example.net", "cloudflare", creds()); statusOf(err) != 404 {
		t.Fatalf("unknown: %v", err)
	}
	if len(api.creds) != 2 {
		t.Fatalf("credentials forwarded %d times", len(api.creds))
	}
	assertNoSecret(t, f, audit)
}

// TestKnownDomainsSurviveRestart: the known list is in state.yaml, so a
// Hub that starts while the service is down still publishes it.
func TestKnownDomainsSurviveRestart(t *testing.T) {
	f, _, _ := newDomainsFixture(t)
	f.h.EnrollDomain(context.Background(), "alice", "team-b.example.net", "cloudflare", creds())
	h2, err := New(f.h.cfg, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeDomainsAPI()
	api.setDown(true)
	h2.SetDomainsAPI(api)
	h2.Init()
	t.Cleanup(h2.Wait)
	if doc := readPolicy(t, f); strings.Join(doc.ExtraDomains, ",") != "team-b.example.net" {
		t.Fatalf("extra_domains after restart: %v", doc.ExtraDomains)
	}
	if ds := h2.KnownDomains(); len(ds) != 1 || ds[0].Name != "team-b.example.net" {
		t.Fatalf("known %v", ds)
	}
	var se *StatusError
	if _, err := h2.RefreshDomains(context.Background()); !errors.As(err, &se) || se.Status != 503 {
		t.Fatalf("refresh = %v", err)
	}
}
