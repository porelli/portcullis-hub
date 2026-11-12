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

	"github.com/portcullis/hub/internal/directory"
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
	// Hooks (run without f.mu): listHook before List answers (with the
	// list snapshot already taken), enrollHook / deleteHook inside the call.
	listHook   func()
	enrollHook func(ctx context.Context) error
	deleteHook func() error
	// DNS plans (DNS hardening): plans by name, main the main domain's;
	// applied every ApplySets call ("<name> <a,b>"), signed every
	// EnableDNSSEC name; refreshes every Plan call with refresh;
	// signErr / planErr answer those calls instead.
	plans     map[string]domains.Plan
	main      domains.Plan
	applied   []string
	signed    []string
	refreshes int
	signErr   error
	planErr   error
}

func newFakeDomainsAPI() *fakeDomainsAPI {
	return &fakeDomainsAPI{list: map[string]domains.Domain{}, plans: map[string]domains.Plan{}}
}

func (f *fakeDomainsAPI) Plan(_ context.Context, name string, refresh bool) (domains.Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return domains.Plan{}, domains.ErrUnreachable
	}
	if f.planErr != nil {
		return domains.Plan{}, f.planErr
	}
	if _, ok := f.list[name]; !ok {
		return domains.Plan{}, &domains.APIError{Status: 404, Message: name + " is not enrolled"}
	}
	if refresh {
		f.refreshes++
	}
	p, ok := f.plans[name]
	if !ok {
		p = domains.Plan{Name: name, CanWrite: true, Items: []domains.PlanItem{}}
	}
	return p, nil
}

func (f *fakeDomainsAPI) MainPlan(_ context.Context, refresh bool) (domains.Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return domains.Plan{}, domains.ErrUnreachable
	}
	if f.planErr != nil {
		return domains.Plan{}, f.planErr
	}
	if refresh {
		f.refreshes++
	}
	return f.main, nil
}

func (f *fakeDomainsAPI) ApplySets(_ context.Context, name string, sets []string) (domains.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.list[name]
	if !ok {
		return domains.Domain{}, &domains.APIError{Status: 404, Message: name + " is not enrolled"}
	}
	f.applied = append(f.applied, name+" "+strings.Join(sets, ","))
	d.State = "records"
	f.list[name] = d
	return d, nil
}

func (f *fakeDomainsAPI) EnableDNSSEC(_ context.Context, name string) (domains.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.list[name]
	if !ok {
		return domains.Domain{}, &domains.APIError{Status: 404, Message: name + " is not enrolled"}
	}
	if f.signErr != nil {
		return domains.Domain{}, f.signErr
	}
	f.signed = append(f.signed, name)
	d.State = "records"
	f.list[name] = d
	return d, nil
}

func (f *fakeDomainsAPI) Available() error { return nil }

func (f *fakeDomainsAPI) List(context.Context) ([]domains.Domain, error) {
	f.mu.Lock()
	if f.down {
		f.mu.Unlock()
		return nil, fmt.Errorf("%w (dial tcp: connection refused)", domains.ErrUnreachable)
	}
	out := []domains.Domain{}
	for _, d := range f.list {
		out = append(out, d)
	}
	hook := f.listHook
	f.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if hook != nil {
		hook()
	}
	return out, nil
}

func (f *fakeDomainsAPI) Enroll(ctx context.Context, name, provider string, creds map[string]string) (domains.Domain, error) {
	if f.enrollHook != nil {
		if err := f.enrollHook(ctx); err != nil {
			return domains.Domain{}, err
		}
	}
	if ctx.Err() != nil {
		return domains.Domain{}, ctx.Err()
	}
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
	if f.deleteHook != nil {
		if err := f.deleteHook(); err != nil {
			return "", err
		}
	}
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
	d, err := f.h.EnrollDomain(ctx, directory.Human("alice"), "Team-B.Example.net.", "cloudflare", creds())
	if err != nil || d.Name != "team-b.example.net" || d.State != "pending" {
		t.Fatalf("enroll = %+v, %v", d, err)
	}
	if e := audit.last(); e.Action != "domain.add" || e.Target != "team-b.example.net" || e.Result != "ok" || e.Detail != "provider cloudflare" || e.Actor != "alice" {
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
		"team-b.example.net":       {409, "already added"},
		"a.team-b.example.net":     {409, "under the added domain"},
		"example.net":              {409, "above the added domain"},
		"grafana.example.org":      {409, "take over the hostname grafana.example.org"},   // a template's default host
		"grafana-x.example.org":    {409, "take over the hostname grafana-x.example.org"}, // an instance's host
		"chat.example.org":         {409, "take over the hostname chat.example.org"},
		"*.example.com":            {400, "not a valid hostname"},
		"https://team-c.example.n": {400, "not a valid hostname"},
	} {
		_, err := f.h.EnrollDomain(ctx, directory.Human("alice"), name, "cloudflare", creds())
		if statusOf(err) != want.status || !strings.Contains(err.Error(), want.why) {
			t.Errorf("enroll %s: %v, want %d %q", name, err, want.status, want.why)
		}
	}
	if len(api.enrolled) != 1 {
		t.Fatalf("refused enrollments reached the service: %v", api.enrolled)
	}
	if e := audit.last(); e.Result != "refused" || e.Action != "domain.add" {
		t.Fatalf("refusal audit %+v", e)
	}
	// Allowed: other names under the main domain, deeper ones too.
	if _, err := f.h.EnrollDomain(ctx, directory.Human("alice"), "lab.team-a.example.org", "cloudflare", creds()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.EnrollDomain(ctx, directory.Human(""), "z.example.net", "cloudflare", creds()); statusOf(err) != 400 {
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
		if _, err := f.h.EnrollDomain(context.Background(), directory.Human("alice"), name, "cloudflare", creds()); statusOf(err) != 409 || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAssignRequiresValidCert(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	ctx := context.Background()
	if _, err := f.h.EnrollDomain(ctx, directory.Human("alice"), "team-b.example.net", "cloudflare", creds()); err != nil {
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
	if _, err := f.h.EnrollDomain(ctx, directory.Human("alice"), "team-z.example.net", "cloudflare", creds()); statusOf(err) != 503 {
		t.Fatalf("enroll while down: %v", err)
	}
	if _, err := f.h.DeleteDomain(ctx, directory.Human("alice"), "team-b.example.net"); statusOf(err) != 503 {
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
	f.h.EnrollDomain(ctx, directory.Human("alice"), "team-b.example.net", "cloudflare", creds())
	api.set("team-b.example.net", true, time.Now().Add(60*24*time.Hour))
	f.h.RefreshDomains(ctx)
	if err := f.h.CreateInstance("grafana", "grafana-b", map[string]string{"grafana": "team-b.example.net"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.h.DeleteDomain(ctx, directory.Human("alice"), "team-b.example.net")
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
	if err := f.h.SetHosts("grafana-b", map[string]string{"grafana": "grafana-b.example.org"}, directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	api.warning = "some DNS records couldn't be removed"
	w, err := f.h.DeleteDomain(ctx, directory.Human("alice"), "team-b.example.net")
	if err != nil || w != api.warning {
		t.Fatalf("delete = %q, %v", w, err)
	}
	if e := audit.last(); e.Result != "ok" || e.Detail != api.warning {
		t.Fatalf("audit %+v", e)
	}
	if doc := readPolicy(t, f); len(doc.ExtraDomains) != 0 {
		t.Fatalf("extra_domains after delete: %v", doc.ExtraDomains)
	}
	if _, err := f.h.DeleteDomain(ctx, directory.Human("alice"), "team-b.example.net"); statusOf(err) != 404 {
		t.Fatalf("delete unknown: %v", err)
	}
}

func TestReplaceDomainToken(t *testing.T) {
	f, api, audit := newDomainsFixture(t)
	ctx := context.Background()
	f.h.EnrollDomain(ctx, directory.Human("alice"), "team-b.example.net", "cloudflare", creds())
	d, err := f.h.ReplaceDomainToken(ctx, directory.Human("alice"), "team-b.example.net", "porkbun", map[string]string{"api_key": secretToken, "secret_api_key": secretToken + "2"})
	if err != nil || d.Provider != "porkbun" {
		t.Fatalf("token = %+v, %v", d, err)
	}
	if e := audit.last(); e.Action != "domain.token" || e.Detail != "provider porkbun" || e.Result != "ok" {
		t.Fatalf("audit %+v", e)
	}
	if _, err := f.h.ReplaceDomainToken(ctx, directory.Human("alice"), "nope.example.net", "cloudflare", creds()); statusOf(err) != 404 {
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
	f.h.EnrollDomain(context.Background(), directory.Human("alice"), "team-b.example.net", "cloudflare", creds())
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

func readyDomain(t *testing.T, f *fixture, api *fakeDomainsAPI, name string) {
	t.Helper()
	if _, err := f.h.EnrollDomain(context.Background(), directory.Human("alice"), name, "cloudflare", creds()); err != nil {
		t.Fatal(err)
	}
	api.set(name, true, time.Now().Add(60*24*time.Hour))
	if _, err := f.h.RefreshDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestDeleteMarksDeleting: while the service deletes, the domain is not
// assignable (no host can slip in between the check and the delete); a
// failed delete makes it assignable again.
func TestDeleteMarksDeleting(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	readyDomain(t, f, api, "team-b.example.net")
	inDelete, release := make(chan struct{}), make(chan error)
	api.deleteHook = func() error { close(inDelete); return <-release }
	done := make(chan error)
	go func() {
		_, err := f.h.DeleteDomain(context.Background(), directory.Human("alice"), "team-b.example.net")
		done <- err
	}()
	<-inDelete
	err := f.h.CreateInstance("grafana", "grafana-d", map[string]string{"grafana": "grafana.team-b.example.net"})
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "deleting") {
		t.Fatalf("host on a domain being deleted: %v", err)
	}
	release <- &domains.APIError{Status: 500, Message: "boom"}
	if err := <-done; statusOf(err) != 502 {
		t.Fatalf("failed delete = %v", err)
	}
	api.deleteHook = nil
	if err := f.h.CreateInstance("grafana", "grafana-d", map[string]string{"grafana": "grafana.team-b.example.net"}); err != nil {
		t.Fatalf("after a failed delete the domain must be assignable again: %v", err)
	}
}

// TestRefreshDropsStaleList: a List that started before an enrollment
// committed can't drop the new domain from the known list.
func TestRefreshDropsStaleList(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	listed, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	api.listHook = func() { once.Do(func() { close(listed); <-release }) }
	done := make(chan struct{})
	go func() { f.h.RefreshDomains(context.Background()); close(done) }()
	<-listed // a background refresh holds the (empty) list
	api.mu.Lock()
	api.listHook = nil
	api.mu.Unlock()
	if _, err := f.h.EnrollDomain(context.Background(), directory.Human("alice"), "team-b.example.net", "cloudflare", creds()); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	if ds := f.h.KnownDomains(); len(ds) != 1 || ds[0].Name != "team-b.example.net" {
		t.Fatalf("a stale refresh dropped the new domain: %v", ds)
	}
}

// TestEnrollRecheckIgnoresOwnEntry: a refresh that lands between the
// service's Enroll and the Hub's commit lists the new name already; the
// re-check must not take that for a conflict (and undo the enrollment).
// The service call isn't cancelled with the request either.
func TestEnrollRecheckIgnoresOwnEntry(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	api.enrollHook = func(context.Context) error {
		cancel() // the client went away
		return nil
	}
	api.listHook = nil
	d, err := f.h.EnrollDomain(ctx, directory.Human("alice"), "team-b.example.net", "cloudflare", creds())
	if err != nil || d.Name != "team-b.example.net" {
		t.Fatalf("enroll with a cancelled request = %+v, %v", d, err)
	}
	// The race itself: the known list already has the name (a refresh
	// after the service's Enroll); the re-check skips it, the first check
	// doesn't.
	f2, api2, _ := newDomainsFixture(t)
	// Simulate: the service already lists the domain and the Hub refreshed.
	api2.list["team-c.example.net"] = domains.Domain{Name: "team-c.example.net", Provider: "cloudflare", State: "pending"}
	f2.h.mu.Lock()
	f2.h.st.Domains = append(f2.h.st.Domains, toKnown([]domains.Domain{api2.list["team-c.example.net"]})...)
	runtime := map[string][]string{}
	err = f2.h.checkEnrollLocked("team-c.example.net", runtime, true)
	f2.h.mu.Unlock()
	if err != nil {
		t.Fatalf("re-check refused the name's own entry: %v", err)
	}
	f2.h.mu.Lock()
	err = f2.h.checkEnrollLocked("team-c.example.net", runtime, false)
	f2.h.mu.Unlock()
	if statusOf(err) != 409 {
		t.Fatalf("first check accepted an enrolled name: %v", err)
	}
}

// TestServiceListValidated: entries breaking the enrollment rules are
// ignored, whatever the service says.
func TestServiceListValidated(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	for _, n := range []string{"auth.example.org", "x.hub.example.org", "example.org", "org.example.org.x", "nest.example.net", "a.nest.example.net", "ok.example.net", "Bad_Name.net"} {
		api.list[n] = domains.Domain{Name: n, State: "ready"}
	}
	if _, err := f.h.RefreshDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range f.h.KnownDomains() {
		got = append(got, d.Name)
	}
	if strings.Join(got, ",") != "ok.example.net,org.example.org.x" {
		t.Fatalf("known = %v", got)
	}
	if doc := readPolicy(t, f); strings.Join(doc.ExtraDomains, ",") != "ok.example.net,org.example.org.x" {
		t.Fatalf("extra_domains = %v", doc.ExtraDomains)
	}
}

func TestUnknownProviderRefused(t *testing.T) {
	f, api, audit := newDomainsFixture(t)
	if _, err := f.h.EnrollDomain(context.Background(), directory.Human("alice"), "team-b.example.net", "evil\nprovider "+secretToken, creds()); statusOf(err) != 400 {
		t.Fatalf("unknown provider: %v", err)
	}
	if len(api.enrolled) != 0 {
		t.Fatal("forwarded")
	}
	if e := audit.last(); e.Detail != "provider (invalid)" {
		t.Fatalf("audit detail %q", e.Detail)
	}
	assertNoSecret(t, f, audit)
}

// TestDeleteNoAnswerStaysDeleting: without an answer the domain stays
// marked deleting (not assignable) until the service's list shows the
// outcome.
func TestDeleteNoAnswerStaysDeleting(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	readyDomain(t, f, api, "team-b.example.net")
	api.deleteHook = func() error { return fmt.Errorf("%w (timeout)", domains.ErrUnreachable) }
	if _, err := f.h.DeleteDomain(context.Background(), directory.Human("alice"), "team-b.example.net"); statusOf(err) != 502 || !strings.Contains(err.Error(), "stays marked deleting") {
		t.Fatalf("delete without answer = %v", err)
	}
	if err := f.h.CreateInstance("grafana", "grafana-e", map[string]string{"grafana": "grafana.team-b.example.net"}); statusOf(err) != 409 {
		t.Fatalf("assignable after an unanswered delete: %v", err)
	}
	// The service did delete it: the next refresh clears the mark and the entry.
	api.mu.Lock()
	delete(api.list, "team-b.example.net")
	api.mu.Unlock()
	if _, err := f.h.RefreshDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.h.mu.RLock()
	marked := f.h.domainsDeleting["team-b.example.net"]
	f.h.mu.RUnlock()
	if marked || len(f.h.KnownDomains()) != 0 {
		t.Fatalf("mark %v, known %v", marked, f.h.KnownDomains())
	}
}

// TestStaleListKeepsDeletingMark: a list fetched before a delete marked the
// domain can't clear the mark (it would be assignable mid-delete).
func TestStaleListKeepsDeletingMark(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	readyDomain(t, f, api, "team-b.example.net")
	saved := api.list["team-b.example.net"]
	api.mu.Lock()
	delete(api.list, "team-b.example.net") // the stale snapshot lacks it
	listed, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	api.listHook = func() { once.Do(func() { close(listed); <-release }) }
	api.mu.Unlock()
	done := make(chan struct{})
	go func() { f.h.RefreshDomains(context.Background()); close(done) }()
	<-listed
	api.mu.Lock()
	api.list["team-b.example.net"] = saved
	api.listHook = nil
	api.mu.Unlock()
	// What DeleteDomain does under its lock.
	f.h.mu.Lock()
	f.h.domainsDeleting = map[string]bool{"team-b.example.net": true}
	f.h.domainsGen++
	f.h.mu.Unlock()
	close(release)
	<-done
	f.h.mu.RLock()
	marked := f.h.domainsDeleting["team-b.example.net"]
	f.h.mu.RUnlock()
	if !marked {
		t.Fatal("a stale list cleared the deleting mark")
	}
	if err := f.h.CreateInstance("grafana", "grafana-s", map[string]string{"grafana": "grafana.team-b.example.net"}); statusOf(err) != 409 {
		t.Fatalf("assignable mid-delete: %v", err)
	}
}

// TestApplyDomainDNSAudited (contract §12.3): apply forwards the sets and
// is audited domain.dns_apply with detail sets=<a,b>; an unknown or empty
// set list is 400 before anything is forwarded (refused); signing is
// audited domain.dnssec_enable and the service's 409 passes through.
func TestApplyDomainDNSAudited(t *testing.T) {
	f, api, audit := newDomainsFixture(t)
	ctx := context.Background()
	readyDomain(t, f, api, "team-b.example.net")
	d, err := f.h.ApplyDomainDNS(ctx, directory.Human("alice"), "Team-B.example.net", []string{"caa", "nomail"})
	if err != nil || d.State != "records" {
		t.Fatalf("apply = %+v, %v", d, err)
	}
	if strings.Join(api.applied, ";") != "team-b.example.net caa,nomail" {
		t.Fatalf("applied %v", api.applied)
	}
	if e := audit.last(); e.Action != "domain.dns_apply" || e.Target != "team-b.example.net" || e.Detail != "sets=caa,nomail" || e.Result != "ok" || e.Actor != "alice" {
		t.Fatalf("audit %+v", e)
	}
	for _, sets := range [][]string{nil, {}, {"mx"}, {"caa", "caa\n"}} {
		if _, err := f.h.ApplyDomainDNS(ctx, directory.Human("alice"), "team-b.example.net", sets); statusOf(err) != 400 {
			t.Errorf("sets %q: %v, want 400", sets, err)
		}
		if e := audit.last(); e.Action != "domain.dns_apply" || e.Result != "refused" {
			t.Errorf("sets %q: audit %+v", sets, e)
		}
	}
	if len(api.applied) != 1 {
		t.Fatalf("refused sets reached the service: %v", api.applied)
	}
	if _, err := f.h.ApplyDomainDNS(ctx, directory.Human("alice"), "other.example.net", []string{"caa"}); statusOf(err) != 404 {
		t.Fatalf("unknown domain: %v", err)
	}
	// DNSSEC.
	if _, err := f.h.EnableDomainDNSSEC(ctx, directory.Human("alice"), "team-b.example.net"); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "domain.dnssec_enable" || e.Target != "team-b.example.net" || e.Result != "ok" {
		t.Fatalf("audit %+v", e)
	}
	api.signErr = &domains.APIError{Status: 409, Message: "porkbun can't sign the zone through its API"}
	_, err = f.h.EnableDomainDNSSEC(ctx, directory.Human("alice"), "team-b.example.net")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "porkbun can't sign the zone through its API") {
		t.Fatalf("can't sign: %v", err)
	}
	if e := audit.last(); e.Action != "domain.dnssec_enable" || e.Result != "refused" {
		t.Fatalf("audit %+v", e)
	}
	// Through the AI without a confirmation: refused (defence in depth;
	// enable_domain_dnssec is D).
	ai := directory.Actor{User: "alice", Via: directory.ViaAI, Client: "portcullis-ai-claude"}
	api.signErr = nil
	if _, err := f.h.EnableDomainDNSSEC(ctx, ai, "team-b.example.net"); statusOf(err) != 409 || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("AI without confirmation: %v", err)
	}
	if len(api.signed) != 1 {
		t.Fatalf("signed %v", api.signed)
	}
	if _, err := f.h.ApplyDomainDNS(ctx, directory.Human(""), "team-b.example.net", []string{"caa"}); statusOf(err) != 400 {
		t.Fatalf("no actor: %v", err)
	}
}

// TestDomainPlanUnknown404: only a known domain's plan is fetched (404
// otherwise, never forwarded); refresh is passed through; the main
// domain's plan has its own call; unreachable is 503.
func TestDomainPlanUnknown404(t *testing.T) {
	f, api, _ := newDomainsFixture(t)
	ctx := context.Background()
	if _, err := f.h.DomainPlan(ctx, "nope.example.net", false); statusOf(err) != 404 {
		t.Fatalf("unknown: %v", err)
	}
	readyDomain(t, f, api, "team-b.example.net")
	api.plans["team-b.example.net"] = domains.Plan{Name: "team-b.example.net", CanWrite: true}
	p, err := f.h.DomainPlan(ctx, "team-b.example.net", true)
	if err != nil || p.Name != "team-b.example.net" || api.refreshes != 1 {
		t.Fatalf("plan = %+v, %v (refreshes %d)", p, err, api.refreshes)
	}
	api.main = domains.Plan{Name: "example.org"}
	if p, err := f.h.MainDNSPlan(ctx, false); err != nil || p.Name != "example.org" || p.CanWrite {
		t.Fatalf("main = %+v, %v", p, err)
	}
	api.setDown(true)
	if _, err := f.h.MainDNSPlan(ctx, false); statusOf(err) != 503 {
		t.Fatalf("down: %v", err)
	}
}

// TestHetznerCloudAccepted: hetzner-cloud is a known provider (enroll and
// token), named in the refusal's list.
func TestHetznerCloudAccepted(t *testing.T) {
	f, api, audit := newDomainsFixture(t)
	ctx := context.Background()
	if _, err := f.h.EnrollDomain(ctx, directory.Human("alice"), "team-b.example.net", "hetzner-cloud", creds()); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Detail != "provider hetzner-cloud" {
		t.Fatalf("audit %+v", e)
	}
	if _, err := f.h.ReplaceDomainToken(ctx, directory.Human("alice"), "team-b.example.net", "hetzner-cloud", creds()); err != nil {
		t.Fatal(err)
	}
	_, err := f.h.EnrollDomain(ctx, directory.Human("alice"), "team-c.example.net", "hetzner-dns", creds())
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "hetzner-cloud") {
		t.Fatalf("unknown provider: %v", err)
	}
	if len(api.enrolled) != 1 {
		t.Fatalf("enrolled %v", api.enrolled)
	}
}
