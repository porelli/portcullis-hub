package hub

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// fakeSignInSrc is the inventory's Keycloak and enroll sides.
type fakeSignInSrc struct {
	mu      sync.Mutex
	keys    map[string][]signin.Method
	certs   []invite.CertRecord
	certErr error
	down    bool
	calls   int
}

func (s *fakeSignInSrc) passkeys(ctx context.Context) (map[string][]keycloak.PasskeyCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.down {
		return nil, errors.New("keycloak: connection refused")
	}
	out := map[string][]keycloak.PasskeyCredential{}
	for u, ms := range s.keys {
		out[u] = []keycloak.PasskeyCredential{}
		for i, m := range ms {
			out[u] = append(out[u], keycloak.PasskeyCredential{ID: u + string(rune('a'+i)), Type: string(m)})
		}
	}
	return out, nil
}

func (s *fakeSignInSrc) certificates(ctx context.Context) ([]invite.CertRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.certErr != nil {
		return nil, s.certErr
	}
	return slices.Clone(s.certs), nil
}

func (s *fakeSignInSrc) set(fn func(s *fakeSignInSrc)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// wireSignIn wires p and src into h, with a clock that moves a minute
// on every reading (no refresh is ever skipped as too recent).
func wireSignIn(h *Hub, p *fakePeople, src *fakeSignInSrc) {
	h.SetPeople(p)
	h.SetSignInSources(SignInSources{Passkeys: src.passkeys, Certificates: src.certificates})
	var mu sync.Mutex
	clock := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	h.signInInv.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(time.Minute)
		return clock
	}
}

func compiledStrong(t *testing.T, on map[signin.Method]bool) signin.Node {
	t.Helper()
	c, err := signin.Compile(siLeaves("any", "security_key", "yubikey_cert"), on)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func allOn() map[signin.Method]bool {
	return map[signin.Method]bool{signin.Password: true, signin.PasskeySynced: true, signin.PasskeyDevice: true, signin.SecurityKey: true, signin.YubiKeyCert: true}
}

func TestBlockedWhy(t *testing.T) {
	on := allOn()
	inv := &Inventory{People: map[string]PersonMethods{
		"alice": {User: "alice", Methods: []signin.Method{signin.SecurityKey}},
		"bob":   {User: "bob", Methods: []signin.Method{signin.Password}},
		"carol": {User: "carol", Methods: []signin.Method{signin.Password, signin.PasskeySynced}},
		"erin":  {User: "erin", Methods: []signin.Method{}},
	}}
	got := blockedFor(inv, []string{"dave", "carol", "bob", "alice", "erin", "Bob"}, compiledStrong(t, on), on)
	want := []Blocked{{"bob", "password only"}, {"carol", "password + synced passkey only"}, {"dave", "no method yet"}, {"erin", "no method yet"}}
	if !slices.Equal(got, want) {
		t.Errorf("blocked = %+v", got)
	}
	// A method that is switched off doesn't meet anything (here the
	// security key, with Strong compiled while it is on).
	off := allOn()
	off[signin.SecurityKey] = false
	if b := blockedFor(inv, []string{"alice"}, compiledStrong(t, on), off); len(b) != 1 || b[0].Why != "security key only" {
		t.Errorf("switched-off method = %+v", b)
	}
	// No inventory: nobody's methods are known, nobody counts.
	if b := blockedFor(nil, []string{"alice"}, compiledStrong(t, on), on); len(b) != 1 || b[0].Why != "no method yet" {
		t.Errorf("nil inventory = %+v", b)
	}
}

func TestCertsUnknownNeverCount(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	p := newFakePeople()
	p.addGroup(lldap.AdminGroup, "ann", "bea")
	src := &fakeSignInSrc{keys: map[string][]signin.Method{"bea": {signin.PasskeySynced, signin.SecurityKey}},
		certs: []invite.CertRecord{
			{User: "ann", Serial: "01", NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
			{User: "bea", Serial: "02", NotAfter: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
			{User: "cid", Serial: "03", NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Revoked: true},
		}}
	wireSignIn(f.h, p, src)
	inv, err := f.h.SignInInventory(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	// Known certificates: only unexpired, unrevoked ones count.
	if a := inv.People["ann"]; !slices.Equal(a.Methods, []signin.Method{signin.YubiKeyCert}) || !a.CertsKnown {
		t.Errorf("ann = %+v", a)
	}
	if b := inv.People["bea"]; !slices.Equal(b.Methods, []signin.Method{signin.PasskeySynced, signin.SecurityKey}) {
		t.Errorf("bea = %+v", b)
	}
	if _, ok := inv.People["cid"]; ok {
		t.Error("a revoked certificate made cid known")
	}
	on := allOn()
	if b := blockedFor(inv, []string{"ann"}, compiledStrong(t, on), on); len(b) != 0 {
		t.Errorf("ann with a certificate = %+v", b)
	}
	v, _ := f.h.SignInView(ctx)
	if n := methodRow(v, signin.YubiKeyCert).People; n != 1 {
		t.Errorf("yubikey_cert people = %d", n)
	}
	// enroll without the route (404), or failing: unknown, never counts.
	for _, cerr := range []error{invite.ErrNoCertAPI, errors.New("enroll: 500")} {
		src.set(func(s *fakeSignInSrc) { s.certErr = cerr })
		inv, err := f.h.SignInInventory(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		if a := inv.People["ann"]; len(a.Methods) != 0 || a.CertsKnown {
			t.Errorf("%v: ann = %+v", cerr, a)
		}
		if b := blockedFor(inv, []string{"ann"}, compiledStrong(t, on), on); len(b) != 1 || b[0] != (Blocked{"ann", "no method yet"}) {
			t.Errorf("%v: a YubiKey-certificate-only admin isn't blocked: %+v", cerr, b)
		}
		v, _ := f.h.SignInView(ctx)
		if n := methodRow(v, signin.YubiKeyCert).People; n != -1 {
			t.Errorf("%v: yubikey_cert people = %d, want -1 (unknown)", cerr, n)
		}
		if n := methodRow(v, signin.SecurityKey).People; n != 1 {
			t.Errorf("%v: security_key people = %d", cerr, n)
		}
		// The policy file: ann (not in Keycloak, certificates unknown) is
		// not known; bea is.
		f.h.mu.RLock()
		pm := f.h.peopleMethodsLocked()
		f.h.mu.RUnlock()
		if ms, ok := pm["ann"]; ok {
			t.Errorf("%v: policy people[ann] = %v", cerr, ms)
		}
		if !slices.Equal(pm["bea"], []signin.Method{signin.PasskeySynced, signin.SecurityKey}) {
			t.Errorf("%v: policy people[bea] = %v", cerr, pm["bea"])
		}
	}
	// Keycloak down: nothing is known.
	src.set(func(s *fakeSignInSrc) { s.down = true })
	if _, err := f.h.SignInInventory(ctx, true); err == nil {
		t.Error("Keycloak down: want an error")
	}
}

func methodRow(v *SignInView, m signin.Method) SignInMethodView {
	for _, r := range v.Methods {
		if r.ID == m {
			return r
		}
	}
	return SignInMethodView{}
}

func TestInventoryRefreshAtMostEvery30s(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	src := &fakeSignInSrc{keys: map[string][]signin.Method{"bea": {signin.SecurityKey}}}
	f.h.SetSignInSources(SignInSources{Passkeys: src.passkeys})
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f.h.signInInv.now = func() time.Time { return now }
	if _, err := f.h.SignInInventory(ctx, true); err != nil {
		t.Fatal(err)
	}
	now = now.Add(29 * time.Second)
	if _, err := f.h.SignInInventory(ctx, true); err != nil || src.calls != 1 {
		t.Errorf("within 30 s: %d calls, %v", src.calls, err)
	}
	if _, err := f.h.SignInInventory(ctx, false); err != nil || src.calls != 1 {
		t.Errorf("cached: %d calls, %v", src.calls, err)
	}
	now = now.Add(2 * time.Second)
	src.set(func(s *fakeSignInSrc) { s.down = true })
	if _, err := f.h.SignInInventory(ctx, true); err == nil || src.calls != 2 {
		t.Errorf("after 30 s: %d calls, %v", src.calls, err)
	}
	// A failed refresh is the answer for 30 s too (no hammering), and
	// the cached inventory stays for the non-fresh readers.
	if _, err := f.h.SignInInventory(ctx, true); err == nil || src.calls != 2 {
		t.Errorf("failed, within 30 s: %d calls, %v", src.calls, err)
	}
	if inv, err := f.h.SignInInventory(ctx, false); err != nil || len(inv.People["bea"].Methods) != 1 {
		t.Errorf("non-fresh after a failure = %+v, %v", inv, err)
	}
}

func TestPasswordRules(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	p := newFakePeople()
	p.addGroup(lldap.AdminGroup, "ann")
	src := &fakeSignInSrc{keys: map[string][]signin.Method{}}
	wireSignIn(f.h, p, src)
	if f.h.PasswordMethodOn() {
		t.Error("password starts off")
	}
	if err := f.h.RecordPassword("Bob", "root"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"admin", "portcullis-hub", "ADMIN"} {
		if err := f.h.RecordPassword(u, "root"); err != nil {
			t.Fatal(err)
		}
	}
	h2 := reopen(t, f)
	h2.mu.RLock()
	rec, ok := h2.st.SignIn.Passwords["bob"]
	_, admin := h2.st.SignIn.Passwords["admin"]
	h2.mu.RUnlock()
	if !ok || rec.SetBy != "root" || rec.SetAt.IsZero() || admin {
		t.Errorf("records = %+v %v, admin %v", rec, ok, admin)
	}
	// A record state.yaml holds for the two accounts never counts.
	f.h.mu.Lock()
	f.h.st.SignIn.Passwords["admin"] = state.PasswordRecord{SetBy: "root"}
	f.h.st.SignIn.Passwords["portcullis-hub"] = state.PasswordRecord{SetBy: "root"}
	f.h.mu.Unlock()
	if _, err := f.h.SetMethod(ctx, signin.Password, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	inv, err := f.h.SignInInventory(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if b := inv.People["bob"]; !slices.Equal(b.Methods, []signin.Method{signin.Password}) {
		t.Errorf("bob = %+v", b)
	}
	for _, u := range []string{"admin", "portcullis-hub"} {
		if pm, ok := inv.People[u]; ok {
			t.Errorf("%s has methods %+v", u, pm)
		}
	}
	f.h.mu.RLock()
	pm := f.h.peopleMethodsLocked()
	counts := f.h.methodPeopleLocked()
	f.h.mu.RUnlock()
	if _, ok := pm["admin"]; ok || !slices.Equal(pm["bob"], []signin.Method{signin.Password}) {
		t.Errorf("policy people = %v", pm)
	}
	if counts[signin.Password] != 2 { // bob and the fixture's root
		t.Errorf("password count = %d", counts[signin.Password])
	}
	// The lockout guard: an admin whose only way in is a password the
	// Hub didn't count (admin) is no administrator who can meet Basic.
	p.addGroup(lldap.AdminGroup, "admin")
	f.h.mu.Lock()
	adminCan := len(blockedFor(composeInventory(&invBase{passkeys: map[string][]signin.Method{}, certs: map[string]bool{}}, f.h.st.SignIn.Passwords), []string{"admin"}, signin.Node{Op: "any", Items: []signin.Node{{Leaf: "password"}}}, allOn())) == 0
	f.h.mu.Unlock()
	if adminCan {
		t.Error("admin's password counted")
	}
	// The record is never the password, and a deleted account's record
	// goes with it.
	b, _ := os.ReadFile(filepath.Join(f.data, "state.yaml"))
	if !strings.Contains(string(b), "set_by: root") {
		t.Errorf("state.yaml lacks the record")
	}
	f.h.PersonDeleted(ctx, siAdmin, "bob")
	f.h.mu.RLock()
	_, still := f.h.st.SignIn.Passwords["bob"]
	f.h.mu.RUnlock()
	if still {
		t.Error("a deleted account's password record stayed")
	}
}

func TestInstanceSignInAndPreviewAffected(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	if err := f.h.Enable("grafana"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	p := newFakePeople()
	p.addGroup("users_grafana", "gus", "gil")
	p.addGroup("admin_grafana", "gia")
	p.addGroup(lldap.AdminGroup, "ann")
	p.set(func(p *fakePeople) { p.expired["gil"] = map[string]bool{"users_grafana": true} })
	src := &fakeSignInSrc{keys: map[string][]signin.Method{"gus": {signin.PasskeySynced}, "gia": {}, "ann": {signin.SecurityKey}}}
	wireSignIn(f.h, p, src)

	v, err := f.h.InstanceSignIn(ctx, "grafana")
	if err != nil {
		t.Fatal(err)
	}
	if !v.TakesTemplate || v.Template != "standard" || !v.Inherits || v.Default != "standard" || v.PeopleUnknown != "" {
		t.Errorf("view = %+v", v)
	}
	if !slices.ContainsFunc(v.Choices, func(c TemplateChoice) bool { return c.ID == "strong" }) || slices.ContainsFunc(v.Choices, func(c TemplateChoice) bool { return c.ID == "basic" }) {
		t.Errorf("choices = %+v", v.Choices)
	}
	// gil's membership expired: not listed; gia (admin group) has nothing.
	if want := []Blocked{{"gia", "no method yet"}}; !slices.Equal(v.Blocked, want) {
		t.Errorf("blocked = %+v", v.Blocked)
	}
	if _, err := f.h.InstanceSignIn(ctx, "nope"); statusOf(err) != 404 {
		t.Errorf("unknown = %v", err)
	}

	// A Standard draft needing a security key: grafana's gus and gia and
	// the portal (everyone); the consoles on the default only hold ann,
	// who has one; the Hub and people pages are on Strong.
	pv, err := f.h.PreviewTemplate(ctx, "standard", TemplateInput{Name: "Standard", Rule: siLeaves("any", "security_key")})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range pv.Affected {
		got = append(got, a.Kind+":"+a.Instance)
	}
	if !slices.Equal(got, []string{"core:portal", "instance:grafana"}) {
		t.Errorf("affected = %v", got)
	}
	for _, a := range pv.Affected {
		if a.Instance == "grafana" && !slices.Equal(a.Blocked, []Blocked{{"gia", "no method yet"}, {"gus", "synced passkey only"}}) {
			t.Errorf("grafana blocked = %+v", a.Blocked)
		}
	}
	// A new template affects nobody yet.
	if pv, err := f.h.PreviewTemplate(ctx, "", TemplateInput{Name: "X", Rule: siLeaves("any", "security_key")}); err != nil || len(pv.Affected) != 0 {
		t.Errorf("new draft = %+v, %v", pv, err)
	}
	// Keycloak down: unknown, said so.
	src.set(func(s *fakeSignInSrc) { s.down = true })
	f.h.SetSignInSources(SignInSources{Passkeys: src.passkeys})
	if v, err := f.h.InstanceSignIn(ctx, "grafana"); err != nil || v.PeopleUnknown == "" || len(v.Blocked) != 0 {
		t.Errorf("Keycloak down = %+v, %v", v, err)
	}
}

func TestInventorySyncPublishesPeople(t *testing.T) {
	f, _ := signInFixture(t)
	src := &fakeSignInSrc{keys: map[string][]signin.Method{"bea": {signin.SecurityKey, signin.PasskeySynced}}}
	wireSignIn(f.h, newFakePeople(), src)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.h.runInventorySync(ctx) }()
	defer func() { cancel(); <-done }()
	f.h.TriggerInventoryRefresh()
	want := `"bea": [
      "passkey_synced",
      "security_key"
    ]`
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, _ := os.ReadFile(f.h.policyPath())
		if strings.Contains(string(b), want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("policy file people not published:\n%s", b)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
