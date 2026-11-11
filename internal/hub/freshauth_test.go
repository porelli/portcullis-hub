package hub

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// fakeFreshAuth answers every proof with err (nil: alice, now).
type fakeFreshAuth struct {
	err   error
	calls atomic.Int32
}

func (f *fakeFreshAuth) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return &freshauth.Result{User: user, AuthTime: time.Now(), Method: "security_key"}, nil
}

func (f *fakeFreshAuth) Info() freshauth.AuthorizeInfo {
	return freshauth.AuthorizeInfo{AuthorizeURL: "https://auth.example.org/a", ClientID: freshauth.ClientID, RedirectURI: "https://people.example.org/"}
}

var testProof = freshauth.Proof{Code: "the-code", CodeVerifier: "the-verifier", Nonce: "the-nonce"}

// Every fresh-auth failure is a 403 with the generic text; the reason is
// returned for the audit only and never carries the proof.
func TestCheckFreshAuth(t *testing.T) {
	f := newFixture(t)
	// Not configured: refused (fail closed), never a pass.
	if _, reason, err := f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "alice"); statusOf(err) != 403 || err.Error() != freshauth.Message || reason == "" {
		t.Errorf("unconfigured: %v (%q)", err, reason)
	}
	if f.h.FreshAuthInfo() != nil {
		t.Error("Info without a verifier")
	}
	fa := &fakeFreshAuth{}
	f.h.SetFreshAuth(ListenerPeople, fa)
	f.h.freshAuthReady.Store(true) // the client is in place
	if info := f.h.FreshAuthInfo(); info == nil || info.ClientID != freshauth.ClientID {
		t.Errorf("FreshAuthInfo = %+v", info)
	}
	res, _, err := f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "Alice")
	if err != nil || res.User != "alice" {
		t.Fatalf("accepted proof: %+v, %v", res, err)
	}
	for _, e := range []error{&freshauth.Error{Reason: "nonce mismatch"}, errors.New("unexpected: the-code the-verifier the-nonce")} {
		fa.err = e
		_, reason, err := f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "alice")
		if statusOf(err) != 403 || err.Error() != freshauth.Message {
			t.Errorf("%v: answered %d %q", e, statusOf(err), err)
		}
		for _, s := range []string{testProof.Code, testProof.CodeVerifier, testProof.Nonce} {
			if strings.Contains(reason, s) {
				t.Errorf("reason %q carries the proof", reason)
			}
		}
		if reason == "" {
			t.Error("no reason")
		}
	}
}

// methodFreshAuth accepts every proof with pc_fresh method.
type methodFreshAuth struct {
	fakeFreshAuth
	method string
}

func (f *methodFreshAuth) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	return &freshauth.Result{User: user, AuthTime: time.Now(), Method: f.method}, nil
}

// switchFreshAuth accepts every proof with pc_fresh method and runs
// during (if set) inside Verify: a switch or template change during the
// code exchange.
type switchFreshAuth struct {
	fakeFreshAuth
	method string
	during func()
}

func (f *switchFreshAuth) Verify(_ context.Context, p freshauth.Proof, user string) (*freshauth.Result, error) {
	if f.during != nil {
		f.during()
	}
	return &freshauth.Result{User: user, AuthTime: time.Now(), Method: f.method}, nil
}

// passwordOnly is a password-only template (contract §8 "Governing
// template": confirmed by typing the password again).
var passwordOnly = signin.Node{Op: signin.OpAny, Items: []signin.Node{{Leaf: "password"}}}

// setSignIn edits the fixture's sign-in section under mu.
func setSignIn(f *fixture, edit func(si *state.SignIn)) {
	f.h.mu.Lock()
	edit(&f.h.st.SignIn)
	f.h.mu.Unlock()
}

// TestFreshAuthFollowsGoverningTemplate (contract §8 "Governing
// template", the controller rulings): pc_fresh must be the strongest
// switched-on method of an alternative of the governing template's
// compiled rule — Strong only security_key / yubikey_cert, Standard any
// passkey kind or yubikey_cert, a password-only template the password,
// all[security_key, password] the key only; anything else, a switched-off
// method, and a missing, disabled or unmeetable template refuse with the
// one 403, the template named in the reason only.
func TestFreshAuthFollowsGoverningTemplate(t *testing.T) {
	f := newFixture(t)
	f.h.freshAuthReady.Store(true)
	setSignIn(f, func(si *state.SignIn) {
		si.Methods["password"] = true
		si.Templates["pw-only"] = state.SignInTemplate{Name: "Password only", Rule: passwordOnly, Enabled: true}
		si.Templates["key-and-pw"] = state.SignInTemplate{Name: "Key and password", Enabled: true,
			Rule: signin.Node{Op: signin.OpAll, Items: []signin.Node{{Leaf: "security_key"}, {Leaf: "password"}}}}
		si.Core["hub"], si.Core["people"], si.Core["portal"], si.Core["directory"] = "strong", "standard", "pw-only", "key-and-pw"
	})
	if got := strings.Join(f.h.freshAuthAccepted(), ","); got != "password,passkey_synced,passkey_device,security_key,yubikey_cert" {
		t.Errorf("freshAuthAccepted = %s", got)
	}
	for _, c := range []struct {
		core, method string
		ok           bool
	}{
		{"hub", "passkey_synced", false}, {"hub", "passkey_device", false}, {"hub", "password", false},
		{"hub", "security_key", true}, {"hub", "yubikey_cert", true},
		{"people", "passkey_synced", true}, {"people", "passkey_device", true}, {"people", "security_key", true}, {"people", "yubikey_cert", true},
		{"people", "password", false}, {"people", "browser_cert", false}, {"people", "inv", false}, {"people", "", false},
		{"portal", "password", true}, {"portal", "security_key", false}, {"portal", "passkey_synced", false},
		// all[security_key, password]: the strongest of its one
		// alternative — the key; a typed password alone never approves.
		{"directory", "password", false}, {"directory", "security_key", true}, {"directory", "passkey_synced", false},
	} {
		f.h.SetFreshAuth(ListenerPeople, &switchFreshAuth{method: c.method})
		res, reason, err := f.h.checkFreshAuth(context.Background(), govCore(c.core), testProof, "alice")
		if c.ok != (err == nil) {
			t.Errorf("%s + pc_fresh %q: %+v, %q, %v; want ok %v", c.core, c.method, res, reason, err, c.ok)
			continue
		}
		if c.ok {
			want := map[string]string{"hub": "strong", "people": "standard", "portal": "pw-only", "directory": "key-and-pw"}[c.core]
			if res.Template != want || res.Method != c.method || reason != "" {
				t.Errorf("%s + %s: template %q method %q reason %q", c.core, c.method, res.Template, res.Method, reason)
			}
			continue
		}
		if statusOf(err) != 403 || err.Error() != freshauth.Message || !strings.Contains(reason, "template ") {
			t.Errorf("%s + pc_fresh %q: %d %v (%q)", c.core, c.method, statusOf(err), err, reason)
		}
	}
}

// A leaf switched off refuses: dropped from the compiled rule before the
// proof, or switched off (or the template changed) during the exchange.
func TestFreshAuthSwitchedOffLeafRefused(t *testing.T) {
	f := newFixture(t)
	f.h.freshAuthReady.Store(true)
	setSignIn(f, func(si *state.SignIn) { si.Core["people"] = "standard"; si.Methods["passkey_synced"] = false })
	f.h.SetFreshAuth(ListenerPeople, &switchFreshAuth{method: "passkey_synced"})
	if _, reason, err := f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "alice"); statusOf(err) != 403 ||
		reason != "pc_fresh names a method that is switched off (template standard)" {
		t.Errorf("switched off: %v (%q)", err, reason)
	}
	setSignIn(f, func(si *state.SignIn) { si.Methods["passkey_synced"] = true })
	f.h.SetFreshAuth(ListenerPeople, &switchFreshAuth{method: "passkey_synced", during: func() {
		setSignIn(f, func(si *state.SignIn) { si.Methods["passkey_synced"] = false })
	}})
	if _, reason, err := f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "alice"); statusOf(err) != 403 || !strings.Contains(reason, "switched off") {
		t.Errorf("switched off during the exchange: %v (%q)", err, reason)
	}
	setSignIn(f, func(si *state.SignIn) { si.Methods["passkey_synced"] = true })
	f.h.SetFreshAuth(ListenerPeople, &switchFreshAuth{method: "passkey_synced", during: func() {
		setSignIn(f, func(si *state.SignIn) { si.Core["people"] = "strong" })
	}})
	if _, reason, err := f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "alice"); statusOf(err) != 403 ||
		reason != "pc_fresh names a method template strong doesn't accept" {
		t.Errorf("template changed during the exchange: %v (%q)", err, reason)
	}
}

// A missing, disabled or unmeetable governing template, an unknown core
// key, a gone instance and the zero freshGov all refuse — before the code
// is exchanged (the verifier is never called).
func TestFreshAuthMissingTemplateRefused(t *testing.T) {
	f := newFixture(t)
	f.h.freshAuthReady.Store(true)
	fa := &fakeFreshAuth{}
	f.h.SetFreshAuth(ListenerPeople, fa)
	setSignIn(f, func(si *state.SignIn) {
		si.Templates["key-and-pw"] = state.SignInTemplate{Name: "Key and password", Enabled: true,
			Rule: signin.Node{Op: signin.OpAll, Items: []signin.Node{{Leaf: "security_key"}, {Leaf: "password"}}}} // password off: unmeetable
		si.Templates["off"] = state.SignInTemplate{Name: "Off", Rule: passwordOnly}
	})
	for _, c := range []struct {
		name string
		edit func(si *state.SignIn)
		gov  freshGov
	}{
		{"gone", func(si *state.SignIn) { si.Core["people"] = "nope" }, govCore("people")},
		{"disabled", func(si *state.SignIn) { si.Core["people"] = "off" }, govCore("people")},
		{"unmeetable", func(si *state.SignIn) { si.Core["people"] = "key-and-pw" }, govCore("people")},
		{"default gone", func(si *state.SignIn) { si.Core["people"], si.Default = "", "nope" }, govCore("people")},
		{"unknown core key", nil, govCore("auth")},
		{"instance gone", nil, govInstance("nope")},
		{"zero", nil, freshGov{}},
		{"both", nil, freshGov{instance: "x", core: "hub"}},
	} {
		if c.edit != nil {
			setSignIn(f, c.edit)
		}
		before := fa.calls.Load()
		_, reason, err := f.h.checkFreshAuth(context.Background(), c.gov, testProof, "alice")
		if statusOf(err) != 403 || err.Error() != freshauth.Message || !strings.Contains(reason, "governing template") {
			t.Errorf("%s: %d %v (%q)", c.name, statusOf(err), err, reason)
		}
		if fa.calls.Load() != before {
			t.Errorf("%s: the code was exchanged", c.name)
		}
	}
}

// F45: a refused proof is a 4xx, so it counts toward the people
// listener's per-caller refusal limit (shared with value saves): ten in a
// minute and the caller's next save is a 429.
func TestFreshAuthRefusalsCountTowardLimit(t *testing.T) {
	f, _, _, _ := entryFixture(t)
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	f.h.entryNow = func() time.Time { return now }
	f.h.SetFreshAuth(ListenerPeople, &fakeFreshAuth{err: &freshauth.Error{Reason: "stale"}})
	f.h.freshAuthReady.Store(true)
	for i := range entryRefusalLimit {
		if !f.h.entryLimit.reserve("alice", f.h.entryClock()) {
			t.Fatalf("limited after %d refusals", i)
		}
		_, _, err := f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "alice")
		f.h.entryLimit.release("alice", f.h.entryClock(), isRefusal(err))
	}
	if _, err := setEntry(f, entryID, "ext_id", "alice", aliceExt, "alice"); statusOf(err) != 429 {
		t.Errorf("after ten refused proofs = %v, want 429", err)
	}
}

// The directory sync loop ensures the fresh-auth client at start and on
// every sync, next to the attribute mappers; its failure blocks nothing.
func TestRunDirectorySyncEnsuresFreshAuthClient(t *testing.T) {
	f := newFixture(t)
	var syncs, ensures atomic.Int32
	f.h.SetDirectory(dirStateOf(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, nil, nil
	}), func(context.Context) error { syncs.Add(1); return nil })
	f.h.SetFreshAuthClient(func(context.Context) error { ensures.Add(1); return errors.New("keycloak down") })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.h.RunDirectorySync(ctx); close(done) }()
	waitFor := func(n int32) {
		t.Helper()
		for i := 0; i < 500 && (ensures.Load() < n || syncs.Load() < n); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if ensures.Load() < n || syncs.Load() < n {
			t.Fatalf("ensures %d syncs %d, want %d", ensures.Load(), syncs.Load(), n)
		}
	}
	waitFor(1)
	f.h.TriggerDirectorySync()
	waitFor(2)
	cancel()
	<-done
}

// Review fix 1: until the fresh-auth client is in place (the last ensure
// succeeded), every proof is refused, even one a verifier would accept: a
// conflicting (untagged or foreign) client must fail closed.
func TestFreshAuthRefusedUntilClientInPlace(t *testing.T) {
	f := newFixture(t)
	f.h.SetFreshAuth(ListenerPeople, &fakeFreshAuth{}) // accepts everything
	var ensureErr atomic.Value
	ensureErr.Store(errBox{&keycloak.ConflictError{ClientID: freshauth.ClientID}})
	var ensures atomic.Int32
	f.h.SetDirectory(dirStateOf(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, nil, nil
	}), nil)
	f.h.SetFreshAuthClient(func(context.Context) error { ensures.Add(1); return ensureErr.Load().(errBox).err })
	check := func(label string, wantOK bool) {
		t.Helper()
		_, reason, err := f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "alice")
		// The flag is stored right after the ensure returns: wait for it.
		for i := 0; i < 500 && (err == nil) != wantOK; i++ {
			time.Sleep(10 * time.Millisecond)
			_, reason, err = f.h.checkFreshAuth(context.Background(), govCore("people"), testProof, "alice")
		}
		if wantOK && err != nil {
			t.Errorf("%s: refused: %v (%s)", label, err, reason)
		}
		// C-M7: the Hub's own outage is a 503 (generic text), never
		// counted as the caller's refusal.
		if !wantOK && (statusOf(err) != 503 || err != errFreshAuthUnavailable || reason != "fresh-auth client not in place" || isRefusal(err)) {
			t.Errorf("%s: %v (%q), want the 503 with reason \"fresh-auth client not in place\"", label, err, reason)
		}
	}
	check("before any ensure", false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.h.RunDirectorySync(ctx); close(done) }()
	waitEnsures := func(n int32) {
		t.Helper()
		for i := 0; i < 500 && ensures.Load() < n; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if ensures.Load() < n {
			t.Fatalf("ensures %d, want %d", ensures.Load(), n)
		}
	}
	waitEnsures(1)
	check("ensure answered *ConflictError", false)
	ensureErr.Store(errBox{nil})
	f.h.TriggerDirectorySync()
	waitEnsures(2)
	check("after a nil ensure", true)
	ensureErr.Store(errBox{errors.New("keycloak down")})
	f.h.TriggerDirectorySync()
	waitEnsures(3)
	check("after a later failed ensure", false)
	cancel()
	<-done
}

type errBox struct{ err error }
