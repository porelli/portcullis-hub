package hub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
)

// Plan 4 Task 12b: the master switch, the Keycloak AI clients and their
// health (contract §8 "AI clients", §15.11 "Master switch").

// fakeAIKC's client side (12b): EnsureAIClient records the spec;
// failClient makes it fail; DeleteAIClient records the delete.
func (k *fakeAIKC) EnsureAIClient(ctx context.Context, s keycloak.AIClientSpec) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, "client:"+s.ClientID)
	if err := k.failClient[s.ClientID]; err != nil {
		return err
	}
	for _, sc := range s.OptionalScopes {
		if _, ok := k.scopes[sc]; !ok {
			return fmt.Errorf("client scope %s does not exist", sc)
		}
	}
	if k.clients == nil {
		k.clients = map[string]keycloak.AIClientSpec{}
	}
	k.clients[s.ClientID] = s
	k.optional[s.ClientID] = slices.Sorted(slices.Values(s.OptionalScopes))
	return nil
}

func (k *fakeAIKC) DeleteAIClient(ctx context.Context, clientID, owner string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, "delete-client:"+clientID)
	delete(k.clients, clientID)
	return nil
}

func (k *fakeAIKC) setFailClient(id string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.failClient == nil {
		k.failClient = map[string]error{}
	}
	if err == nil {
		delete(k.failClient, id)
		return
	}
	k.failClient[id] = err
}

// hubAIRealm is a fake realm with Keycloak's built-in scopes (what
// EnsureAIClient needs) and a keycloak.Client on it.
func hubAIRealm(t *testing.T) (*kctest.Server, *keycloak.Client) {
	t.Helper()
	kc := kctest.New(t)
	for _, n := range []string{"basic", "acr", "offline_access", "profile", "email", "roles", "web-origins", "groups"} {
		kc.AddScope(n)
	}
	kc.SetRealmDefaultScopes([]string{"basic", "acr", "profile", "email", "roles", "web-origins"}, []string{"offline_access"})
	return kc, keycloak.New(kc.HTTP.URL, "admin", "admin")
}

func saveAI(t *testing.T, a *instAIFixture, u AISettingsUpdate) {
	t.Helper()
	if err := a.h.SaveAISettings(u, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
}

const (
	idleAttr = "client.offline.session.idle.timeout"
	maxAttr  = "client.offline.session.max.lifespan"
)

func TestMasterSwitchManagesClients(t *testing.T) {
	kc, c := hubAIRealm(t)
	a := newInstAIFixture(t, func(st *state.AppState) { st.AI.Enabled = false })
	a.h.SetAIKeycloak(c)
	a.h.SetAIClientHealth(nil)
	// An untagged client holding Generic's id: a conflict, left alone.
	foreign := kc.AddClient(keycloak.AIClientIDs.Generic, nil)
	kc.SetClientURIs(foreign, []string{"https://evil.example.net/cb"}, nil)

	// Master on → the offered clients exist, with Settings → AI's
	// connection length (defaults 7 / 30 days).
	saveAI(t, a, AISettingsUpdate{Enabled: ptr(true)})
	for _, id := range []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode} {
		cl := kc.ClientByClientID(id)
		if cl == nil {
			t.Fatalf("%s not created", id)
		}
		if cl.Attributes[keycloak.OwnerAttr] != keycloak.AIOwner || cl.Attributes[idleAttr] != "604800" || cl.Attributes[maxAttr] != "2592000" {
			t.Errorf("%s attributes = %v", id, cl.Attributes)
		}
	}
	if cl := kc.ClientByClientID(keycloak.AIClientIDs.Generic); cl.Attributes[keycloak.OwnerAttr] != "" || !slices.Equal(cl.RedirectURIs, []string{"https://evil.example.net/cb"}) {
		t.Errorf("the untagged client was taken over: %+v", cl)
	}
	// The gate lists only the healthy ones (the conflict is not).
	g := a.gate(t)
	if !g.Enabled || !slices.Equal(g.Clients, []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode}) {
		t.Errorf("gate enabled %v clients %v", g.Enabled, g.Clients)
	}
	// The admin scope only on Claude (its admin flag), PortcullisAdmin on.
	if got := kc.OptionalScopes(kc.ClientByClientID(keycloak.AIClientIDs.Claude).ID); !slices.Contains(got, "mcp:portcullis.admin") || !slices.Contains(got, "mcp:all") {
		t.Errorf("claude optional = %v", got)
	}
	if got := kc.OptionalScopes(kc.ClientByClientID(keycloak.AIClientIDs.ClaudeCode).ID); slices.Contains(got, "mcp:portcullis.admin") || !slices.Contains(got, "mcp:portcullis.people") {
		t.Errorf("claude code optional = %v", got)
	}

	// Connection length changes update them.
	saveAI(t, a, AISettingsUpdate{OfflineIdleDays: ptr(3), OfflineMaxDays: ptr(10)})
	for _, id := range []string{keycloak.AIClientIDs.Claude, keycloak.AIClientIDs.ClaudeCode} {
		if cl := kc.ClientByClientID(id); cl.Attributes[idleAttr] != "259200" || cl.Attributes[maxAttr] != "864000" {
			t.Errorf("%s after the length change: %v", id, cl.Attributes)
		}
	}

	// PortcullisAdmin off → the admin scope detached at once; on → back.
	saveAI(t, a, AISettingsUpdate{PortcullisAdmin: ptr(false)})
	if got := kc.OptionalScopes(kc.ClientByClientID(keycloak.AIClientIDs.Claude).ID); slices.Contains(got, "mcp:portcullis.admin") {
		t.Errorf("admin scope kept with PortcullisAdmin off: %v", got)
	}
	saveAI(t, a, AISettingsUpdate{PortcullisAdmin: ptr(true)})
	if got := kc.OptionalScopes(kc.ClientByClientID(keycloak.AIClientIDs.Claude).ID); !slices.Contains(got, "mcp:portcullis.admin") {
		t.Errorf("admin scope not back: %v", got)
	}

	// Claude Code unticked → deleted (tagged); Generic unticked → the
	// untagged client stays (only owner-tagged clients are deleted).
	saveAI(t, a, AISettingsUpdate{Clients: &AIClientsUpdate{ClaudeCode: &AIClientUpdate{Offered: ptr(false)}, Generic: &AIClientUpdate{Offered: ptr(false)}}})
	if kc.ClientByClientID(keycloak.AIClientIDs.ClaudeCode) != nil {
		t.Error("portcullis-ai-claude-code not deleted")
	}
	if kc.ClientByClientID(keycloak.AIClientIDs.Generic) == nil {
		t.Error("the untagged portcullis-ai-generic was deleted")
	}
	if g := a.gate(t); !slices.Equal(g.Clients, []string{keycloak.AIClientIDs.Claude}) {
		t.Errorf("gate clients after unticking = %v", g.Clients)
	}

	// The sync loop re-asserts (drift put back) with the same pass.
	kc.UpdateClient(kc.ClientByClientID(keycloak.AIClientIDs.Claude).ID, func(cl *kctest.Client) { cl.Attributes[idleAttr] = "60" })
	changed, err := a.h.syncAIClients(context.Background())
	var conflict *keycloak.ConflictError
	if changed || !errors.As(err, &conflict) || conflict.ClientID != keycloak.AIClientIDs.Generic {
		t.Errorf("loop pass: changed %v err %v (want only the untagged generic's conflict)", changed, err)
	}
	if cl := kc.ClientByClientID(keycloak.AIClientIDs.Claude); cl.Attributes[idleAttr] != "259200" {
		t.Errorf("drift not put back: %v", cl.Attributes)
	}

	// Master off → clients and scopes kept, the gate refuses everything.
	saveAI(t, a, AISettingsUpdate{Enabled: ptr(false)})
	if kc.ClientByClientID(keycloak.AIClientIDs.Claude) == nil || kc.Scope("mcp:all") == nil || kc.Scope("mcp:portcullis.admin") == nil {
		t.Error("master off removed a client or a scope")
	}
	if g := a.gate(t); g.Enabled || len(g.Clients) != 0 || len(g.Resources) != 0 {
		t.Errorf("gate with the master off: enabled %v clients %v resources %d", g.Enabled, g.Clients, len(g.Resources))
	}
	// Audited settings.ai once per save, as T9 does.
	if n := len(a.audits("settings.ai")); n != 6 {
		t.Errorf("settings.ai audited %d times, want 6", n)
	}
}

// The loop pass: an EnsureAIClient error makes that id unhealthy (left
// out of mcp-gate.json); the gate file is rewritten only when health
// changed.
func TestAIClientHealthFromSync(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.h.SetAIClientHealth(nil)
	if changed, err := a.h.syncAIClients(context.Background()); err != nil || !changed {
		t.Fatalf("first pass: changed %v err %v", changed, err)
	}
	a.h.writePolicyLogged()
	if g := a.gate(t); len(g.Clients) != 3 {
		t.Fatalf("clients = %v", g.Clients)
	}
	// Exact scopes and connection length on each.
	a.kc.mu.Lock()
	spec := a.kc.clients[keycloak.AIClientIDs.Claude]
	a.kc.mu.Unlock()
	if spec.OfflineIdle.Hours() != 7*24 || spec.OfflineMax.Hours() != 30*24 || !spec.Public || spec.Owner != keycloak.AIOwner ||
		!slices.Equal(spec.OptionalScopes, a.h.wantedAIScopes(keycloak.AIClientIDs.Claude)) {
		t.Errorf("claude spec = %+v", spec)
	}
	// Unchanged health: no rewrite.
	if changed, err := a.h.syncAIClients(context.Background()); err != nil || changed {
		t.Errorf("same health: changed %v err %v", changed, err)
	}
	a.kc.setFailClient(keycloak.AIClientIDs.Generic, errors.New("keycloak down"))
	changed, err := a.h.aiClientPass(context.Background())
	if err == nil || !changed {
		t.Errorf("failing ensure: changed %v err %v", changed, err)
	}
	if h := a.h.aiClientHealth(); h[keycloak.AIClientIDs.Generic] || !h[keycloak.AIClientIDs.Claude] {
		t.Errorf("health = %v", h)
	}
	// The pass rewrote the gate file on the change.
	if g := a.gate(t); slices.Contains(g.Clients, keycloak.AIClientIDs.Generic) || len(g.Clients) != 2 {
		t.Errorf("unhealthy generic listed: %v", g.Clients)
	}
	// A conflict: logged, unhealthy, never deleted.
	a.kc.setFailClient(keycloak.AIClientIDs.Generic, &keycloak.ConflictError{ClientID: keycloak.AIClientIDs.Generic})
	if _, err := a.h.syncAIClients(context.Background()); err == nil {
		t.Error("conflict not reported")
	}
	if h := a.h.aiClientHealth(); h[keycloak.AIClientIDs.Generic] {
		t.Error("conflicting generic healthy")
	}
	// An ai_client's health (T23's) is never touched by the pass.
	a.h.mu.Lock()
	a.h.aiHealth["chat-portcullis-ai"] = true
	a.h.mu.Unlock()
	a.h.syncAIClients(context.Background())
	if h := a.h.aiClientHealth(); !h["chat-portcullis-ai"] {
		t.Errorf("the pass dropped an ai_client's health: %v", h)
	}
	a.kc.mu.Lock()
	calls := slices.Clone(a.kc.calls)
	a.kc.mu.Unlock()
	for _, c := range calls {
		if strings.Contains(c, "chat-portcullis-ai") {
			t.Errorf("the pass touched the ai_client: %s", c)
		}
	}
}

// Master off switches AI off app-side (env, restart, app_oauth
// on_change false) keeping per-companion state; on re-applies (revoke_all
// before on_change true). A busy lockApp (backup) doesn't lose it.
func TestMasterSwitchAppSide(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.h.lockPoll, a.h.restartWait = 5e6, 30e9
	// The oauth fixture's hooks run on its web service: it runs after
	// every up (a restart's down forgets the containers).
	up := a.runner.upHook
	a.runner.upHook = func(p string) {
		up(p)
		if p != "portcullis-oauthapp" {
			return
		}
		a.engine.mu.Lock()
		defer a.engine.mu.Unlock()
		for _, c := range a.engine.containers {
			if c.Project() == p && c.Service() == "web" {
				return
			}
		}
		a.engine.containers = append(a.engine.containers, container("oauthapp-web", p, "web", "running"))
	}
	a.enable(t, "aiapp")
	a.enable(t, "oauthapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", true, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	nRev := len(a.stdins("/revoke"))
	downs := func(p string) int {
		n := 0
		for _, c := range a.runner.Calls() {
			if c == "down:"+p {
				n++
			}
		}
		return n
	}
	d0, o0 := downs("portcullis-aiapp"), downs("portcullis-oauthapp")

	// A backup holds oauthapp's lock while the master goes off.
	unlock, err := a.h.lockApp("oauthapp")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.h.SaveAISettings(AISettingsUpdate{Enabled: ptr(false)}, root); err != nil {
		t.Fatal(err)
	}
	// Owed in the same commit: the oauth companion's on_change.
	st, err := state.Load(a.h.statePath())
	if err != nil || !st.AIInstances["oauthapp"].Companions["oauth"].OnChangePending {
		t.Errorf("on_change not owed at the commit: %+v (%v)", st.AIInstances["oauthapp"], err)
	}
	unlock()
	a.h.Wait()
	for _, id := range []string{"aiapp", "oauthapp"} {
		env := a.env(t, id)
		if !strings.Contains(env, "\nPORTCULLIS_AI_ENABLED=false\n") {
			t.Errorf("%s env enabled with the master off:\n%s", id, env)
		}
	}
	if env := a.env(t, "aiapp"); !strings.Contains(env, "\nPORTCULLIS_AI_READONLY_TOK=true\n") {
		t.Errorf("aiapp read-write with the master off:\n%s", env)
	}
	if downs("portcullis-aiapp") <= d0 || downs("portcullis-oauthapp") <= o0 {
		t.Errorf("not restarted: %v", a.runner.Calls())
	}
	if got := a.stdins("/toggle"); got[len(got)-1] != `{"action":"on_change","enabled":false,"mode":"read_write","companion":"oauth"}` {
		t.Errorf("on_change = %v", got)
	}
	// Per-companion state untouched; the gate refuses everything.
	if c := a.companion("oauthapp", "oauth"); !c.Enabled || c.OnChangePending || c.RevokePending {
		t.Errorf("oauth state = %+v", c)
	}
	if c := a.companion("aiapp", "tok"); !c.Enabled || c.Mode != "read_write" {
		t.Errorf("tok state = %+v", c)
	}
	if a.gate(t).Enabled {
		t.Error("gate enabled with the master off")
	}
	if n := len(a.audits("settings.ai")); n != 1 {
		t.Errorf("settings.ai audited %d times", n)
	}

	// Master on: env back, revoke_all before on_change true.
	a.seq = &seqLog{}
	saveAI(t, a, AISettingsUpdate{Enabled: ptr(true)})
	for _, id := range []string{"aiapp", "oauthapp"} {
		if env := a.env(t, id); !strings.Contains(env, "\nPORTCULLIS_AI_ENABLED=true\n") {
			t.Errorf("%s env not enabled after the master on:\n%s", id, env)
		}
	}
	if env := a.env(t, "aiapp"); !strings.Contains(env, "\nPORTCULLIS_AI_READONLY_TOK=false\n") {
		t.Errorf("aiapp mode not back:\n%s", env)
	}
	if got := a.stdins("/revoke"); len(got) <= nRev {
		t.Errorf("no revoke_all on the master on: %v", got)
	}
	seq := a.seq.list()
	i, j := slices.Index(seq, "/revoke:revoke_all"), slices.Index(seq, "/toggle:on_change")
	if i < 0 || j < i {
		t.Errorf("sequence = %v", seq)
	}
	if got := a.stdins("/toggle"); got[len(got)-1] != `{"action":"on_change","enabled":true,"mode":"read_write","companion":"oauth"}` {
		t.Errorf("on_change = %v", got)
	}
	if c := a.companion("oauthapp", "oauth"); !c.Enabled || c.OnChangePending || c.RevokePending {
		t.Errorf("oauth state after on = %+v", c)
	}
}

// An instance whose effective policy lands on LoA 3 (a restore, a template
// change) with a companion on: the env says AI is off.
func TestAIEnvOffAtLoA3(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); err != nil {
		t.Fatal(err)
	}
	a.h.mu.Lock()
	a.h.st.AuthPolicies["aiapp"] = policy.AuthPolicy{Factors: []string{"mtls"}, Op: "any"}
	env := a.h.aiEnvLocked(a.h.findLocked("aiapp"))
	a.h.mu.Unlock()
	if env["PORTCULLIS_AI_ENABLED"] != "false" || env["PORTCULLIS_AI_READONLY_TOK"] != "true" {
		t.Errorf("env at LoA 3 = %v", env)
	}
}

// The master toggled while UpdateInstanceAI is between its plan and its
// commit: the commit refuses (409), nothing saved.
func TestMasterToggleRacesUpdateInstanceAI(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.enable(t, "aiapp")
	a.h.testHookAIBeforeSave = func() {
		a.h.testHookAIBeforeSave = nil
		if err := a.h.SaveAISettings(AISettingsUpdate{Enabled: ptr(false)}, root); err != nil {
			t.Error(err)
		}
		if err := a.h.SaveAISettings(AISettingsUpdate{Enabled: ptr(true)}, root); err != nil {
			t.Error(err)
		}
	}
	err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 409 {
		t.Errorf("err = %v", err)
	}
	if c := a.companion("aiapp", "tok"); c.Enabled {
		t.Errorf("saved across a master toggle: %+v", c)
	}
	a.h.Wait()
}

// ── 12b fix round 1 ─────────────────────────────────────

// R1-1: the restarts a master toggle owes are in delivered.json before
// the Keycloak pass runs (a crash there still repeats them at start).
func TestMasterRestartOwedBeforeKeycloak(t *testing.T) {
	a := newInstAIFixture(t, nil)
	oauthWeb(a)
	a.enable(t, "oauthapp")
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", true, root); err != nil {
		t.Fatal(err)
	}
	saveAI(t, a, AISettingsUpdate{Enabled: ptr(false)})
	a.kc.mu.Lock()
	a.kc.block, a.kc.entered = make(chan struct{}), make(chan struct{}, 1)
	block := a.kc.block
	a.kc.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- a.h.SaveAISettings(AISettingsUpdate{Enabled: ptr(true)}, root) }()
	<-a.kc.entered
	if got := a.h.loadDelivered("oauthapp").Owed; got != "restart" {
		t.Errorf("delivered.json owed = %q during the Keycloak pass, want restart", got)
	}
	a.kc.mu.Lock()
	a.kc.block = nil
	a.kc.mu.Unlock()
	close(block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
}

// R1-2: the master off makes the Hub's clients unhealthy, so a switch-on
// never publishes the health of before.
func TestMasterOffClearsHealth(t *testing.T) {
	a := newInstAIFixture(t, nil)
	if _, err := a.h.syncAIClients(context.Background()); err != nil {
		t.Fatal(err)
	}
	saveAI(t, a, AISettingsUpdate{Enabled: ptr(false)})
	for id, ok := range a.h.aiClientHealth() {
		if ok {
			t.Errorf("%s healthy with the master off", id)
		}
	}
	a.kc.setFailClient(keycloak.AIClientIDs.Claude, errors.New("keycloak 500"))
	saveAI(t, a, AISettingsUpdate{Enabled: ptr(true)})
	h := a.h.aiClientHealth()
	if h[keycloak.AIClientIDs.Claude] || !h[keycloak.AIClientIDs.ClaudeCode] {
		t.Errorf("health after the switch-on = %v", h)
	}
	if g := a.gate(t); slices.Contains(g.Clients, keycloak.AIClientIDs.Claude) {
		t.Errorf("stale claude listed: %v", g.Clients)
	}
}

// R1-4: the exact set. An existing scope whose ensure fails stays
// attached and the client healthy; a scope that doesn't exist yet makes
// the client unhealthy and leaves it as it was (12a's apply too).
func TestExactScopesOnFailedEnsure(t *testing.T) {
	a := newInstAIFixture(t, nil)
	if _, err := a.h.syncAIClients(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.kc.mu.Lock()
	a.kc.failEnsure = map[string]error{"mcp:all": errors.New("keycloak 500")}
	a.kc.mu.Unlock()
	if _, err := a.h.syncAIClients(context.Background()); err == nil || !strings.Contains(err.Error(), "mcp:all") {
		t.Errorf("err = %v", err)
	}
	if !a.h.aiClientHealth()[keycloak.AIClientIDs.Claude] || !slices.Contains(a.kc.opt(keycloak.AIClientIDs.Claude), "mcp:all") {
		t.Errorf("existing scope: health %v, claude %v", a.h.aiClientHealth(), a.kc.opt(keycloak.AIClientIDs.Claude))
	}

	// A new companion scope that can't be created.
	a.kc.mu.Lock()
	a.kc.failEnsure = map[string]error{"mcp:aiapp.tok": errors.New("keycloak 500")}
	before := a.kc.clients[keycloak.AIClientIDs.Claude]
	a.kc.mu.Unlock()
	beforeOpt := a.kc.opt(keycloak.AIClientIDs.Claude)
	a.enable(t, "aiapp")
	var oe *OpError
	// 12a asks for the exact set: Keycloak refuses the missing scope.
	if err := a.h.SetAISupport(context.Background(), "aiapp", "tok", true, root); !errors.As(err, &oe) ||
		!strings.Contains(err.Error(), "client "+keycloak.AIClientIDs.Claude+" scopes") {
		t.Errorf("12a apply err = %v, want an OpError with the refused exact set", err)
	}
	if got := a.kc.opt(keycloak.AIClientIDs.Claude); !slices.Equal(got, beforeOpt) {
		t.Errorf("12a changed claude to %v (was %v)", got, beforeOpt)
	}
	if _, err := a.h.syncAIClients(context.Background()); err == nil {
		t.Error("no error for the missing scope")
	}
	a.kc.mu.Lock()
	after := a.kc.clients[keycloak.AIClientIDs.Claude]
	a.kc.mu.Unlock()
	if a.h.aiClientHealth()[keycloak.AIClientIDs.Claude] || !slices.Equal(after.OptionalScopes, before.OptionalScopes) {
		t.Errorf("missing scope: health %v, claude %v (was %v)", a.h.aiClientHealth(), after.OptionalScopes, before.OptionalScopes)
	}
}

// R1-6: the sync loop's kick runs the client pass.
func TestAttrSyncRunsAIClientPass(t *testing.T) {
	a := newInstAIFixture(t, nil)
	a.h.SetAIClientHealth(nil)
	ctx, cancel := context.WithCancel(context.Background())
	kick := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		a.h.runAttrSync(ctx, kick)
		close(done)
	}()
	kick <- struct{}{}
	deadline := time.Now().Add(10 * time.Second)
	for {
		a.kc.mu.Lock()
		calls := slices.Clone(a.kc.calls)
		a.kc.mu.Unlock()
		if slices.Contains(calls, "client:"+keycloak.AIClientIDs.Generic) && len(a.h.aiClientHealth()) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no AI client pass after the kick: %v", calls)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if g := a.gate(t); len(g.Clients) != 3 {
		t.Errorf("gate clients after the loop's pass = %v", g.Clients)
	}
}

// R1-6: a failed save of a master toggle puts ai_instances and the
// generation back.
func TestMasterToggleFailedSaveRestores(t *testing.T) {
	a := newInstAIFixture(t, nil)
	oauthWeb(a)
	a.enable(t, "oauthapp")
	if err := a.h.SetAISupport(context.Background(), "oauthapp", "oauth", true, root); err != nil {
		t.Fatal(err)
	}
	a.h.Wait()
	a.h.mu.RLock()
	gen, before := a.h.aiMasterGen, a.h.st.AIInstances["oauthapp"].Companions["oauth"]
	a.h.mu.RUnlock()
	if err := os.Chmod(a.data, 0o500); err != nil {
		t.Fatal(err)
	}
	err := a.h.SaveAISettings(AISettingsUpdate{Enabled: ptr(false)}, root)
	os.Chmod(a.data, 0o755)
	if err == nil {
		t.Fatal("the save didn't fail")
	}
	a.h.mu.RLock()
	defer a.h.mu.RUnlock()
	if !a.h.st.AI.Enabled || a.h.aiMasterGen != gen || a.h.st.AIInstances["oauthapp"].Companions["oauth"] != before {
		t.Errorf("not restored: enabled %v gen %d (was %d) oauth %+v (was %+v)", a.h.st.AI.Enabled, a.h.aiMasterGen, gen,
			a.h.st.AIInstances["oauthapp"].Companions["oauth"], before)
	}
}

// oauthWeb keeps a running web container for oauthapp's hooks after
// every up.
func oauthWeb(a *instAIFixture) {
	up := a.runner.upHook
	a.runner.upHook = func(p string) {
		up(p)
		if p != "portcullis-oauthapp" {
			return
		}
		a.engine.mu.Lock()
		defer a.engine.mu.Unlock()
		for _, c := range a.engine.containers {
			if c.Project() == p && c.Service() == "web" {
				return
			}
		}
		a.engine.containers = append(a.engine.containers, container("oauthapp-web", p, "web", "running"))
	}
}
