package hub

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// wireFix is the mail fixture with nothing wired: the slot open,
// mailsrv installed, root a full administrator, a security-key fresh
// sign-in on both listeners, a fake audit and fast void waits.
type wireFix struct {
	*mailFixture
	fa    *touchFA
	audit *fakeAudit
	// ups are the override's content at each up of mailsrv, with the
	// provider's accepted documents at that moment.
	mu  sync.Mutex
	ups []wireUp
}

type wireUp struct {
	override string
	puts     int
}

var wireProof = freshauth.Proof{Code: "c", CodeVerifier: "v", Nonce: "n"}

func newWireFix(t *testing.T, others ...string) *wireFix {
	t.Helper()
	m := newMailFixture(t, others...)
	w := &wireFix{mailFixture: m, fa: &touchFA{method: "security_key"}, audit: &fakeAudit{}}
	m.h.mu.Lock()
	m.h.st.Mail.Provider = nil
	m.h.mu.Unlock()
	m.h.SetFreshAuth(ListenerHub, w.fa)
	m.h.SetFreshAuth(ListenerPeople, w.fa)
	m.h.freshAuthReady.Store(true)
	setSignIn(m.fixture, func(si *state.SignIn) {
		for k := range allOn() {
			si.Methods[string(k)] = true
		}
	})
	m.h.SetAudit(w.audit)
	m.h.mailBootstrapWait, m.h.mailPollEvery = 500*time.Millisecond, time.Millisecond
	m.runner.upHook = func(project string) {
		if project != "portcullis-"+mailProviderID {
			return
		}
		b, _ := os.ReadFile(m.h.overridePath(strings.TrimPrefix(project, "portcullis-")))
		w.mu.Lock()
		w.ups = append(w.ups, wireUp{string(b), m.mc.Puts()})
		w.mu.Unlock()
	}
	return w
}

func (w *wireFix) wire(t *testing.T, in WireRequest, actor directory.Actor) (*AsyncOp, error) {
	t.Helper()
	op, err := w.h.StartWireMail(context.Background(), mailProviderID, in, actor)
	w.h.Wait()
	return op, err
}

func rootActor() directory.Actor { return directory.Human("root") }

// TestWireGuardOrder: each guard's status and text, in contract order.
func TestWireGuardOrder(t *testing.T) {
	w := newWireFix(t)
	ok := WireRequest{Confirm: mailProviderID, Proof: &wireProof, Listener: ListenerHub}
	for _, c := range []struct {
		name   string
		setup  func()
		in     WireRequest
		actor  directory.Actor
		status int
		text   string
	}{
		{"ai", nil, ok, directory.Actor{User: "root", Via: directory.ViaAI, Client: "claude"}, 403, "never wired, switched or unwired through MCP or AI"},
		{"delegate", nil, ok, directory.Human("alice"), 403, "full administrators only"},
		{"no proof", nil, WireRequest{Confirm: mailProviderID}, rootActor(), 403, freshauth.Message},
		{"stale proof", func() { w.fa.set("password", "", nil) }, ok, rootActor(), 403, freshauth.Message},
		{"typed id", func() { w.fa.set("security_key", "", nil) }, WireRequest{Confirm: "mailsr", Proof: &wireProof}, rootActor(), 400, "type the instance id to confirm"},
		{"slot off", func() { setCoreMail(t, w.fixture, false) }, ok, rootActor(), 409, "mail is off: run ./portcullis mail enable on the host"},
		{"another wired", func() {
			setCoreMail(t, w.fixture, true)
			w.h.mu.Lock()
			w.h.st.Mail.Provider = &state.MailProvider{Instance: "othermail"}
			w.h.mu.Unlock()
		}, ok, rootActor(), 409, "othermail is this server's mail provider: switch instead"},
		{"kubernetes", func() {
			w.h.mu.Lock()
			w.h.st.Mail.Provider = nil
			w.h.mu.Unlock()
			w.h.cfg.Runtime = runtime.KindKubernetes
		}, ok, rootActor(), 409, "mail isn't available on Kubernetes yet"},
		{"port start", func() {
			w.h.cfg.Runtime = runtime.KindPodman
			writeFile(t, w.project+"/.env", "CORE_VAR=core-value\nPORTCULLIS_MAIL=on\nPORTCULLIS_MAIL_HOSTNAME=mail.example.org\nPORTCULLIS_UNPRIVILEGED_PORT_START=1024\n")
		}, ok, rootActor(), 409, "net.ipv4.ip_unprivileged_port_start = 1024"},
	} {
		if c.setup != nil {
			c.setup()
		}
		_, err := w.wire(t, c.in, c.actor)
		if statusOf(err) != c.status || err == nil || !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: %v (%d), want %d %q", c.name, err, statusOf(err), c.status, c.text)
		}
	}
	// No guard ran a step: nothing recorded, no up.
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.Provider != nil || w.h.st.Mail.VoidOwed != nil || len(w.ups) != 0 {
		t.Fatalf("a refused wiring changed something: %+v %+v %d", w.h.st.Mail.Provider, w.h.st.Mail.VoidOwed, len(w.ups))
	}
}

// TestWirePortCollision: another enabled instance on 25, 465, 587 or 993
// refuses the wiring, naming it.
func TestWirePortCollision(t *testing.T) {
	w := newWireFix(t)
	w.h.mu.Lock()
	tp := w.h.findLocked(mailProviderID)
	refusals := w.h.mailWireRefusalsLocked(tp, "")
	w.h.mu.Unlock()
	if len(refusals) != 0 {
		t.Fatalf("refused: %v", refusals)
	}
	w.h.mu.Lock()
	w.h.st.Enabled = append(w.h.st.Enabled, "grafana")
	s := w.h.st.Settings["grafana"]
	s.Ports = map[string]string{"GRAFANA_PORT": "587"}
	w.h.st.Settings["grafana"] = s
	refusals = w.h.mailWireRefusalsLocked(tp, "")
	w.h.mu.Unlock()
	if len(refusals) != 1 || !strings.Contains(refusals[0], "grafana publishes port 587") {
		t.Fatalf("refusals %v", refusals)
	}
}

// TestWireRefusedFromAI, TestWireRefusedForDelegate, TestWireNeedsFreshProof
// and TestWireTypedID are rows of TestWireGuardOrder; the host path:

// TestHostInstallCreatesDefault (R-HH5, H5): with no instance of the
// template created, the host install creates its default instance, then
// wires it; a wrong source or no source installs nothing.
func TestHostInstallCreatesDefault(t *testing.T) {
	w := newWireFix(t)
	w.h.mu.Lock()
	delete(w.h.st.Instances, mailProviderID)
	w.h.st.SetEnabled(mailProviderID, false)
	w.h.mu.Unlock()
	w.engine.mu.Lock()
	w.engine.containers = slices.DeleteFunc(w.engine.containers, func(c docker.Container) bool { return c.Labels[docker.LabelProject] == "portcullis-"+mailProviderID })
	w.engine.mu.Unlock()
	for _, src := range []string{"", "elsewhere"} {
		if _, err := w.h.HostMailInstall(context.Background(), mailProviderID, src, mailProviderID); err == nil {
			t.Fatalf("source %q accepted", src)
		}
	}
	if _, err := w.h.HostMailInstall(context.Background(), mailProviderID, "local", mailProviderID); err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	w.h.mu.RLock()
	_, created := w.h.st.Instances[mailProviderID]
	p := w.h.st.Mail.Provider
	w.h.mu.RUnlock()
	if !created || p == nil || p.Instance != mailProviderID {
		t.Fatalf("created %v provider %+v", created, p)
	}
}

// TestWireHostPathNoProofButConfirm: the host socket wires with the typed
// id and no proof (actor host); a wrong id is still refused.
func TestWireHostPathNoProofButConfirm(t *testing.T) {
	w := newWireFix(t)
	w.h.mu.Lock()
	w.h.st.SetEnabled(mailProviderID, true)
	w.h.mu.Unlock()
	if _, err := w.h.HostMailInstall(context.Background(), mailProviderID, "local", "nope"); statusOf(err) != 400 {
		t.Fatalf("wrong id: %v", err)
	}
	if _, err := w.h.HostMailInstall(context.Background(), mailProviderID, "local", mailProviderID); err != nil {
		t.Fatal(err)
	}
	w.h.Wait()
	w.h.mu.RLock()
	p := w.h.st.Mail.Provider
	w.h.mu.RUnlock()
	if p == nil || p.Instance != mailProviderID || p.WiredBy != HostActor {
		t.Fatalf("provider %+v", p)
	}
	if e := w.audit.last(); e.Action != "mail.provider_wired" || e.Actor != HostActor || e.Result != "ok" {
		t.Fatalf("audit %+v", e)
	}
	if w.fa.calls.Load() != 0 {
		t.Fatal("the host path asked for a fresh sign-in")
	}
}

// TestWireStepsInOrder: the first up renders void mode (no ports, the
// void session) and runs before the void; the normal override (ports)
// only after a verified void; the first document after the normal up;
// the gate opens; the record names the template, its source and hash.
func TestWireStepsInOrder(t *testing.T) {
	w := newWireFix(t)
	op, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof, Listener: ListenerHub}, rootActor())
	if err != nil {
		t.Fatal(err)
	}
	if op.Op != OpMailWire {
		t.Fatalf("op %+v", op)
	}
	if lo := w.h.LastOp(mailProviderID); lo == nil || !lo.OK {
		t.Fatalf("op record %+v", lo)
	}
	w.mu.Lock()
	ups := append([]wireUp(nil), w.ups...)
	w.mu.Unlock()
	if len(ups) < 2 {
		t.Fatalf("%d ups", len(ups))
	}
	first, last := ups[0], ups[len(ups)-1]
	if strings.Contains(first.override, "0.0.0.0:25:") || !strings.Contains(first.override, VarMailVoidSession) || !strings.Contains(first.override, "internal: true") {
		t.Fatalf("first up isn't void mode:\n%s", first.override)
	}
	if !strings.Contains(last.override, `"0.0.0.0:25:10025"`) || strings.Contains(last.override, VarMailVoidSession) {
		t.Fatalf("last up isn't normal:\n%s", last.override)
	}
	for _, u := range ups[:len(ups)-1] {
		if strings.Contains(u.override, "0.0.0.0:25:") {
			t.Fatal("ports before the verified void")
		}
	}
	if last.puts != 0 || w.mc.Puts() == 0 {
		t.Fatalf("documents: %d at the normal up, %d after", last.puts, w.mc.Puts())
	}
	if len(w.mc.Voids) != 1 || w.mc.Voids[0] != state.MailVoidWire {
		t.Fatalf("voids %v", w.mc.Voids)
	}
	if gateFile(t, w.fixture, mailGatePresent) != mailGateSentinel+"\n" || len(gateFile(t, w.fixture, mailGateAPISecret)) != mailSecretLen {
		t.Fatal("the gate isn't open")
	}
	w.h.mu.RLock()
	p, owed, enabled := w.h.st.Mail.Provider, w.h.st.Mail.VoidOwed, slices.Contains(w.h.st.Enabled, mailProviderID)
	w.h.mu.RUnlock()
	if p == nil || p.Template != mailProviderID || p.Source != "local" || len(p.BlockHash) != 64 || p.WiredBy != "root" || p.WiredAt.IsZero() || owed != nil || !enabled {
		t.Fatalf("provider %+v owed %+v enabled %v", p, owed, enabled)
	}
	tg, _ := os.ReadFile(w.h.cfg.MailSlotDir + "/" + mailTargetsFile)
	if !strings.Contains(string(tg), "mail-provider-metrics:9100") || !strings.Contains(string(tg), "/metrics/prometheus") {
		t.Fatalf("targets %s", tg)
	}
}

// TestWireAudit: mail.provider_wired with the template, source, commit
// and block hash, the actor; a refusal is audited too; never a secret.
func TestWireAudit(t *testing.T) {
	w := newWireFix(t)
	if _, err := w.wire(t, WireRequest{Confirm: "x", Proof: &wireProof}, rootActor()); err == nil {
		t.Fatal("wrong id wired")
	}
	if e := w.audit.last(); e.Action != "mail.provider_wired" || e.Result == "ok" {
		t.Fatalf("refusal audit %+v", e)
	}
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); err != nil {
		t.Fatal(err)
	}
	e := w.audit.last()
	if e.Action != "mail.provider_wired" || e.Target != mailProviderID || e.Actor != "root" || e.Result != "ok" ||
		!strings.Contains(e.Detail, "template=mailsrv") || !strings.Contains(e.Detail, "source=local") || !strings.Contains(e.Detail, "block_hash=") || !strings.Contains(e.Detail, "commit=") {
		t.Fatalf("audit %+v", e)
	}
	if s := gateFile(t, w.fixture, mailGateAPISecret); s == "" || strings.Contains(e.Detail, s) {
		t.Fatal("secret in the audit")
	}
}

// TestWarningTextExact: the warning text, answered by the Mail tab and
// the host view.
func TestWarningTextExact(t *testing.T) {
	const want = "This app becomes the mail server for every person and every mail domain. It gets public ports 25, 465, 587 and 993, writes the mail DNS records of every mail domain, creates and checks the mail passwords of every person in mail_users, sends mail to the internet (outbound SMTP), and can read every mailbox."
	if MailWarning != want {
		t.Fatalf("%q", MailWarning)
	}
	w := newWireFix(t)
	v, err := w.h.InstanceMailProvider(context.Background(), mailProviderID)
	if err != nil || v.Warning != want || v.Wired || v.Mode != "unwired" || len(v.RefusedBecause) != 0 {
		t.Fatalf("%+v %v", v, err)
	}
	if hv := w.h.HostMailProviderView(context.Background()); hv.Warning != want || hv.Slot != "open" || hv.Wired {
		t.Fatalf("%+v", hv)
	}
	if _, err := w.h.InstanceMailProvider(context.Background(), "grafana"); statusOf(err) != 404 {
		t.Fatalf("grafana: %v", err)
	}
	setCoreMail(t, w.fixture, false)
	if v, _ := w.h.InstanceMailProvider(context.Background(), mailProviderID); len(v.RefusedBecause) != 1 || v.RefusedBecause[0] != mailSlotOffText {
		t.Fatalf("refused %v", v.RefusedBecause)
	}
}

// TestWireResumesVoidAfterRestart: a start with a provider wired and a
// void owed resumes void mode and the void, never the normal override
// first; nothing owed resumes nothing.
func TestWireResumesVoidAfterRestart(t *testing.T) {
	w := newWireFix(t)
	tp := w.h.Template(mailProviderID)
	hash, err := templates.MailBlockHash(tp.Path, tp.Manifest.Mail, tp.ReadCompose())
	if err != nil {
		t.Fatal(err)
	}
	w.h.mu.Lock()
	w.h.st.Mail.Provider = &state.MailProvider{Instance: mailProviderID, Template: mailProviderID, Source: "local", BlockHash: hash}
	w.h.st.Mail.VoidOwed = &state.MailVoid{Reason: state.MailVoidWire}
	w.h.mu.Unlock()
	w.h.resumeMail()
	w.h.Wait()
	w.mu.Lock()
	ups := append([]wireUp(nil), w.ups...)
	w.mu.Unlock()
	if len(ups) < 2 || strings.Contains(ups[0].override, "0.0.0.0:25:") || !strings.Contains(ups[0].override, VarMailVoidSession) {
		t.Fatalf("ups %d, first:\n%s", len(ups), ups[0].override)
	}
	if !strings.Contains(ups[len(ups)-1].override, "0.0.0.0:25:") {
		t.Fatal("no normal up after the verified void")
	}
	w.h.mu.RLock()
	owed := w.h.st.Mail.VoidOwed
	w.h.mu.RUnlock()
	if owed != nil || len(w.mc.Voids) != 1 {
		t.Fatalf("owed %+v voids %v", owed, w.mc.Voids)
	}
	n := len(w.ups)
	w.h.resumeMail()
	w.h.Wait()
	if len(w.ups) != n {
		t.Fatal("resumed with nothing owed")
	}
}

// TestWireStopUndoes: a Stop before the normal step closes the gate,
// clears the record and the wiring's void, stops the instance.
func TestWireStopUndoes(t *testing.T) {
	w := newWireFix(t)
	ctx, cancel := context.WithCancel(context.Background())
	t0 := w.h.Template(mailProviderID)
	unlock, err := w.h.lockApp(mailProviderID)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = w.h.runWireMail(ctx, t0, rootActor(), state.MailVoidWire)
	unlock()
	if err == nil {
		t.Fatal("a stopped wiring succeeded")
	}
	w.h.mu.RLock()
	p, owed := w.h.st.Mail.Provider, w.h.st.Mail.VoidOwed
	w.h.mu.RUnlock()
	if p != nil || owed != nil || gateFile(t, w.fixture, mailGateAPISecret) != "" {
		t.Fatalf("not undone: %+v %+v", p, owed)
	}
	// L3: every gate file goes, mail_slot's metrics secret too.
	if gateFile(t, w.fixture, mailGateMetricsSecret) != "" || gateFile(t, w.fixture, mailGateRelayPassword) != "" {
		t.Fatal("secrets left in the gate")
	}
	if _, err := os.Stat(filepath.Join(w.h.cfg.MailSlotDir, mailGateMetricsSecret)); !os.IsNotExist(err) {
		t.Fatal("mail_slot's metrics secret left")
	}
}

// TestModeChangeDownsFirst (Ruling T8-void): every up that changes the
// provider's mode is preceded by a down of its project.
func TestModeChangeDownsFirst(t *testing.T) {
	w := newWireFix(t)
	if _, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor()); err != nil {
		t.Fatal(err)
	}
	var seq []string
	for _, c := range w.runner.Calls() {
		if strings.HasSuffix(c, ":portcullis-"+mailProviderID) {
			seq = append(seq, strings.TrimSuffix(c, ":portcullis-"+mailProviderID))
		}
	}
	// void up (after a down), void's own up (same mode: none), then the
	// normal up after a down.
	joined := strings.Join(seq, ",")
	if !strings.HasPrefix(joined, "down,up") || !strings.HasSuffix(joined, "down,up") || strings.Count(joined, "down") < 2 {
		t.Fatalf("calls %v", seq)
	}
	// The same mode again: no down.
	n := len(w.runner.callsMatching("down"))
	unlock, _ := w.h.lockApp(mailProviderID)
	err := w.h.composeUp(context.Background(), w.h.Template(mailProviderID))
	unlock()
	if err != nil || len(w.runner.callsMatching("down")) != n {
		t.Fatalf("same-mode up: %v, downs %d → %d", err, n, len(w.runner.callsMatching("down")))
	}
}

// TestVoidNetworkNotInternalStops (Ruling T8-void): a template network
// the engine still has non-internal in void mode stops the instance and
// keeps the error; void isn't reported applied.
func TestVoidNetworkNotInternalStops(t *testing.T) {
	w := newWireFix(t)
	w.engine.mu.Lock()
	w.engine.networks = append(w.engine.networks, runtime.Network{Name: "portcullis-mailsrv_egress", Internal: false,
		Labels: map[string]string{"com.docker.compose.project": "portcullis-mailsrv", "com.docker.compose.network": "egress"}})
	w.engine.mu.Unlock()
	_, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof}, rootActor())
	if err != nil {
		t.Fatal(err) // the op is accepted; it fails in the background
	}
	if lo := w.h.LastOp(mailProviderID); lo == nil || lo.OK || !strings.Contains(lo.Error, "not internal") {
		t.Fatalf("op %+v", lo)
	}
	if msg, _ := w.h.MailVoidError(); !strings.Contains(msg, "portcullis-mailsrv_egress is not internal") {
		t.Fatalf("doctor error %q", msg)
	}
	calls := w.runner.Calls()
	if len(calls) == 0 || calls[len(calls)-1] != "down:portcullis-"+mailProviderID {
		t.Fatalf("not stopped: %v", calls)
	}
	w.h.mu.RLock()
	defer w.h.mu.RUnlock()
	if w.h.st.Mail.VoidOwed == nil || len(w.mc.Voids) != 0 {
		t.Fatalf("void reported applied: owed %+v voids %v", w.h.st.Mail.VoidOwed, w.mc.Voids)
	}
}

// TestWireRefusalsRecheckedUnderLocks (L2): the slot closing between
// the guards and the locks refuses the wiring.
func TestWireRefusalsRecheckedUnderLocks(t *testing.T) {
	w := newWireFix(t)
	w.h.testHookMailSlotLocked = func(op string) {
		if op == OpMailWire {
			setCoreMail(t, w.fixture, false)
		}
	}
	_, err := w.wire(t, WireRequest{Confirm: mailProviderID, Proof: &wireProof, Listener: ListenerHub}, rootActor())
	w.h.mu.RLock()
	p := w.h.st.Mail.Provider
	w.h.mu.RUnlock()
	if statusOf(err) != 409 || p != nil {
		t.Fatalf("%v, provider %+v", err, p)
	}
}

// TestWireRefusedOnWorker and the move refusal (final review M2): a
// mail provider instance on a worker can't be wired; the wired one
// can't move.
func TestWireRefusedOnWorker(t *testing.T) {
	w := newWireFix(t)
	w.h.mu.Lock()
	in := w.h.st.Instances[mailProviderID]
	in.ID, in.Template, in.Server = mailProviderID, mailProviderID, "nas"
	w.h.st.Instances[mailProviderID] = in
	refusals := w.h.mailWireRefusalsLocked(w.h.findLocked(mailProviderID), "")
	w.h.mu.Unlock()
	found := false
	for _, r := range refusals {
		found = found || strings.Contains(r, "runs on the primary server")
	}
	if !found {
		t.Fatalf("refusals %v", refusals)
	}
	v := wiredFix(t)
	if err := v.h.moveInstance(context.Background(), mailProviderID, "nas", rootActor(), func() {}); statusOf(err) != 409 {
		t.Fatalf("move: %v", err)
	}
}
