package hub

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/settings"
)

const hookID = "hookapp"

// hookFixture loads testdata/settings/hookapp: hook apply (start,
// settings_change, membership_change; 5 s) receives quota (size, GiB),
// the secret token, motd (applies reload) and the per-person seats; hook
// audit (settings_change only, user 10001) receives quota; reload is the
// hook apply. alice and bob are in users_hookapp. Not enabled yet.
func hookFixture(t *testing.T) (*fixture, *fakePeople, *fakeClock) {
	t.Helper()
	m := mustRead(t, filepath.Join("testdata", "settings", "hookapp", "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", "hookapp", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{hookID: {string(m), string(c)}})
	if f.h.Template(hookID) == nil {
		t.Fatalf("hookapp not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople()
	people.addGroup("users_hookapp", "alice", "bob")
	people.addGroup("admin_hookapp")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_hookapp": true, "admin_hookapp": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc = clk.afterFunc
	f.h.sleep = clk.sleep
	return f, people, clk
}

// hookRuns are the ExecStdin calls of hook command cmd0 (from call from
// on), decoded.
func hookRuns(t *testing.T, f *fixture, cmd0 string, from int) []settings.HookInput {
	t.Helper()
	var out []settings.HookInput
	for _, c := range f.engine.ExecCalls()[from:] {
		if len(c.in.Cmd) == 0 || c.in.Cmd[0] != cmd0 {
			continue
		}
		var in settings.HookInput
		if err := json.Unmarshal(c.in.Stdin, &in); err != nil {
			t.Fatalf("stdin of %v is not a HookInput: %v\n%s", c.in.Cmd, err, c.in.Stdin)
		}
		out = append(out, in)
	}
	return out
}

func saveHook(t *testing.T, f *fixture, u SettingsUpdate) *SaveResult {
	t.Helper()
	res, err := f.h.SaveSettings(hookID, u, "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	return res
}

func enableHook(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.h.Enable(hookID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
}

func TestHookGetsFullDesiredState(t *testing.T) {
	f, _, _ := hookFixture(t)
	enableHook(t, f)
	const tok = "tok-SECRET-0123456789"
	tv := tok
	n := len(f.engine.ExecCalls())
	res := saveHook(t, f, SettingsUpdate{Values: map[string]json.RawMessage{"quota": raw("10GiB")}, Secrets: map[string]SecretChange{"token": {Value: &tv}}})
	runs := hookRuns(t, f, "/apply", n)
	if len(runs) != 1 {
		t.Fatalf("apply ran %d times, want 1 (%+v)", len(runs), res.Deliveries)
	}
	in := runs[0]
	if in.Trigger != "settings_change" || in.Version != settings.HookInputVersion || in.Instance != hookID {
		t.Errorf("header = %q %d %q", in.Trigger, in.Version, in.Instance)
	}
	if in.Values["quota"] != float64(10) {
		t.Errorf("values.quota = %v, want 10 (GiB)", in.Values["quota"])
	}
	if in.Secrets["token"] != tok {
		t.Errorf("secrets = %v", in.Secrets)
	}
	if _, ok := in.Values["token"]; ok {
		t.Error("the secret is in values")
	}
	if in.People["alice"]["seats"] != float64(1) || in.People["bob"]["seats"] != float64(1) {
		t.Errorf("people = %v", in.People)
	}
	// Argv as declared, never through a shell, nothing secret on it.
	for _, c := range f.engine.ExecCalls()[n:] {
		if strings.Contains(strings.Join(c.in.Cmd, " "), tok) || strings.Contains(c.in.User, tok) {
			t.Errorf("secret on argv: %+v", c.in)
		}
		if c.in.Cmd[0] == "/bin/sh" {
			t.Errorf("run through a shell: %v", c.in.Cmd)
		}
		if c.in.Timeout != 5*time.Second && c.in.Cmd[0] == "/apply" {
			t.Errorf("timeout = %s", c.in.Timeout)
		}
	}
	// audit got quota too (user 10001), not the token.
	audits := hookRuns(t, f, "/audit", n)
	if len(audits) != 1 || audits[0].Values["quota"] != float64(10) || len(audits[0].Secrets) != 0 {
		t.Errorf("audit runs = %+v", audits)
	}
	if u, ok := unit(res.Deliveries, "hook:apply"); !ok || !u.OK || u.Skipped != "" {
		t.Errorf("hook:apply = %+v", u)
	}
	// A second save of another option: the full state again, never a diff.
	n = len(f.engine.ExecCalls())
	saveHook(t, f, SettingsUpdate{Values: map[string]json.RawMessage{"motd": raw("hello")}})
	runs = hookRuns(t, f, "/apply", n)
	if len(runs) != 1 {
		t.Fatalf("apply ran %d times on the second save", len(runs))
	}
	if runs[0].Values["quota"] != float64(10) || runs[0].Values["motd"] != "hello" || runs[0].Secrets["token"] != tok || len(runs[0].People) != 2 {
		t.Errorf("second save's input = %+v", runs[0])
	}
	if a := hookRuns(t, f, "/audit", n); len(a) != 0 {
		t.Errorf("audit (input unchanged) ran %d times", len(a))
	}
}

func TestHookFailureRecorded(t *testing.T) {
	f, _, _ := hookFixture(t)
	enableHook(t, f)
	const tok = "tok-LEAK-0123456789"
	tv := tok
	saveHook(t, f, SettingsUpdate{Secrets: map[string]SecretChange{"token": {Value: &tv}}})
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte("cannot apply " + tok + "\n" + strings.Repeat("x", 5000)), ExitCode: 3, ExecID: "e3"}, nil
	})
	res := saveHook(t, f, SettingsUpdate{Values: map[string]json.RawMessage{"quota": raw("2GiB")}})
	u, ok := unit(res.Deliveries, "hook:apply")
	if !ok || u.OK || u.Skipped != "" {
		t.Fatalf("hook:apply = %+v", u)
	}
	if strings.Contains(u.Error, tok) || !strings.Contains(u.Error, "[redacted]") || !strings.Contains(u.Error, "3") || len(u.Error) > unitErrorMax+len("…") {
		t.Errorf("unit error (%d bytes) = %.200q", len(u.Error), u.Error)
	}
	op := f.h.LastOp(hookID)
	if op == nil || op.Op != OpHook || op.OK {
		t.Fatalf("op record = %+v", op)
	}
	if strings.Contains(op.Error, tok) || !strings.Contains(op.Error, "[redacted]") || len(op.Error) > 600+len("…") {
		t.Errorf("op error (%d bytes) = %.200q", len(op.Error), op.Error)
	}
	st := f.h.DeliveryStatus(hookID)
	if su := st.Units["hook:apply"]; su.OK || su.Error == "" || strings.Contains(su.Error, tok) {
		t.Errorf("panel status = %+v", su)
	}
	// A success later clears the hook's failure record.
	f.engine.setExec(nil)
	rep, err := f.h.Deliver(context.Background(), hookID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := unit(rep, "hook:apply"); !u.OK {
		t.Errorf("retry = %+v", u)
	}
	if op := f.h.LastOp(hookID); op == nil || !op.OK {
		t.Errorf("op record after the retry = %+v", op)
	}
}

func TestHookSerialisedAndRetried(t *testing.T) {
	f, _, clk := hookFixture(t)
	enableHook(t, f)
	// Two concurrent triggers: the second waits for the first.
	release := make(chan struct{})
	started := make(chan struct{}, 16)
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		started <- struct{}{}
		<-release
		return &docker.ExecResult{Output: []byte("ok\n"), ExecID: "e"}, nil
	})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.h.Deliver(context.Background(), hookID, TriggerRetry); err != nil {
				t.Error(err)
			}
		}()
	}
	<-started
	time.Sleep(50 * time.Millisecond) // the other run would start meanwhile
	close(release)
	wg.Wait()
	f.engine.mu.Lock()
	maxIn := f.engine.execMaxInflight
	f.engine.mu.Unlock()
	if maxIn != 1 {
		t.Errorf("hook runs overlapped (%d at once)", maxIn)
	}

	// A failed run is retried on the next trigger, unchanged input.
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte("boom\n"), ExitCode: 1, ExecID: "e1"}, nil
	})
	saveHook(t, f, SettingsUpdate{Values: map[string]json.RawMessage{"quota": raw("3GiB")}})
	f.engine.setExec(nil)
	n := len(f.engine.ExecCalls())
	rep, err := f.h.Deliver(context.Background(), hookID, TriggerMembership)
	if err != nil {
		t.Fatal(err)
	}
	if runs := hookRuns(t, f, "/apply", n); len(runs) != 1 || runs[0].Trigger != "membership_change" || runs[0].Values["quota"] != float64(3) {
		t.Errorf("failed hook not retried on the next trigger: %+v (%+v)", runs, rep)
	}
	// Unchanged and applied: a save trigger skips it, a retry re-runs it.
	n = len(f.engine.ExecCalls())
	rep, _ = f.h.Deliver(context.Background(), hookID, TriggerSave)
	if u, _ := unit(rep, "hook:apply"); u.Skipped != SkipUnchanged || len(hookRuns(t, f, "/apply", n)) != 0 {
		t.Errorf("unchanged hook: %+v", u)
	}
	rep, _ = f.h.Deliver(context.Background(), hookID, TriggerRetry)
	if u, _ := unit(rep, "hook:apply"); !u.OK || len(hookRuns(t, f, "/apply", n)) != 1 {
		t.Errorf("retry: %+v", u)
	}

	// T-6: a timed-out run may still run (Docker can't kill it): the next
	// run waits for it, up to the hook timeout, then skips and re-queues.
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte("slow"), ExitCode: -1, TimedOut: true, ExecID: "slow1"}, nil
	})
	f.engine.setExecRunning("slow1", true)
	rep, _ = f.h.Deliver(context.Background(), hookID, TriggerRetry)
	if u, _ := unit(rep, "hook:apply"); u.OK || !strings.Contains(u.Error, "timed out") {
		t.Errorf("timed-out run = %+v", u)
	}
	f.engine.setExec(nil)
	n = len(f.engine.ExecCalls())
	rep, _ = f.h.Deliver(context.Background(), hookID, TriggerRetry)
	if u, _ := unit(rep, "hook:apply"); u.Skipped != SkipPrevRunning {
		t.Errorf("run while the previous one runs = %+v", u)
	}
	if len(hookRuns(t, f, "/apply", n)) != 0 {
		t.Error("ran while the previous run still runs")
	}
	if !f.h.DeliveryStatus(hookID).Pending || len(clk.pending()) == 0 {
		t.Error("not re-queued")
	}
	// It finished: the next run goes ahead.
	f.engine.setExecRunning("slow1", false)
	rep, _ = f.h.Deliver(context.Background(), hookID, TriggerRetry)
	if u, _ := unit(rep, "hook:apply"); !u.OK || len(hookRuns(t, f, "/apply", n)) != 1 {
		t.Errorf("after the previous run ended = %+v", u)
	}
}

func TestHookOnStartAndMembership(t *testing.T) {
	f, people, _ := hookFixture(t)
	enableHook(t, f)
	runs := hookRuns(t, f, "/apply", 0)
	if len(runs) != 1 || runs[0].Trigger != "start" || runs[0].Values["quota"] != float64(1) {
		t.Fatalf("enable: apply runs = %+v", runs)
	}
	if a := hookRuns(t, f, "/audit", 0); len(a) != 0 {
		t.Errorf("audit (no start in when) ran on enable: %+v", a)
	}
	if u := f.h.DeliveryStatus(hookID).Units["hook:apply"]; !u.OK {
		t.Errorf("start hook status = %+v", u)
	}
	// A membership change: apply (membership_change) runs, audit doesn't.
	people.addGroup("users_hookapp", "alice", "bob", "dave")
	n := len(f.engine.ExecCalls())
	if _, err := f.h.Deliver(context.Background(), hookID, TriggerMembership); err != nil {
		t.Fatal(err)
	}
	runs = hookRuns(t, f, "/apply", n)
	if len(runs) != 1 || runs[0].Trigger != "membership_change" || runs[0].People["dave"]["seats"] != float64(1) {
		t.Errorf("membership: apply runs = %+v", runs)
	}
	if a := hookRuns(t, f, "/audit", n); len(a) != 0 {
		t.Errorf("audit (no membership_change in when) ran: %+v", a)
	}
	// A restart runs the start hook again.
	n = len(f.engine.ExecCalls())
	if err := f.h.RestartApp(hookID); err != nil {
		t.Fatal(err)
	}
	if runs := hookRuns(t, f, "/apply", n); len(runs) != 1 || runs[0].Trigger != "start" {
		t.Errorf("restart: apply runs = %+v", runs)
	}
}

func TestStartHookFailureRecorded(t *testing.T) {
	f, _, _ := hookFixture(t)
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte("no\n"), ExitCode: 2, ExecID: "e2"}, nil
	})
	// The up succeeded: the enable is not rolled back.
	if err := f.h.Enable(hookID); err != nil {
		t.Fatalf("a start hook failure failed the enable: %v", err)
	}
	f.h.Wait()
	if !f.h.IsEnabled(hookID) {
		t.Error("not enabled")
	}
	op := f.h.LastOp(hookID)
	if op == nil || op.Op != OpHook || op.OK || !strings.HasPrefix(op.Error, "hook ") {
		t.Errorf("op record = %+v", op)
	}
	if u := f.h.DeliveryStatus(hookID).Units["hook:apply"]; u.OK || u.Error == "" {
		t.Errorf("start hook status = %+v", u)
	}
}

func TestReloadHookForm(t *testing.T) {
	f, _, _ := hookFixture(t)
	enableHook(t, f)
	n := len(f.engine.ExecCalls())
	res := saveHook(t, f, SettingsUpdate{Values: map[string]json.RawMessage{"motd": raw("hi")}})
	if res.Effect != settings.EffectReload {
		t.Fatalf("effect = %s", res.Effect)
	}
	runs := hookRuns(t, f, "/apply", n)
	if len(runs) != 1 || runs[0].Values["motd"] != "hi" || runs[0].Trigger != "settings_change" {
		t.Errorf("apply runs = %+v (want one: the delivery and the reload folded)", runs)
	}
	u, ok := unit(res.Deliveries, "reload")
	if !ok || !u.OK || u.Skipped != "" || !strings.Contains(u.Message, "apply") {
		t.Errorf("reload unit = %+v", u)
	}
	if k := f.engine.Kills(); len(k) != 0 {
		t.Errorf("signals sent: %v", k)
	}
}

func TestHookNotRunningSkipped(t *testing.T) {
	f, _, _ := hookFixture(t)
	enableHook(t, f)
	// The app's containers are gone (stopped outside the Hub).
	f.engine.mu.Lock()
	f.engine.containers = nil
	f.engine.mu.Unlock()
	n := len(f.engine.ExecCalls())
	res := saveHook(t, f, SettingsUpdate{Values: map[string]json.RawMessage{"quota": raw("7GiB")}})
	if u, _ := unit(res.Deliveries, "hook:apply"); u.Skipped != SkipNotRunning || u.OK {
		t.Errorf("hook:apply = %+v", u)
	}
	if len(f.engine.ExecCalls()) != n {
		t.Error("exec without a running container")
	}
	// The next start delivers.
	if err := f.h.RestartApp(hookID); err != nil {
		t.Fatal(err)
	}
	runs := hookRuns(t, f, "/apply", n)
	if len(runs) != 1 || runs[0].Trigger != "start" || runs[0].Values["quota"] != float64(7) {
		t.Errorf("start after not running: %+v", runs)
	}
}

// Fix round 1: a secret that JSON escapes (`"`, `\`, `<`, `>`, `&`)
// echoed back from stdin is redacted in every form, everywhere.
func TestHookEchoedSecretRedacted(t *testing.T) {
	f, _, _ := hookFixture(t)
	enableHook(t, f)
	const tok = `p"a\ss<w>&rd-0123456789`
	forms := []string{tok, `p\"a\\ss<w>&rd-0123456789`, `p\"a\\ss<w>&rd-0123456789`}
	var logBuf strings.Builder
	var logMu sync.Mutex
	log.SetOutput(writerFunc(func(b []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logBuf.Write(b)
	}))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	tv := tok
	saveHook(t, f, SettingsUpdate{Secrets: map[string]SecretChange{"token": {Value: &tv}}})
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		if in.Cmd[0] != "/apply" {
			return &docker.ExecResult{Output: []byte("ok"), ExecID: "ok"}, nil
		}
		return &docker.ExecResult{Output: append([]byte("bad input: "), in.Stdin...), ExitCode: 1, ExecID: "echo"}, nil
	})
	res := saveHook(t, f, SettingsUpdate{Values: map[string]json.RawMessage{"quota": raw("4GiB")}})
	u, _ := unit(res.Deliveries, "hook:apply")
	op := f.h.LastOp(hookID)
	if u.OK || op == nil || op.OK {
		t.Fatalf("unit %+v, op %+v", u, op)
	}
	logMu.Lock()
	logged := logBuf.String()
	logMu.Unlock()
	for _, where := range []struct{ name, s string }{{"unit error", u.Error}, {"op record", op.Error}, {"log", logged}, {"status", f.h.DeliveryStatus(hookID).Units["hook:apply"].Error}} {
		if !strings.Contains(where.s, "[redacted]") {
			t.Errorf("%s: nothing redacted: %.300q", where.name, where.s)
		}
		for _, form := range forms {
			if strings.Contains(where.s, form) {
				t.Errorf("%s holds the secret as %q", where.name, form)
			}
		}
	}
}

type writerFunc func([]byte) (int, error)

func (w writerFunc) Write(b []byte) (int, error) { return w(b) }

// Fix round 1: a hostname change whose restart's start hook fails keeps
// its own (successful) hosts record; the instance's record is the hook's.
func TestStartHookFailureKeepsHostsRecord(t *testing.T) {
	f, _, _ := hookFixture(t)
	enableHook(t, f)
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		return &docker.ExecResult{Output: []byte("no\n"), ExitCode: 2, ExecID: "e2"}, nil
	})
	if err := f.h.SetHosts(hookID, map[string]string{"hookapp": "hooks-new.example.org"}, "admin"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if r := f.h.lastHostsOp(hookID); r == nil || !r.OK || r.Op != OpHosts {
		t.Errorf("hosts record = %+v", r)
	}
	if b, err := os.ReadFile(f.h.hostsOpPath(hookID)); err != nil || !strings.Contains(string(b), `"ok": true`) {
		t.Errorf("hosts.json = %s (%v)", b, err)
	}
	if r := f.h.LastOp(hookID); r == nil || r.Op != OpHook || r.OK {
		t.Errorf("instance record = %+v", r)
	}
}

// Fix round 1 (M2, M3): a stuck exec is checked once per run, up to the
// timeout of the hook that timed out; re-queues back off and stop after
// hookStuckRequeues with a failed hook record, until the next trigger.
func TestHookStuckBackoffCapped(t *testing.T) {
	f, _, clk := hookFixture(t)
	enableHook(t, f)
	// warm (2 s) times out and keeps running.
	f.engine.setExec(func(id string, in docker.ExecInput) (*docker.ExecResult, error) {
		if in.Cmd[0] == "/warm" {
			return &docker.ExecResult{ExitCode: -1, TimedOut: true, ExecID: "stuck"}, nil
		}
		return &docker.ExecResult{Output: []byte("ok\n"), ExecID: "x"}, nil
	})
	f.engine.setExecRunning("stuck", true)
	f.h.Deliver(context.Background(), hookID, TriggerRetry) // apply, audit run; warm times out
	f.engine.setExec(nil)
	inspects := func() int {
		f.engine.mu.Lock()
		defer f.engine.mu.Unlock()
		return f.engine.execInspects
	}
	before := inspects()
	rep, _ := f.h.Deliver(context.Background(), hookID, TriggerRetry)
	// Once per run, up to warm's 2 s (3 inspects at hookPoll 1 s), every
	// hook skipped.
	if n := inspects() - before; n != 3 {
		t.Errorf("inspects in one run = %d, want 3", n)
	}
	for _, name := range []string{"hook:apply", "hook:audit", "hook:warm"} {
		if u, _ := unit(rep, name); u.Skipped != SkipPrevRunning {
			t.Errorf("%s = %+v", name, u)
		}
	}
	var delays []time.Duration
	for range 20 {
		ts := clk.pending()
		if len(ts) == 0 {
			break
		}
		delays = append(delays, ts[0].d)
		clk.fire()
		f.h.Wait()
	}
	if len(delays) != hookStuckRequeues {
		t.Errorf("re-queues = %d (%v), want %d", len(delays), delays, hookStuckRequeues)
	}
	if len(delays) > 2 && (delays[0] != busyRetry || delays[1] != 2*busyRetry) {
		t.Errorf("no backoff: %v", delays)
	}
	op := f.h.LastOp(hookID)
	if op == nil || op.OK || op.Op != OpHook || !strings.Contains(op.Error, SkipPrevRunning) {
		t.Errorf("op record after the cap = %+v", op)
	}
	// The next real trigger tries again.
	f.h.Deliver(context.Background(), hookID, TriggerRetry)
	if len(clk.pending()) != 1 {
		t.Error("a new trigger did not re-queue")
	}
}

// Fix round 1 (M4, M5): start hooks skipped at start are forced in the
// re-queued run even when it merges into a higher-ranked trigger, and get
// the trigger they declare.
func TestSkippedStartHookForcedAfterMerge(t *testing.T) {
	f, people, clk := hookFixture(t)
	f.h.deliveryMu.Lock()
	f.h.hookExecs = map[string]timedOutExec{hookID: {execID: "old", timeout: time.Second}}
	f.h.deliveryMu.Unlock()
	f.engine.setExecRunning("old", true)
	enableHook(t, f)
	if runs := hookRuns(t, f, "/warm", 0); len(runs) != 0 {
		t.Fatalf("warm ran while the previous run runs")
	}
	// A membership change merges into the queued start re-run.
	people.addGroup("users_hookapp", "alice", "bob", "dave")
	f.h.TriggerMembershipDelivery()
	if ts := clk.pending(); len(ts) != 1 {
		t.Fatalf("armed timers = %d", len(ts))
	}
	f.engine.setExecRunning("old", false)
	clk.fire()
	f.h.Wait()
	warm := hookRuns(t, f, "/warm", 0)
	if len(warm) != 1 || warm[0].Trigger != "start" {
		t.Errorf("warm runs = %+v (forced, its own trigger start)", warm)
	}
	if apply := hookRuns(t, f, "/apply", 0); len(apply) != 1 || apply[0].Trigger != "membership_change" {
		t.Errorf("apply runs = %+v", apply)
	}
	// M5: a retry sends each hook a trigger it declares.
	n := len(f.engine.ExecCalls())
	f.h.Deliver(context.Background(), hookID, TriggerRetry)
	for cmd, want := range map[string]string{"/warm": "start", "/apply": "settings_change", "/audit": "settings_change"} {
		if runs := hookRuns(t, f, cmd, n); len(runs) != 1 || runs[0].Trigger != want {
			t.Errorf("retry: %s runs = %+v, want trigger %s", cmd, runs, want)
		}
	}

	// A start hook skipped with the directory down is re-queued, forced.
	f2, people2, clk2 := hookFixture(t)
	people2.set(func(p *fakePeople) { p.err = errors.New("directory down") })
	enableHook(t, f2)
	if runs := hookRuns(t, f2, "/apply", 0); len(runs) != 0 {
		t.Fatalf("apply (needs people) ran with the directory down")
	}
	if ts := clk2.pending(); len(ts) != 1 || ts[0].d != settingsDebounce {
		t.Fatalf("directory skip not re-queued: %d timers", len(ts))
	}
	people2.set(func(p *fakePeople) { p.err = nil })
	clk2.fire()
	f2.h.Wait()
	if runs := hookRuns(t, f2, "/apply", 0); len(runs) != 1 || runs[0].Trigger != "start" {
		t.Errorf("after the directory is back: apply runs = %+v", runs)
	}
}
