package hub

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/settings"
)

// fakeClock replaces the delivery engine's timers (afterFunc) and the
// reload grace period (sleep): timers fire only when the test says so.
type fakeClock struct {
	mu     sync.Mutex
	timers []*fakeTimer
	slept  []time.Duration
	// onSleep runs inside sleep (e.g. the container exits meanwhile).
	onSleep func(d time.Duration)
}

type fakeTimer struct {
	d       time.Duration
	f       func()
	stopped bool
	fired   bool
}

func (c *fakeClock) afterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	tm := &fakeTimer{d: d, f: f}
	c.timers = append(c.timers, tm)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !tm.stopped && !tm.fired
		tm.stopped = true
		return was
	}
}

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.slept = append(c.slept, d)
	fn := c.onSleep
	c.mu.Unlock()
	if fn != nil {
		fn(d)
	}
	return nil
}

// pending are the armed timers.
func (c *fakeClock) pending() []*fakeTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*fakeTimer
	for _, tm := range c.timers {
		if !tm.stopped && !tm.fired {
			out = append(out, tm)
		}
	}
	return out
}

// fire runs every armed timer (as time.AfterFunc would: each in its own
// goroutine) and returns how many fired.
func (c *fakeClock) fire() int {
	ts := c.pending()
	c.mu.Lock()
	for _, tm := range ts {
		tm.fired = true
	}
	c.mu.Unlock()
	var wg sync.WaitGroup
	for _, tm := range ts {
		wg.Add(1)
		go func() { defer wg.Done(); tm.f() }()
	}
	wg.Wait()
	return len(ts)
}

const tmID = "tmfixture"

// tmFixture loads testdata/settings/tmfixture (spec call 14, the Time
// Machine case: per-person size_limit into data file people, instance
// greeting (applies reload) and secret api_token into the same file,
// reload HUP) with a fake directory — alice in tm_small, carol in tm_big,
// bob in neither, all three in users_tmfixture; erin outside — and a
// fake clock. The instance is enabled and running.
func tmFixture(t *testing.T) (*fixture, *fakePeople, *fakeClock) {
	t.Helper()
	m := mustRead(t, filepath.Join("testdata", "settings", "tmfixture", "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", "tmfixture", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{tmID: {string(m), string(c)}})
	if f.h.Template(tmID) == nil {
		t.Fatalf("tmfixture not loaded (see the log)")
	}
	f.h.SetAudit(&fakeAudit{})
	people := newFakePeople("erin")
	people.addGroup("users_tmfixture", "alice", "bob", "carol")
	people.addGroup("admin_tmfixture")
	people.addGroup("tm_small", "alice")
	people.addGroup("tm_big", "carol")
	f.h.SetGroups(&fakeGroups{people: people, existing: map[string]bool{"users_tmfixture": true, "admin_tmfixture": true}})
	f.h.SetPeople(people)
	f.h.SetUserSweep(people, nil)
	simulateCompose(f, 0)
	clk := &fakeClock{}
	f.h.afterFunc = clk.afterFunc
	f.h.sleep = clk.sleep
	return f, people, clk
}

// tmConfigure stores the size_limit configuration: 1 GiB by default,
// 10 GiB for tm_small, 500 GiB for tm_big.
func tmConfigure(t *testing.T, f *fixture) *SaveResult {
	t.Helper()
	res, err := f.h.SaveSettings(tmID, SettingsUpdate{Person: map[string]PersonChange{
		"size_limit": {Default: raw("1GiB"), Rows: rows("tm_small", "10GiB", "tm_big", "500GiB")},
	}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (f *fixture) appFile(id, name string) string {
	return filepath.Join(f.project, "appfiles", id, name, name+".json")
}

func readDoc(t *testing.T, path string) settings.DataFileDoc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d settings.DataFileDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, b)
	}
	return d
}

func unit(rep *DeliveryReport, name string) (UnitResult, bool) {
	if rep == nil {
		return UnitResult{}, false
	}
	for _, u := range rep.Units {
		if u.Unit == name {
			return u, true
		}
	}
	return UnitResult{}, false
}

func TestPerPersonFileDelivery(t *testing.T) {
	f, _, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	tmConfigure(t, f)
	f.h.Wait()
	p := f.appFile(tmID, "people")
	d := readDoc(t, p)
	if d.Version != settings.DataFileVersion || d.Instance != tmID {
		t.Errorf("doc header = %d %q", d.Version, d.Instance)
	}
	for user, want := range map[string]float64{"alice": 10240, "carol": 512000, "bob": 1024} {
		if got := d.People[user]["size_limit"]; got != want {
			t.Errorf("people.%s.size_limit = %v, want %v", user, got, want)
		}
	}
	if _, ok := d.People["erin"]; ok {
		t.Error("erin (outside the access group) has a value")
	}
	if d.Entries == nil || d.Groups == nil || d.Values == nil {
		t.Errorf("sections must be objects: %+v", d)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0640 {
		t.Errorf("mode = %v, want 0640", st.Mode().Perm())
	}
	if uid, ok := fileOwner(st); ok && uid != os.Getuid() {
		t.Errorf("owner = %d, want the Hub (%d)", uid, os.Getuid())
	}
	ov, err := os.ReadFile(f.h.overridePath(tmID))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ov), `"/host/project/appfiles/tmfixture/people:/portcullis:ro"`) {
		t.Errorf("override does not mount the data file directory read-only:\n%s", ov)
	}
}

func TestSecretFileSeparate(t *testing.T) {
	f, _, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	const secret = "s3cr3t-token-value"
	v := secret
	if _, err := f.h.SaveSettings(tmID, SettingsUpdate{Secrets: map[string]SecretChange{"api_token": {Value: &v}}}, "admin"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	data, err := os.ReadFile(f.appFile(tmID, "people"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), "api_token") {
		t.Errorf("people.json holds the secret:\n%s", data)
	}
	sp := filepath.Join(f.project, "appfiles", tmID, "people", "people.secrets.json")
	sb, err := os.ReadFile(sp)
	if err != nil {
		t.Fatal(err)
	}
	var sd settings.SecretsFileDoc
	if err := json.Unmarshal(sb, &sd); err != nil || sd.Secrets["api_token"] != secret || sd.Instance != tmID || sd.Version != settings.DataFileVersion {
		t.Errorf("secrets file = %s (%v)", sb, err)
	}
	if st, _ := os.Stat(sp); st == nil || st.Mode().Perm() != 0600 {
		t.Errorf("secrets file mode = %v", st)
	}
	// Nothing about the value in delivered.json or the status.
	dj, _ := os.ReadFile(filepath.Join(f.data, "settings", tmID, "delivered.json"))
	if len(dj) == 0 || strings.Contains(string(dj), secret) {
		t.Errorf("delivered.json = %s", dj)
	}
}

// restarts counts the instance's compose downs (Restart = down + up).
func restarts(f *fixture) int {
	n := 0
	for _, c := range f.runner.Calls() {
		if c == "down:"+ProjectPrefix+tmID {
			n++
		}
	}
	return n
}

func TestMembershipDebounced(t *testing.T) {
	f, people, clk := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	tmConfigure(t, f)
	f.h.Wait()
	before := restarts(f)
	// bob joins tm_big: his size_limit changes.
	people.addGroup("tm_big", "bob")
	for range 5 {
		f.h.TriggerMembershipDelivery()
	}
	ts := clk.pending()
	if len(ts) != 1 || ts[0].d != settingsDebounce {
		t.Fatalf("armed timers = %d (want one, %s)", len(ts), settingsDebounce)
	}
	if !f.h.DeliveryStatus(tmID).Pending {
		t.Error("status not pending while debounced")
	}
	clk.fire()
	f.h.Wait()
	if got := readDoc(t, f.appFile(tmID, "people")).People["bob"]["size_limit"]; got != float64(512000) {
		t.Errorf("bob = %v after the membership delivery", got)
	}
	if n := restarts(f) - before; n != 1 {
		t.Errorf("restarts = %d, want 1 (on_membership_change: restart, folded)", n)
	}
	// Nothing changed: no restart.
	before = restarts(f)
	for range 5 {
		f.h.TriggerMembershipDelivery()
	}
	if n := clk.fire(); n != 1 {
		t.Fatalf("fired %d timers", n)
	}
	f.h.Wait()
	if n := restarts(f) - before; n != 0 {
		t.Errorf("unchanged output restarted %d times", n)
	}
}

func TestUnchangedNotReapplied(t *testing.T) {
	f, _, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	tmConfigure(t, f)
	f.h.Wait()
	p := f.appFile(tmID, "people")
	st1, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	os.Chtimes(p, old, old)
	rep, err := f.h.Deliver(context.Background(), tmID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(p)
	if !st2.ModTime().Equal(old) || st1.Size() != st2.Size() {
		t.Errorf("the file was rewritten (mtime %v)", st2.ModTime())
	}
	if u, ok := unit(rep, "file:people"); !ok || u.Skipped != "unchanged" {
		t.Errorf("report = %+v", rep)
	}
	// A file removed on disk is written again.
	os.Remove(p)
	if _, err := f.h.Deliver(context.Background(), tmID, TriggerRetry); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("missing file not re-delivered: %v", err)
	}
}

func TestReloadSignal(t *testing.T) {
	f, _, clk := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	before := restarts(f)
	res, err := f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "hello")}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	kills := f.engine.Kills()
	if len(kills) != 1 || kills[0] != ProjectPrefix+tmID+"-c:HUP" {
		t.Errorf("kills = %v", kills)
	}
	if len(clk.slept) != 1 || clk.slept[0] != reloadGrace || reloadGrace != 10*time.Second {
		t.Errorf("grace = %v", clk.slept)
	}
	u, ok := unit(res.Deliveries, "reload")
	if !ok || !u.OK || u.Message != "reload signal sent, app still running" {
		t.Errorf("reload unit = %+v (%+v)", u, res.Deliveries)
	}
	if n := restarts(f) - before; n != 0 {
		t.Errorf("a reload-only save restarted %d times", n)
	}
	if got := readDoc(t, f.appFile(tmID, "people")).Values["greeting"]; got != "hello" {
		t.Errorf("greeting = %v", got)
	}

	// Exited after the signal: failed, with an op record.
	clk.onSleep = func(time.Duration) { f.engine.setState(ProjectPrefix+tmID+"-c", docker.State{Running: false}) }
	res, err = f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "hello again")}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := unit(res.Deliveries, "reload"); u.OK || u.Error == "" {
		t.Errorf("exited: reload unit = %+v", u)
	}
	if op := f.h.LastOp(tmID); op == nil || op.Op != OpReload || op.OK {
		t.Errorf("op record = %+v", op)
	}
	// Unhealthy: failed too.
	clk.onSleep = func(time.Duration) {
		f.engine.setState(ProjectPrefix+tmID+"-c", docker.State{Running: true, Health: "unhealthy"})
	}
	res, _ = f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "hello 3")}, "admin")
	if u, _ := unit(res.Deliveries, "reload"); u.OK || !strings.Contains(u.Error, "unhealthy") {
		t.Errorf("unhealthy: reload unit = %+v", u)
	}
	// A running op record is never replaced.
	f.h.opsMu.Lock()
	f.h.ops[tmID] = OpRecord{Op: OpBackup, Running: true}
	f.h.opsMu.Unlock()
	res, _ = f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "hello 4")}, "admin")
	if op := f.h.LastOp(tmID); op == nil || op.Op != OpBackup || !op.Running {
		t.Errorf("running op record replaced: %+v", op)
	}
	f.h.opsMu.Lock()
	delete(f.h.ops, tmID)
	f.h.opsMu.Unlock()

	// Not running: no signal.
	clk.onSleep = nil
	f.engine.mu.Lock()
	for i := range f.engine.containers {
		f.engine.containers[i].State = "exited"
	}
	f.engine.mu.Unlock()
	n := len(f.engine.Kills())
	res, _ = f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "hello 5")}, "admin")
	if len(f.engine.Kills()) != n {
		t.Error("signal sent to a stopped app")
	}
	if u, _ := unit(res.Deliveries, "reload"); u.Skipped != "not running" {
		t.Errorf("not running: reload unit = %+v", u)
	}
}

func TestFilesWrittenBeforeReload(t *testing.T) {
	f, _, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	var order []string
	f.engine.killHook = func(id, sig string) {
		d := readDoc(t, f.appFile(tmID, "people"))
		order = append(order, "kill(greeting="+d.Values["greeting"].(string)+")")
	}
	if _, err := f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "new")}, "admin"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "kill(greeting=new)" {
		t.Errorf("order = %v (the file must be written before the signal)", order)
	}
}

func TestDirectoryDownKeepsLastDelivery(t *testing.T) {
	f, people, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	tmConfigure(t, f)
	f.h.Wait()
	p := f.appFile(tmID, "people")
	before, _ := os.ReadFile(p)
	people.set(func(p *fakePeople) { p.err = errors.New("lldap: connection refused") })
	people.addGroup("tm_big", "bob")
	rep, err := f.h.Deliver(context.Background(), tmID, TriggerMembership)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) || !strings.Contains(string(after), "alice") {
		t.Errorf("people.json changed with the directory down:\n%s", after)
	}
	if u, ok := unit(rep, "file:people"); !ok || u.Skipped != "directory unavailable" {
		t.Errorf("report = %+v", rep)
	}
	if u := f.h.DeliveryStatus(tmID).Units["file:people"]; u.Skipped != "directory unavailable" {
		t.Errorf("status = %+v", u)
	}
	// A restart with the directory down keeps the delivered file too.
	f.h.RestartApp(tmID)
	after, _ = os.ReadFile(p)
	if string(before) != string(after) {
		t.Error("people.json changed by a restart with the directory down")
	}
}

func TestStaleDeliveryDoesNotOverwrite(t *testing.T) {
	f, _, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "a")}, "admin"); err != nil {
		t.Fatal(err)
	}
	blocked, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.h.deliverHook = func(id, stage string) {
		if stage == "built" {
			once.Do(func() {
				close(blocked)
				<-release
			})
		}
	}
	// Run 1 (greeting b) blocks after building its outputs.
	type out struct {
		res *SaveResult
		err error
	}
	first := make(chan out, 1)
	go func() {
		r, err := f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "b")}, "admin")
		first <- out{r, err}
	}()
	<-blocked
	// A newer save commits meanwhile (its delivery waits for the lock).
	second := make(chan out, 1)
	go func() {
		r, err := f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "c")}, "admin")
		second <- out{r, err}
	}()
	for storedSettings(f, tmID).Values["greeting"] != "c" {
		time.Sleep(time.Millisecond)
	}
	if got := readDoc(t, f.appFile(tmID, "people")).Values["greeting"]; got != "a" {
		t.Fatalf("greeting = %v before the stale run resumes", got)
	}
	close(release)
	r1 := <-first
	if r1.err != nil {
		t.Fatal(r1.err)
	}
	if u, ok := unit(r1.res.Deliveries, "file:people"); !ok || u.Skipped != "superseded" {
		t.Errorf("stale run = %+v", r1.res.Deliveries)
	}
	if _, ok := unit(r1.res.Deliveries, "reload"); ok {
		t.Error("the stale run reloaded")
	}
	r2 := <-second
	if r2.err != nil {
		t.Fatal(r2.err)
	}
	f.h.Wait()
	if got := readDoc(t, f.appFile(tmID, "people")).Values["greeting"]; got != "c" {
		t.Errorf("greeting = %v, want the newer save's c", got)
	}
}

func TestDisabledInstanceDeliversNothing(t *testing.T) {
	f, _, _ := tmFixture(t)
	tmConfigure(t, f)
	if _, err := f.h.SaveSettings(tmID, SettingsUpdate{Values: vals("greeting", "hi")}, "admin"); err != nil {
		t.Fatal(err)
	}
	rep, err := f.h.Deliver(context.Background(), tmID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Units) != 0 {
		t.Errorf("disabled instance delivered %+v", rep.Units)
	}
	if _, err := os.Stat(filepath.Join(f.project, "appfiles", tmID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("appfiles written for a disabled instance: %v", err)
	}
	if len(f.engine.Kills()) != 0 || len(f.engine.execCmd) != 0 {
		t.Error("signal or hook for a disabled instance")
	}
	s := storedSettings(f, tmID)
	if s.Values["greeting"] != "hi" || len(s.Person["size_limit"].Rows) != 2 {
		t.Errorf("state not kept: %+v", s)
	}
}

func TestDeleteRemovesSettingsFiles(t *testing.T) {
	f, _, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	tmConfigure(t, f)
	f.h.Wait()
	app := filepath.Join(f.project, "appfiles", tmID)
	set := filepath.Join(f.data, "settings", tmID)
	for _, d := range []string{app, set} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("%s before the delete: %v", d, err)
		}
	}
	if _, err := f.h.DeleteInstance(tmID, tmID, "root"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{app, set} {
		if _, err := os.Stat(d); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after the delete: %v", d, err)
		}
	}
}

// Group records written while the directory was down are delivered once
// it is back (the membership tick re-renders the env).
func TestDirectoryRecoveryRedeliversGroupRecords(t *testing.T) {
	f, _, people := privFixture(t)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	if err := f.h.Enable("privapp"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.save("privapp", SettingsUpdate{Groups: map[string][]GroupValueInput{"libraries": rows("office_milan", []string{"/lib/a"})}}); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	people.set(func(p *fakePeople) { p.err = errors.New("down") })
	f.h.RestartApp("privapp") // env written with no snapshot: no records
	if v := readEnvFile(f.h.envPath("privapp"))["PRIVAPP_LIBRARIES"]; v != "[]" {
		t.Fatalf("env with the directory down = %q", v)
	}
	before := len(f.runner.Calls())
	people.set(func(p *fakePeople) { p.err = nil })
	f.h.TriggerMembershipDelivery()
	clk.fire()
	f.h.Wait()
	if v := readEnvFile(f.h.envPath("privapp"))["PRIVAPP_LIBRARIES"]; !strings.Contains(v, "office_milan") {
		t.Errorf("env after recovery = %q", v)
	}
	if !strings.Contains(strings.Join(f.runner.Calls()[before:], ","), "down:"+ProjectPrefix+"privapp") {
		t.Errorf("no restart after the env changed: %v", f.runner.Calls()[before:])
	}
	if d := readDoc(t, f.appFile("privapp", "libs")); len(d.Groups["libraries"]) != 1 || d.Groups["libraries"][0].Group != "office_milan" {
		t.Errorf("libs groups = %+v", d.Groups)
	}
}

// fileOwner is st's owner uid (ok false where the platform has none).
func fileOwner(st os.FileInfo) (int, bool) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid), true
	}
	return 0, false
}

// P6: compose up writes the data files before compose creates the
// containers; a people file never delivered with the directory down
// fails the start (503), a delivered one is kept.
func TestStartDeliversFilesBeforeCreate(t *testing.T) {
	f, people, _ := tmFixture(t)
	var atCreate []string
	f.runner.createHook = func(project string) {
		_, err := os.Stat(f.appFile(tmID, "people"))
		atCreate = append(atCreate, project+":"+map[bool]string{true: "file", false: "nofile"}[err == nil])
	}
	tmConfigure(t, f) // disabled: stored only
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	if strings.Join(atCreate, ",") != ProjectPrefix+tmID+":file" {
		t.Errorf("at create: %v", atCreate)
	}
	if got := readDoc(t, f.appFile(tmID, "people")).People["alice"]["size_limit"]; got != float64(10240) {
		t.Errorf("alice = %v", got)
	}
	if len(f.engine.Kills()) != 0 {
		t.Error("a start delivery sent a reload signal")
	}

	g, gp, _ := tmFixture(t)
	gp.set(func(p *fakePeople) { p.err = errors.New("lldap down") })
	err := g.h.Enable(tmID)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 503 || g.h.IsEnabled(tmID) {
		t.Fatalf("enable with the directory down and no data file = %v", err)
	}
	if n := len(g.runner.Creates()); n != 0 {
		t.Errorf("compose ran %d times", n)
	}
	_ = people
}

// P5: the engine alone restarts — a restart-effect save restarts once.
func TestSaveRestartsOnce(t *testing.T) {
	f, _, _ := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	before := restarts(f)
	res := tmConfigure(t, f)
	f.h.Wait()
	if n := restarts(f) - before; n != 1 {
		t.Errorf("restarts = %d, want 1", n)
	}
	if u, ok := unit(res.Deliveries, "restart"); !ok || !u.OK || res.Effect != settings.EffectRestart {
		t.Errorf("save = %+v", res)
	}
}

// P20: a run while the instance is busy is skipped and re-queued.
func TestDeliverBusyRequeued(t *testing.T) {
	f, _, clk := tmFixture(t)
	if err := f.h.Enable(tmID); err != nil {
		t.Fatal(err)
	}
	unlock, err := f.h.lockApp(tmID)
	if err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	s := f.h.st.Settings[tmID]
	if s.Values == nil {
		s.Values = map[string]any{}
	}
	s.Values["greeting"] = "queued"
	f.h.st.Settings[tmID] = s
	f.h.mu.Unlock()
	rep, err := f.h.Deliver(context.Background(), tmID, TriggerRetry)
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := unit(rep, "delivery"); !ok || u.Skipped != "busy" || len(rep.Units) != 1 {
		t.Errorf("busy run = %+v", rep)
	}
	if ts := clk.pending(); len(ts) != 1 || ts[0].d != busyRetry {
		t.Fatalf("re-queue timers = %+v", ts)
	}
	unlock()
	clk.fire()
	f.h.Wait()
	if got := readDoc(t, f.appFile(tmID, "people")).Values["greeting"]; got != "queued" {
		t.Errorf("greeting = %v after the re-queued run", got)
	}
}
