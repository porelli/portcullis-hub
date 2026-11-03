package hub

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/templates"
)

// Final whole-branch review fixes (hub items H7-H18).

// sharedRoleField publishes a shared field grafana_role (header
// X-Forwarded-Attr-Grafana-Role, the header dash delivers) with a
// delegate-set value Admin for alice.
func sharedRoleField(f *fixture) {
	attrs := policy.BuildUserAttributes([]policy.AttrField{{Name: "grafana_role"}}, map[string]map[string][]string{"alice": {"grafana_role": {"Admin"}}}, nil)
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, &attrs, nil
	}, nil)
}

// H7: a freshly enabled instance whose first header delivery has not run
// (the directory is down) still declares its header on every gated
// host, so group-gate drops the same-named shared-field header there.
func TestFieldHeaderNeverReachesFreshInstance(t *testing.T) {
	f, people, _ := headerFixture(t, nil)
	sharedRoleField(f)
	people.set(func(p *fakePeople) { p.err = errors.New("lldap down") })
	if _, err := f.h.EnableAs(headerID, "root"); err != nil {
		t.Fatal(err)
	}
	settle(f)
	f.h.writePolicyLogged()
	doc, ok := readAttrs(t, f)
	if !ok {
		t.Fatal("no user-attributes.json")
	}
	for _, host := range []string{headerMain, headerExtra} {
		vals, declared := doc.Hosts[host][hdrSuffix]
		if !declared || len(vals) != 0 {
			t.Errorf("%s %s = %v (declared %v), want declared with no values", host, hdrSuffix, vals, declared)
		}
	}
	if _, ok := doc.Hosts[headerStatus]; ok {
		t.Errorf("the ungated host %s is declared: %v", headerStatus, doc.Hosts)
	}
	if doc.Fields["grafana_role"] == "" {
		t.Errorf("fields = %v: the shared field is still published for other hosts", doc.Fields)
	}
}

// H7: when the instance's gated hosts can't be resolved, the colliding
// shared-field header is not published at all (fail closed).
func TestFieldHeaderSuppressedWhenHostsUnknown(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	sharedRoleField(f)
	headerEnable(t, f)
	if doc, _ := readAttrs(t, f); doc.Fields["grafana_role"] == "" {
		t.Fatalf("fields = %v, want grafana_role published", doc.Fields)
	}
	f.h.mu.RLock()
	path := f.h.findLocked(headerID).ComposePath()
	f.h.mu.RUnlock()
	if err := os.WriteFile(path, []byte("services: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The directory state down (the kept file's fields and users).
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, nil, errors.New("directory publish failed")
	}, nil)
	f.h.writePolicyLogged()
	doc, _ := readAttrs(t, f)
	if _, ok := doc.Fields["grafana_role"]; ok {
		t.Errorf("kept file: fields = %v, want grafana_role suppressed while dash-b's hosts are unknown", doc.Fields)
	}
	if v, ok := doc.Users["alice"]["grafana_role"]; ok {
		t.Errorf("kept file: alice's grafana_role = %v still published", v)
	}
	// The directory back: still suppressed.
	sharedRoleField(f)
	f.h.writePolicyLogged()
	doc, _ = readAttrs(t, f)
	if _, ok := doc.Fields["grafana_role"]; ok {
		t.Errorf("fields = %v: grafana_role published while dash-b's hosts are unknown", doc.Fields)
	}
	if v, ok := doc.Users["alice"]["grafana_role"]; ok {
		t.Errorf("alice's grafana_role = %v still published", v)
	}
}

// H8: an account deleted and re-created under the same name inside one
// debounce window (a new LLDAP uuid, its attributes gone with the old
// account) gets its claim written again, though its value is unchanged.
func TestClaimRewrittenForRecreatedAccount(t *testing.T) {
	f, people, store := claimFixture(t)
	quota := SettingAttr(claimID, "storage_quota")
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	if got := store.values["dave"][quota]; len(got) != 1 {
		t.Fatalf("dave's quota = %v before the re-creation", got)
	}
	people.recreate("dave")
	people.addGroup("users_immich", "dave")
	store.mu.Lock()
	delete(store.values, "dave")
	store.mu.Unlock()
	before := len(store.calls())
	deliverNow(t, f, claimID, TriggerMembership)
	calls := store.calls()[before:]
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "dave +") || !strings.Contains(calls[0], quota+"=100") {
		t.Errorf("writes after dave's re-creation = %q, want dave's quota written", calls)
	}
	// Then unchanged.
	before = len(store.calls())
	deliverNow(t, f, claimID, TriggerMembership)
	if n := len(store.calls()) - before; n != 0 {
		t.Errorf("an unchanged run wrote %d times: %q", n, store.calls()[before:])
	}
}

// H13: a template update renames a secret option's env variable, then
// removes the option: neither Expert Env nor a backup's config/env ever
// shows the old line's value, and the prune blanks it in the .env.
func TestSecretEnvLineAfterTemplateUpdate(t *testing.T) {
	f, _ := secretFixture(t)
	const val = "s3cr3t-old-line"
	saveSecret(t, f, "secretapp", "api_key", setSecret(val))
	if err := f.h.Enable("secretapp"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	manifest := filepath.Join(f.src, "secretapp", "manifest.yaml")
	m := string(mustRead(t, manifest))
	renamed := strings.Replace(m, "{env: HEADSCALE_API_KEY}", "{env: HEADSCALE_KEY}", 1)
	writeFile(t, manifest, renamed)
	composePath := filepath.Join(f.src, "secretapp", "compose.yml")
	writeFile(t, composePath, strings.ReplaceAll(string(mustRead(t, composePath)), "HEADSCALE_API_KEY", "HEADSCALE_KEY"))
	f.h.Discover()
	if optionByKey(f.h.Template("secretapp"), "api_key") == nil {
		t.Fatal("rename not loaded")
	}
	f.h.pruneSettings()
	checkEnv := func(when string) {
		t.Helper()
		vars, _, err := f.h.Env("secretapp")
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range vars {
			if strings.Contains(v, val) {
				t.Errorf("%s: Expert Env shows %s=%q", when, k, v)
			}
		}
		entry, err := f.h.BackupInstance("secretapp", "root")
		if err != nil {
			t.Fatal(err)
		}
		_, data, _ := readArchive(t, archivePath(f, entry.Archive))
		for name, b := range data {
			if name != secretsMember && bytes.Contains(b, []byte(val)) {
				t.Errorf("%s: archive member %s holds the secret", when, name)
			}
		}
	}
	checkEnv("renamed")
	// Removed (and api_url's requires with it): the prune drops the
	// stored value and blanks its old .env line first.
	removed := strings.Replace(renamed, "    - key: api_key\n      label: API key\n      type: secret\n      applies: restart\n      delivery: [{env: HEADSCALE_KEY}]\n", "", 1)
	removed = strings.Replace(removed, "      requires: [api_key]\n", "", 1)
	writeFile(t, manifest, removed)
	f.h.Discover()
	if optionByKey(f.h.Template("secretapp"), "api_key") != nil {
		t.Fatal("update not loaded")
	}
	f.h.pruneSettings()
	if _, ok := storedSecrets(t, f, "secretapp")["api_key"]; ok {
		t.Fatal("the prune kept the dropped secret")
	}
	if b, _ := os.ReadFile(f.h.envPath("secretapp")); bytes.Contains(b, []byte(val)) {
		t.Errorf("the .env still holds the dropped secret:\n%s", b)
	}
	checkEnv("removed")
}

// H14: a restart owed by a committed save survives a Hub restart: it is
// recorded in delivered.json before it is queued, Init re-queues it,
// and the restart's finishOp clears it.
func TestOwedRestartSurvivesHubRestart(t *testing.T) {
	f, _ := secretFixture(t)
	clk := &fakeClock{}
	f.h.afterFunc, f.h.sleep = clk.afterFunc, clk.sleep
	f.clk = clk
	const id = "secretapp"
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	unlock, err := f.h.lockApp(id)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	saveSecret(t, f, id, "api_key", setSecret("owed-1"))
	f.h.Wait()
	if got := f.h.loadDelivered(id).Owed; got != settings.EffectRestart {
		t.Fatalf("owed = %q while the app is busy, want %q", got, settings.EffectRestart)
	}
	// The Hub restarts before the busy retry fires.
	before := len(f.runner.Calls())
	h2, err := New(Config{ProjectDir: f.project, ProjectHostDir: "/host/project", DataDir: f.data, Domain: "example.org"}, f.runner, f.engine, f.idp)
	if err != nil {
		t.Fatal(err)
	}
	h2.lockPoll = 5 * time.Millisecond
	h2.SetGroups(&fakeGroups{})
	h2.afterFunc, h2.sleep = clk.afterFunc, clk.sleep
	h2.Init()
	h2.Wait()
	calls := strings.Join(f.runner.Calls()[before:], " ")
	if !strings.Contains(calls, "down:"+projectName(id)) || !strings.Contains(calls, "up:"+projectName(id)) {
		t.Errorf("compose calls after the Hub restart = %q, want the owed restart", calls)
	}
	if got := h2.loadDelivered(id).Owed; got != "" {
		t.Errorf("owed = %q after the restart, want cleared", got)
	}
	if r := h2.LastOp(id); r == nil || r.Op != OpRestart || !r.OK {
		t.Errorf("last op = %+v, want a successful restart", r)
	}
}

// H14: a restart that gives up waiting for the app lock records a failed
// restart op, and the restart stays owed.
func TestRestartGivingUpRecordsFailure(t *testing.T) {
	f, _ := secretFixture(t)
	const id = "secretapp"
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	f.h.setOwed(id, settings.EffectRestart)
	unlock, err := f.h.lockApp(id)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	f.h.restartWait = 20 * time.Millisecond
	f.h.Restart(*f.h.Template(id))
	r := f.h.LastOp(id)
	if r == nil || r.Op != OpRestart || r.OK || !strings.Contains(r.Error, "gave up") {
		t.Errorf("last op = %+v, want a failed restart that gave up", r)
	}
	if got := f.h.loadDelivered(id).Owed; got != settings.EffectRestart {
		t.Errorf("owed = %q after giving up, want still %q", got, settings.EffectRestart)
	}
}

// H7 (follow-up): an enabled instance whose template went missing is
// enforced from its published snapshot, which keeps its header suffixes:
// they stay declared, with no values, on the snapshot's hosts, so the
// same-named shared-field header never reaches them.
func TestFieldHeaderSuppressedTemplateMissing(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	sharedRoleField(f)
	headerEnable(t, f)
	f.h.mu.RLock()
	snap := f.h.st.Published[headerID]
	f.h.mu.RUnlock()
	if len(snap.HeaderSuffixes) != 1 || snap.HeaderSuffixes[0] != hdrSuffix {
		t.Errorf("published header suffixes = %v, want [%s]", snap.HeaderSuffixes, hdrSuffix)
	}
	if err := os.RemoveAll(filepath.Join(f.src, headerTemplate)); err != nil {
		t.Fatal(err)
	}
	f.h.Discover()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	doc, _ := readAttrs(t, f)
	for _, host := range []string{headerMain, headerExtra} {
		vals, declared := doc.Hosts[host][hdrSuffix]
		if !declared || len(vals) != 0 {
			t.Errorf("%s %s = %v (declared %v), want declared with no values", host, hdrSuffix, vals, declared)
		}
	}
}

// H15: a restart prepares the up (override, .env, data files) before it
// stops anything: a refusal there (a data file that needs people, never
// delivered, the directory down) leaves the app running.
func TestRestartRefusalLeavesAppRunning(t *testing.T) {
	f, _, people := privFixture(t)
	const id = "privapp"
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if err := os.Remove(f.h.dataFilePath(id, "libs")); err != nil {
		t.Fatal(err)
	}
	people.set(func(p *fakePeople) { p.err = errors.New("lldap down") })
	before := len(f.runner.Calls())
	err := f.h.RestartApp(id)
	if statusOf(err) != 503 {
		t.Fatalf("RestartApp = %v, want 503", err)
	}
	if calls := f.runner.Calls()[before:]; len(calls) != 0 {
		t.Errorf("compose calls of a refused restart = %v, want none (the app left running)", calls)
	}
}

// H15: a stored value one env delivery can't carry (a template update
// added it) is written empty for that variable only, logged and shown
// in the panel's deliveries; every other variable is written and the
// app still starts.
func TestOptionEnvFailsClosedPerVariable(t *testing.T) {
	f, _, _ := privFixture(t)
	const id = "privapp"
	if _, err := f.h.SaveSettings(id, SettingsUpdate{Values: vals("motd", "hello", "banner", "world")}, "root"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	const bad = "it's here"
	f.h.mu.Lock()
	s := f.h.st.Settings[id].Clone()
	s.Values["motd"] = bad
	f.h.st.Settings[id] = s
	f.h.mu.Unlock()
	if err := f.h.RestartApp(id); err != nil {
		t.Fatalf("RestartApp = %v, want the app started", err)
	}
	env := composeReads(t, f.h.envPath(id))
	if v, ok := env["PRIVAPP_MOTD"]; !ok || v != "" {
		t.Errorf("PRIVAPP_MOTD = %q (present %v), want written empty", v, ok)
	}
	if env["PRIVAPP_BANNER"] != "world" {
		t.Errorf("PRIVAPP_BANNER = %q, want world", env["PRIVAPP_BANNER"])
	}
	u, ok := f.h.DeliveryStatus(id).Units[unitEnvValues]
	if !ok || !strings.Contains(u.Error, "motd") || strings.Contains(u.Error, bad) || strings.Contains(u.Error, "banner") {
		t.Errorf("unit %s = %+v (%v), want an error naming motd only, no value", unitEnvValues, u, ok)
	}
}

// H16: a save never waits for a delivery in progress (a long hook holds
// the delivery lock): it answers at once with a busy unit, and its
// delivery — with the save's effect — runs once the lock is free.
func TestSaveNeverBlocksOnDeliveryLock(t *testing.T) {
	f, _, _ := privFixture(t)
	const id = "privapp"
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	l := f.h.deliverLock(id)
	l.Lock()
	type result struct {
		res *SaveResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := f.h.SaveSettings(id, SettingsUpdate{Values: vals("motd", "busy save")}, "root")
		done <- result{res, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-time.After(5 * time.Second):
		l.Unlock()
		t.Fatal("SaveSettings waited for the delivery lock")
	}
	before := len(f.runner.Calls())
	l.Unlock()
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.res.Deliveries == nil {
		t.Fatal("no deliveries in the answer")
	}
	if u, ok := unit(r.res.Deliveries, unitBusy); !ok || u.Skipped != SkipBusy {
		t.Errorf("deliveries = %+v, want a busy unit", r.res.Deliveries.Units)
	}
	f.h.Wait()
	calls := strings.Join(f.runner.Calls()[before:], " ")
	if !strings.Contains(calls, "down:portcullis-"+id) || !strings.Contains(calls, "up:portcullis-"+id) {
		t.Errorf("compose calls after the lock was freed = %q, want the save's restart", calls)
	}
}

// H2 (defence in depth): group records of a secret option are refused
// even if a template slipped past the validator.
func TestGroupSecretRecordsRefused(t *testing.T) {
	tm := &templates.Template{ID: "x"}
	tm.Manifest.Settings = &templates.SettingsSpec{Options: []templates.Option{
		{Key: "token", Label: "Token", Type: templates.TypeSecret, Scope: templates.ScopeGroup, Delivery: templates.Deliveries{{Env: "TOKEN", Render: &templates.Render{Format: templates.RenderJSON}}}},
	}}
	_, err := parseSettings(tm, settings.NewRegistry(), nil, SettingsUpdate{Groups: map[string][]GroupValueInput{"token": {{Group: "editors", Value: raw("s3cret")}}}})
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("parseSettings = %v, want 400 refusing a secret's group records (no value)", err)
	}
}

// H4: group env records keep & < > as they are (no &, which env
// would refuse), and a JSON escape is named as such.
func TestGroupEnvNoHTMLEscape(t *testing.T) {
	o := &templates.Option{Key: "team", Type: templates.TypeString, Scope: templates.ScopeGroup, Delivery: templates.Deliveries{{Env: "TEAM", Render: &templates.Render{Format: templates.RenderJSON}}}}
	env, err := renderGroupEnv(o, []settings.Row{{Group: "rd", Value: "R&D <x>"}})
	if err != nil || env["TEAM"] != `[{"group":"rd","value":"R&D <x>"}]` {
		t.Errorf("renderGroupEnv = %q, %v", env["TEAM"], err)
	}
	_, err = renderGroupEnv(o, []settings.Row{{Group: "rd", Value: `say "hi"`}})
	if err == nil || !strings.Contains(err.Error(), "JSON escapes") {
		t.Errorf("renderGroupEnv with a double quote = %v, want the JSON escaping named", err)
	}
}
