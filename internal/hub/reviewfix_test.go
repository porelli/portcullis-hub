package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
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

// H9: a membership change that removes someone from a group runs the
// headers unit at once (a demotion never waits out the debounce); the
// rest of the delivery stays debounced.
func TestMembershipRemovalRunsHeadersNow(t *testing.T) {
	f, people, _ := headerFixture(t, nil)
	headerEnable(t, f)
	f.h.TriggerMembershipDelivery() // the snapshot removals are judged against
	f.h.Wait()
	if got := attrHosts(t, f)[headerMain][hdrSuffix]["carol"]; got != "Editor" {
		t.Fatalf("carol = %q, want Editor", got)
	}
	people.removeMember("editors", "carol")
	f.h.TriggerMembershipDelivery()
	f.h.Wait() // the debounce timer is not fired
	if got := attrHosts(t, f)[headerMain][hdrSuffix]["carol"]; got != "Viewer" {
		t.Errorf("carol = %q right after her removal, want Viewer (not after the debounce)", got)
	}
	if !f.h.DeliveryStatus(headerID).Pending {
		t.Error("the debounced membership delivery is not queued any more")
	}
	// An addition waits for the debounce.
	people.addGroup("editors", "alice")
	f.h.TriggerMembershipDelivery()
	f.h.Wait()
	if got := attrHosts(t, f)[headerMain][hdrSuffix]["alice"]; got != "Viewer" {
		t.Errorf("alice = %q before the debounce, want Viewer (only removals run at once)", got)
	}
}

// H10: LLDAP answering without a uuid never purges a stored value, and a
// save is refused (503) rather than stored unbound.
func TestEmptyUUIDNeitherPurgesNorStores(t *testing.T) {
	f, people, _, _ := entryFixture(t)
	mustSetEntry(t, f, entryID, "ext_id", "alice", aliceExt, "alice")
	settle(f)
	people.set(func(p *fakePeople) {
		if p.uuids == nil {
			p.uuids = map[string]string{}
		}
		p.uuids["alice"] = ""
		p.uuids["bob"] = ""
	})
	deliverNow(t, f, entryID, TriggerMembership)
	if _, ok := storedSettings(f, entryID).Entered["ext_id"]["alice"]; !ok {
		t.Error("alice's value was purged because LLDAP gave no uuid")
	}
	_, err := setEntry(f, entryID, "ext_id", "bob", bobExt, "bob")
	if statusOf(err) != 503 {
		t.Errorf("a save without a uuid = %v, want 503", err)
	}
	if _, ok := storedSettings(f, entryID).Entered["ext_id"]["bob"]; ok {
		t.Error("bob's value stored without a uuid")
	}
}

// H11: a person-entered value is refused at save when its claim's
// json_type can't take it, or when its header value holds a ',' (an app
// splitting list headers would read two values).
func TestEntryDeliverableClaimAndHeader(t *testing.T) {
	claim := &templates.Option{Key: "n", Type: templates.TypeInt, Scope: templates.ScopePersonEntered, Delivery: templates.Deliveries{{Claim: &templates.ClaimDelivery{Client: "app", Name: "n", JSONType: "int"}}}}
	if err := entryDeliverable(claim, int64(9999999999)); err == nil || !strings.Contains(err.Error(), "32-bit") {
		t.Errorf("an int over 32 bits for a json_type int claim = %v, want refused", err)
	}
	if err := entryDeliverable(claim, int64(42)); err != nil {
		t.Errorf("42 = %v", err)
	}
	hdr := &templates.Option{Key: "team", Type: templates.TypeString, Scope: templates.ScopePersonEntered, Delivery: templates.Deliveries{{Header: &templates.HeaderDelivery{Name: "X-Forwarded-Attr-Team"}}}}
	if err := entryDeliverable(hdr, "x, admins"); err == nil || !strings.Contains(err.Error(), ",") {
		t.Errorf("a header value with a comma = %v, want refused", err)
	}
	if err := entryDeliverable(hdr, "red team"); err != nil {
		t.Errorf("red team = %v", err)
	}
}

// H9 (follow-up): immediate header runs queued behind one another read
// the directory only once they hold the delivery lock: while the test
// holds it, the only directory reads are the removal checks; each run
// then reads it again (an older snapshot can never be published last).
func TestHeadersNowNeverPublishOlderMembership(t *testing.T) {
	f, people, _ := headerFixture(t, nil)
	headerEnable(t, f)
	f.h.TriggerMembershipDelivery()
	f.h.Wait()
	calls := func() int {
		people.mu.Lock()
		defer people.mu.Unlock()
		return people.calls
	}
	l := f.h.deliverLock(headerID)
	l.Lock()
	start := calls()
	people.removeMember("editors", "carol")
	f.h.TriggerMembershipDelivery() // run A, waiting for the lock
	people.removeMember("admin_dash-b", "bob")
	f.h.TriggerMembershipDelivery() // run B, waiting for the lock
	time.Sleep(50 * time.Millisecond)
	if n := calls() - start; n != 2 {
		l.Unlock()
		t.Fatalf("%d directory reads while the lock was held, want 2 (the removal checks only)", n)
	}
	held := calls()
	l.Unlock()
	f.h.Wait()
	if n := calls() - held; n != 2 {
		t.Errorf("%d directory reads by the two runs once the lock was free, want 2 (each reads it under the lock)", n)
	}
	got := attrHosts(t, f)[headerMain][hdrSuffix]
	if got["carol"] != "Viewer" || got["bob"] != "Viewer" {
		t.Errorf("published = %v, want carol and bob Viewer (the newest membership)", got)
	}
}

// teamHeader adds a person_entered header option team to headerapp.
func teamHeader(m string) string {
	return m + `    - key: team
      label: Team
      type: string
      max_len: 40
      scope: person_entered
      applies: next_request
      delivery: [{header: {name: X-Forwarded-Attr-Team}}]
`
}

// H11 (follow-up): a stored person-entered value holding ',' (stored
// before the rule, or restored) never reaches a header, and the prune
// invalidates it (audited).
func TestStoredEntryCommaNeverInHeader(t *testing.T) {
	f, people, _ := headerFixture(t, teamHeader)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	headerEnable(t, f)
	f.h.mu.Lock()
	s := f.h.st.Settings[headerID].Clone()
	s.Entered = map[string]map[string]state.EnteredValue{"team": {
		"alice": {Value: "x, admins", UUID: people.uuidOf("alice"), UpdatedAt: time.Now().UTC()},
		"bob":   {Value: "blue", UUID: people.uuidOf("bob"), UpdatedAt: time.Now().UTC()},
	}}
	f.h.st.Settings[headerID] = s
	f.h.mu.Unlock()
	deliverNow(t, f, headerID, TriggerRetry)
	got := attrHosts(t, f)[headerMain]["Team"]
	if _, ok := got["alice"]; ok || got["bob"] != "blue" {
		t.Errorf("Team = %v, want bob's only (alice's holds a ',')", got)
	}
	f.h.pruneSettings()
	if _, ok := storedSettings(f, headerID).Entered["team"]["alice"]; ok {
		t.Error("the prune kept alice's undeliverable value")
	}
	if _, ok := storedSettings(f, headerID).Entered["team"]["bob"]; !ok {
		t.Error("the prune dropped bob's value")
	}
	found := false
	for _, e := range auditsOf(audit, "settings.person_value") {
		if e.Target == headerID+"/team/alice" && e.Detail == "invalidated" {
			found = true
		}
	}
	if !found {
		t.Error("no settings.person_value invalidated audit for alice")
	}
}

// ── H17 (delivery engine minors) ──

// H17: SaveEnv's read-modify-write of the .env holds mu (every other
// .env writer does).
func TestSaveEnvHoldsMu(t *testing.T) {
	f, _ := immichFixture(t)
	f.h.mu.RLock() // a reader: SaveEnv's write must wait for it
	done := make(chan error, 1)
	go func() { done <- f.h.SaveEnv("immich", map[string]string{"FREE_VAR": "x"}) }()
	select {
	case err := <-done:
		f.h.mu.RUnlock()
		t.Fatalf("SaveEnv finished (%v) while mu was held", err)
	case <-time.After(100 * time.Millisecond):
	}
	f.h.mu.RUnlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if composeReads(t, f.h.envPath("immich"))["FREE_VAR"] != "x" {
		t.Error("FREE_VAR not written")
	}
}

// H17: the op record in memory and on disk are written together (under
// opsMu) by both writers: after racing writes they agree.
func TestOpRecordMemoryMatchesFile(t *testing.T) {
	f, _ := secretFixture(t)
	const id = "secretapp"
	for i := 0; i < 50; i++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			f.h.recordOp(id, OpRecord{Op: OpRestart, OpID: "op", At: time.Now().UTC(), Running: true})
		}()
		go func() {
			defer wg.Done()
			f.h.finishDeliveryOp(id, OpHook, errors.New("hook failed"))
		}()
		wg.Wait()
		f.h.opsMu.Lock()
		mem := f.h.ops[id]
		f.h.opsMu.Unlock()
		b, err := os.ReadFile(f.h.opPath(id))
		if err != nil {
			t.Fatal(err)
		}
		var disk OpRecord
		if err := json.Unmarshal(b, &disk); err != nil {
			t.Fatal(err)
		}
		if mem.Op != disk.Op || mem.Running != disk.Running {
			t.Fatalf("round %d: memory %s running=%v, file %s running=%v", i, mem.Op, mem.Running, disk.Op, disk.Running)
		}
	}
}

// H17: with a template view, a backup blanks by value only variables the
// template doesn't declare (an orphan line a template update left):
// PUID=1000 stays when a secret happens to be 1000.
func TestBackupBlanksByValueOnlyOrphans(t *testing.T) {
	f, _ := secretFixture(t)
	const id = "secretapp"
	saveSecret(t, f, id, "api_key", setSecret("1000"))
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	// PUID: declared (a compose reference); OLD_KEY: an orphan.
	cp := filepath.Join(f.src, "secretapp", "compose.yml")
	writeFile(t, cp, strings.Replace(string(mustRead(t, cp)), "      API_KEY: ${HEADSCALE_API_KEY}\n", "      API_KEY: ${HEADSCALE_API_KEY}\n      PUID: ${PUID:-1000}\n", 1))
	f.h.Discover()
	if err := f.h.SaveEnv(id, map[string]string{"PUID": "1000", "OLD_KEY": "1000"}); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance(id, "root")
	if err != nil {
		t.Fatal(err)
	}
	_, data, _ := readArchive(t, archivePath(f, entry.Archive))
	env := string(data["config/env"])
	if !strings.Contains(env, "\nPUID=1000\n") {
		t.Errorf("PUID blanked:\n%s", env)
	}
	if !strings.Contains(env, "\nOLD_KEY=\n") || !strings.Contains(env, "\nHEADSCALE_API_KEY=\n") {
		t.Errorf("the secret's lines not blanked:\n%s", env)
	}
}

// H17: hook output a Python hook printed with json.dumps (ensure_ascii)
// is redacted too.
func TestRedactsASCIIEscapedSecret(t *testing.T) {
	f, _ := secretFixture(t)
	const val = "pässwört-€-😀"
	saveSecret(t, f, "secretapp", "api_key", setSecret(val))
	// Python's json.dumps(..., ensure_ascii=True): lowercase \uXXXX,
	// surrogate pairs past the BMP.
	out := f.h.secretRedactor("secretapp", nil)(`{"api_key": "p\u00e4ssw\u00f6rt-\u20ac-\ud83d\ude00"}`)
	if strings.Contains(out, `ssw`) {
		t.Errorf("not redacted: %s", out)
	}
}

// H17: a committed save whose .env write failed still delivers; the
// error is a warning.
func TestCommittedSaveWithEnvFailureDelivers(t *testing.T) {
	f, _, _ := privFixture(t)
	const id = "privapp"
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	dir := filepath.Dir(f.h.envPath(id))
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	res, err := f.h.SaveSettings(id, SettingsUpdate{Values: vals("motd", "hello")}, "root")
	os.Chmod(dir, 0o755)
	if err != nil {
		t.Fatalf("SaveSettings = %v, want the committed save answered with a warning", err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "env") || res.Deliveries == nil {
		t.Errorf("warnings %v, deliveries %+v: want the env failure as a warning and the delivery run", res.Warnings, res.Deliveries)
	}
	f.h.Wait()
}

// H17: an instance stuck in a pending state (a failed delete) gets no
// delivery re-queued forever.
func TestNoRequeueWhilePending(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	f.h.mu.Lock()
	f.h.st.Instances[headerID] = state.Instance{Template: f.h.st.Instances[headerID].Template, State: state.InstanceDeleting}
	f.h.mu.Unlock()
	rep := deliverNow(t, f, headerID, TriggerRetry)
	if u, ok := unit(rep, unitBusy); !ok || u.Skipped == "" {
		t.Errorf("units = %+v, want the run skipped", rep.Units)
	}
	if f.h.DeliveryStatus(headerID).Pending {
		t.Error("a delivery is re-queued for a pending (deleting) instance")
	}
}

// H17: forgetDeliveries drops every per-instance engine map.
func TestForgetDeliveriesClearsHookState(t *testing.T) {
	f, _ := secretFixture(t)
	const id = "secretapp"
	f.h.deliveryMu.Lock()
	f.h.hookStuck = map[string]int{id: 2}
	f.h.hookExecs = map[string]timedOutExec{id: {execID: "x"}}
	f.h.lastTrigger = map[string]Trigger{id: TriggerRetry}
	f.h.deliveryMu.Unlock()
	if err := f.h.forgetDeliveries(id); err != nil {
		t.Fatal(err)
	}
	f.h.deliveryMu.Lock()
	defer f.h.deliveryMu.Unlock()
	if _, a := f.h.hookStuck[id]; a {
		t.Error("hookStuck kept")
	}
	if _, b := f.h.hookExecs[id]; b {
		t.Error("hookExecs kept")
	}
	if _, c := f.h.lastTrigger[id]; c {
		t.Error("lastTrigger kept")
	}
}

// H17: a source sync that changes an enabled instance's delivery
// generation queues its delivery.
func TestSourceSyncQueuesDelivery(t *testing.T) {
	f := newSyncFixture(t, grafanaManifest)
	h := f.start(t, false)
	h.Wait()
	var mu sync.Mutex
	runs := map[string]int{}
	h.deliverHook = func(id, stage string) {
		if stage == "built" {
			mu.Lock()
			runs[id]++
			mu.Unlock()
		}
	}
	f.commit(t, strings.Replace(grafanaManifest, "label: Theme\n", "label: Colour theme\n", 1))
	if err := h.SyncSources(); err != nil {
		t.Fatal(err)
	}
	h.Wait()
	mu.Lock()
	defer mu.Unlock()
	if runs["grafana"] == 0 {
		t.Error("no delivery after the sync changed grafana's generation")
	}
}

// H17: the delivery generation covers the population's inputs (group
// access, the access role, public mode, the policy).
func TestDeliveryGenCoversPopulationInputs(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	gen := func() string {
		f.h.mu.RLock()
		defer f.h.mu.RUnlock()
		return f.h.deliveryGenLocked(f.h.findLocked(headerID))
	}
	before := gen()
	f.h.mu.Lock()
	f.h.st.AuthPolicies[headerID] = policy.AuthPolicy{Factors: []string{"passkey"}}
	f.h.mu.Unlock()
	if gen() == before {
		t.Error("the generation ignores the instance's policy")
	}
}

// H17: setEnvVars updates every line of a duplicated key (compose reads
// the last one).
func TestSetEnvVarsUpdatesDuplicates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.env")
	if err := os.WriteFile(p, []byte("A=1\nB=2\nA=3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setEnvVars(p, map[string]string{"A": "9"}, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "A=9\nB=2\nA=9\n" {
		t.Errorf(".env = %q", b)
	}
}

// H18: a failed unit is logged when its error changes, not on every run.
func TestFailedUnitLoggedOnChange(t *testing.T) {
	buf := captureLog(t)
	d := deliveredDoc{Hashes: map[string]string{}, Status: map[string]UnitResult{}}
	fail := func(msg string) { recordUnits("app", &d, []UnitResult{{Unit: "file:people", Error: msg}}) }
	fail("disk full")
	fail("disk full")
	fail("permission denied")
	out := buf.String()
	if n := strings.Count(out, "disk full"); n != 1 {
		t.Errorf("logged %d times, want once:\n%s", n, out)
	}
	if !strings.Contains(out, "permission denied") {
		t.Errorf("the changed error is not logged:\n%s", out)
	}
}

// Follow-up to H16: the panel's Retry never waits for a delivery in
// progress either: busy = queued (TriggerRetry), answered as a busy unit.
func TestRetryNeverBlocksOnDeliveryLock(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	headerEnable(t, f)
	f.h.Wait()
	var ran atomic.Bool
	f.h.deliverHook = func(id, stage string) {
		if id == headerID && stage == "built" {
			ran.Store(true)
		}
	}
	l := f.h.deliverLock(headerID)
	l.Lock()
	done := make(chan *DeliveryReport, 1)
	go func() {
		rep, _ := f.h.RetryDeliveries(context.Background(), headerID, "admin")
		done <- rep
	}()
	var rep *DeliveryReport
	select {
	case rep = <-done:
	case <-time.After(5 * time.Second):
		l.Unlock()
		t.Fatal("RetryDeliveries waited for the delivery lock")
	}
	l.Unlock()
	if u, ok := unit(rep, unitBusy); !ok || u.Skipped != SkipBusy {
		t.Errorf("units = %+v, want a busy unit", rep.Units)
	}
	f.h.Wait()
	if !ran.Load() {
		t.Error("the queued retry did not run once the lock was free")
	}
}

// ── Residual pass ──

// Residual I1: the Expert round trip of a variable masked by value: an
// undeclared copy of a secret (MY_COPY=1000) posted back as [set] stays
// as it is; a Hub-set variable whose value collides with a secret is not
// masked (declared), so posting it back is no 400.
func TestExpertEnvRoundTripWithSecretValues(t *testing.T) {
	f, _ := secretFixture(t)
	const id = "secretapp"
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	group := composeReads(t, f.h.envPath(id))["PORTCULLIS_ACCESS_GROUP"]
	if group == "" {
		t.Fatal("no PORTCULLIS_ACCESS_GROUP in the .env")
	}
	saveSecret(t, f, id, "api_key", setSecret("1000"))
	saveSecret(t, f, id, "token", setSecret(group))
	if err := f.h.SaveEnv(id, map[string]string{"MY_COPY": "1000"}); err != nil {
		t.Fatal(err)
	}
	vars, _, err := f.h.Env(id)
	if err != nil {
		t.Fatal(err)
	}
	if vars["MY_COPY"] != settings.SecretShown {
		t.Errorf("MY_COPY shown as %q, want masked", vars["MY_COPY"])
	}
	if vars["PORTCULLIS_ACCESS_GROUP"] != group {
		t.Errorf("PORTCULLIS_ACCESS_GROUP shown as %q, want %q (declared: not masked)", vars["PORTCULLIS_ACCESS_GROUP"], group)
	}
	// The UI posts every variable back.
	if err := f.h.SaveEnv(id, vars); err != nil {
		t.Fatalf("posting Env back = %v", err)
	}
	got := composeReads(t, f.h.envPath(id))
	if got["MY_COPY"] != "1000" || got["PORTCULLIS_ACCESS_GROUP"] != group {
		t.Errorf("after the round trip MY_COPY=%q PORTCULLIS_ACCESS_GROUP=%q", got["MY_COPY"], got["PORTCULLIS_ACCESS_GROUP"])
	}
}

// Residual I2: a person leaving the population while LLDAP answers
// without uuids still has the claim attribute cleared (an empty uuid
// never means "re-created").
func TestClaimClearedWithoutUUID(t *testing.T) {
	f, people, store := claimFixture(t)
	quota := SettingAttr(claimID, "storage_quota")
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	if got := store.values["dave"][quota]; len(got) != 1 {
		t.Fatalf("dave's quota = %v", got)
	}
	people.set(func(p *fakePeople) {
		if p.uuids == nil {
			p.uuids = map[string]string{}
		}
		for _, u := range []string{"alice", "bob", "carol", "dave", "erin"} {
			p.uuids[u] = ""
		}
	})
	people.removeMember("users_immich", "dave")
	deliverNow(t, f, claimID, TriggerMembership)
	store.mu.Lock()
	got := store.values["dave"][quota]
	store.mu.Unlock()
	if len(got) != 0 {
		t.Errorf("dave's quota = %v after leaving, want cleared", got)
	}
}

// Residual M1: a busy Retry merged into a queued membership run keeps
// "re-run every hook": the unchanged audit hook (settings_change only)
// runs again.
func TestBusyRetryMergedKeepsForceAll(t *testing.T) {
	f, _, _ := hookFixture(t)
	enableHook(t, f)
	f.h.Deliver(context.Background(), hookID, TriggerRetry)
	f.h.Wait()
	f.h.TriggerMembershipDelivery() // a debounced membership run is queued
	if !f.h.DeliveryStatus(hookID).Pending {
		t.Fatal("no membership run queued")
	}
	l := f.h.deliverLock(hookID)
	l.Lock()
	n := len(f.engine.ExecCalls())
	if _, err := f.h.RetryDeliveries(context.Background(), hookID, "admin"); err != nil {
		l.Unlock()
		t.Fatal(err)
	}
	l.Unlock()
	f.h.Wait()
	if runs := hookRuns(t, f, "/audit", n); len(runs) != 1 {
		t.Errorf("audit ran %d times after the merged retry, want 1 (every hook re-run)", len(runs))
	}
}

// Residual M2: a run for an instance being deleted records no owed
// effect (nor re-queues); a successful compose up clears what is owed.
func TestOwedNeverForDeletingClearedByUp(t *testing.T) {
	f, _ := secretFixture(t)
	const id = "secretapp"
	f.h.setOwed(id, settings.EffectRestart)
	if err := f.h.Enable(id); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	if got := f.h.loadDelivered(id).Owed; got != "" {
		t.Errorf("owed = %q after a successful up, want cleared", got)
	}
	f.h.mu.Lock()
	f.h.st.Instances[id] = state.Instance{Template: id, State: state.InstanceDeleting}
	f.h.mu.Unlock()
	unlock, err := f.h.lockApp(id) // the delete holds the instance's lock
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := f.h.deliver(context.Background(), id, TriggerSave, deliverOpts{effect: settings.EffectRestart}); err != nil {
		t.Fatal(err)
	}
	f.h.owedMu.Lock()
	mem := f.h.owed[id]
	f.h.owedMu.Unlock()
	if got := f.h.loadDelivered(id).Owed; got != "" || mem != "" {
		t.Errorf("owed = %q (memory %q) for a deleting instance, want none", got, mem)
	}
	if f.h.DeliveryStatus(id).Pending {
		t.Error("a delivery is re-queued for a deleting instance")
	}
}
