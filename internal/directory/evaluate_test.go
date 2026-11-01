package directory_test

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak/kctest"
	"github.com/portcullis/hub/internal/rules"
)

// evalEnv: fields city (text) and manager (person); people bob and carol
// in Milan, dave in Rome; an empty LLDAP group "milan".
func evalEnv(t *testing.T) (*env, *directory.Store) {
	t.Helper()
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store
	for _, f := range []directory.Field{
		{Name: "city", Label: "City", Kind: directory.FieldKindText},
		{Name: "manager", Label: "Manager", Kind: directory.FieldKindPerson},
	} {
		if err := e.svc.CreateField(ctx, "root", f); err != nil {
			t.Fatal(err)
		}
	}
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	e.ll.AddUser("carol", "carol@example.org", "Carol", "")
	e.ll.AddUser("dave", "dave@example.org", "Dave", "")
	setCity(t, e, "bob", "Milan")
	setCity(t, e, "carol", "milan")
	setCity(t, e, "dave", "Rome")
	e.ll.AddGroup("milan")
	return e, store
}

func setCity(t *testing.T, e *env, user, city string) {
	t.Helper()
	if err := e.svc.LLDAP.SetUserAttributes(ctx, user, map[string][]string{"city": {city}}, nil); err != nil {
		t.Fatal(err)
	}
}

func setRule(t *testing.T, store *directory.Store, group, rule string, exc ...directory.Exception) {
	t.Helper()
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	expr, err := rules.Parse(rule)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Groups[group] = &directory.GroupConfig{Rule: expr, Exceptions: exc}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
}

func evaluate(t *testing.T, e *env, now time.Time) *directory.EvalReport {
	t.Helper()
	rep, err := e.svc.Evaluate(ctx, now)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return rep
}

func wantMembers(t *testing.T, e *env, group string, want ...string) {
	t.Helper()
	got := e.ll.GroupMembers(group)
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s members = %v, want %v", group, got, want)
	}
}

func hasChange(rep *directory.EvalReport, c directory.Change) bool {
	for _, x := range rep.Changes {
		if x == c {
			return true
		}
	}
	return false
}

func syncAudit(t *testing.T, e *env) []directory.AuditEntry {
	t.Helper()
	all, err := e.svc.Recent(1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []directory.AuditEntry
	for _, a := range all {
		if a.Action == "group.sync" {
			out = append(out, a)
		}
	}
	return out
}

var t0 = time.Date(2027, 3, 31, 12, 0, 0, 0, time.UTC)

func TestEvaluateRuleGroup(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	rep := evaluate(t, e, t0)
	wantMembers(t, e, "milan", "bob", "carol")
	if len(rep.Changes) != 2 || !hasChange(rep, directory.Change{Group: "milan", User: "bob", Add: true, Cause: "rule"}) {
		t.Errorf("changes = %+v", rep.Changes)
	}
	if len(rep.Errors) != 0 {
		t.Errorf("errors = %v", rep.Errors)
	}
	audit := syncAudit(t, e)
	if len(audit) != 2 {
		t.Fatalf("group.sync audit = %+v", audit)
	}
	for _, a := range audit {
		if a.Actor != "portcullis-hub (rules)" || a.Detail != "+rule" || a.Result != "ok" || !strings.HasPrefix(a.Target, "milan:") {
			t.Errorf("audit entry = %+v", a)
		}
	}

	// Idempotent.
	rep = evaluate(t, e, t0.Add(time.Minute))
	if len(rep.Changes) != 0 || len(rep.Errors) != 0 {
		t.Errorf("second run = %+v", rep)
	}
	wantMembers(t, e, "milan", "bob", "carol")

	// A detail change takes effect at the next run.
	setCity(t, e, "carol", "Rome")
	rep = evaluate(t, e, t0.Add(2*time.Minute))
	if len(rep.Changes) != 1 || !hasChange(rep, directory.Change{Group: "milan", User: "carol", Cause: "rule"}) {
		t.Errorf("changes = %+v", rep.Changes)
	}
	wantMembers(t, e, "milan", "bob")
}

func TestExceptionIncludeExclude(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`,
		directory.Exception{User: "dave", Reason: "covers Milan", By: "root", Include: true, At: t0},
		directory.Exception{User: "Carol", Reason: "on leave", By: "root", Include: false, At: t0},
	)
	rep := evaluate(t, e, t0)
	wantMembers(t, e, "milan", "bob", "dave")
	if !hasChange(rep, directory.Change{Group: "milan", User: "dave", Add: true, Cause: "exception"}) ||
		!hasChange(rep, directory.Change{Group: "milan", User: "bob", Add: true, Cause: "rule"}) || len(rep.Changes) != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}

	// An exclude removes a current member, with cause "exception".
	setRule(t, store, "milan", `city = "Milan"`,
		directory.Exception{User: "bob", Reason: "moved", By: "root", Include: false, At: t0},
	)
	rep = evaluate(t, e, t0)
	wantMembers(t, e, "milan", "carol")
	if !hasChange(rep, directory.Change{Group: "milan", User: "bob", Cause: "exception"}) ||
		!hasChange(rep, directory.Change{Group: "milan", User: "carol", Add: true, Cause: "rule"}) {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestExpiryBoundary(t *testing.T) {
	until := t0
	t.Run("exception", func(t *testing.T) {
		e, store := evalEnv(t)
		setRule(t, store, "milan", `city = "Milan"`,
			directory.Exception{User: "dave", Reason: "temp", By: "root", Include: true, Until: &until, At: t0.Add(-time.Hour)},
			directory.Exception{User: "carol", Reason: "leave", By: "root", Include: false, Until: &until, At: t0.Add(-time.Hour)},
		)
		evaluate(t, e, t0.Add(-time.Second))
		wantMembers(t, e, "milan", "bob", "dave")
		cfg, _ := store.Load()
		if len(cfg.Groups["milan"].Exceptions) != 2 {
			t.Fatalf("exceptions pruned early: %+v", cfg.Groups["milan"].Exceptions)
		}

		rep := evaluate(t, e, t0)
		wantMembers(t, e, "milan", "bob", "carol")
		if !hasChange(rep, directory.Change{Group: "milan", User: "dave", Cause: "exception expired"}) ||
			!hasChange(rep, directory.Change{Group: "milan", User: "carol", Add: true, Cause: "exception expired"}) || len(rep.Changes) != 2 {
			t.Errorf("changes = %+v", rep.Changes)
		}
		cfg, _ = store.Load()
		if len(cfg.Groups["milan"].Exceptions) != 0 {
			t.Errorf("expired exceptions kept: %+v", cfg.Groups["milan"].Exceptions)
		}
	})
	t.Run("manual expiry", func(t *testing.T) {
		e, store := evalEnv(t)
		e.ll.AddGroup("contractors", "bob", "carol")
		cfg, _ := store.Load()
		cfg.Groups["contractors"] = &directory.GroupConfig{Expiry: map[string]time.Time{"bob": until, "carol": until.Add(time.Hour)}}
		if err := store.Save(cfg); err != nil {
			t.Fatal(err)
		}
		rep := evaluate(t, e, t0.Add(-time.Second))
		if len(rep.Changes) != 0 {
			t.Errorf("early changes = %+v", rep.Changes)
		}
		wantMembers(t, e, "contractors", "bob", "carol")

		rep = evaluate(t, e, t0)
		wantMembers(t, e, "contractors", "carol")
		if len(rep.Changes) != 1 || !hasChange(rep, directory.Change{Group: "contractors", User: "bob", Cause: "membership expired"}) {
			t.Errorf("changes = %+v", rep.Changes)
		}
		cfg, _ = store.Load()
		if _, ok := cfg.Groups["contractors"].Expiry["bob"]; ok || len(cfg.Groups["contractors"].Expiry) != 1 {
			t.Errorf("expiry = %+v", cfg.Groups["contractors"].Expiry)
		}
		audit := syncAudit(t, e)
		if len(audit) != 1 || audit[0].Target != "contractors:bob" || audit[0].Detail != "-membership expired" {
			t.Errorf("audit = %+v", audit)
		}
	})
}

func TestEvaluateRevertsOutsideChange(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	evaluate(t, e, t0)
	// Someone adds dave in LLDAP directly and removes bob.
	gid := groupID(t, e, "milan")
	if err := e.svc.LLDAP.AddUserToGroup(ctx, "dave", gid); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LLDAP.RemoveUserFromGroup(ctx, "bob", gid); err != nil {
		t.Fatal(err)
	}
	rep := evaluate(t, e, t0)
	wantMembers(t, e, "milan", "bob", "carol")
	if !hasChange(rep, directory.Change{Group: "milan", User: "dave", Cause: "reverted: outside change"}) ||
		!hasChange(rep, directory.Change{Group: "milan", User: "bob", Add: true, Cause: "reverted: outside change"}) || len(rep.Changes) != 2 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func groupID(t *testing.T, e *env, name string) int {
	t.Helper()
	gs, err := e.svc.LLDAP.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gs {
		if g.DisplayName == name {
			return g.ID
		}
	}
	t.Fatalf("no group %s", name)
	return 0
}

func TestEvaluateIgnoresUnknownAttribute(t *testing.T) {
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store
	// An LLDAP attribute that is not a defined field.
	if err := e.svc.LLDAP.AddUserAttribute(ctx, "office", false); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "alice", map[string][]string{"office": {"Milan"}}, nil); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("office_milan")
	setRule(t, store, "office_milan", `office = "Milan"`)
	rep := evaluate(t, e, t0)
	wantMembers(t, e, "office_milan")
	if len(rep.Changes) != 0 {
		t.Errorf("changes = %+v", rep.Changes)
	}
}

func TestRemovalLogsOut(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	evaluate(t, e, t0)
	e.kc.Import("bob")
	e.kc.Update("bob", func(u *kctest.User) { u.Sessions = 2 })
	e.kc.Import("carol")
	e.kc.Update("carol", func(u *kctest.User) { u.Sessions = 1 })
	setCity(t, e, "bob", "Rome")
	rep := evaluate(t, e, t0)
	if len(rep.Errors) != 0 {
		t.Errorf("errors = %v", rep.Errors)
	}
	if e.kc.Get("bob").Sessions != 0 {
		t.Error("removed member still has Keycloak sessions")
	}
	if e.kc.Get("carol").Sessions != 1 {
		t.Error("unchanged member was logged out")
	}

	// A Keycloak failure is reported, not fatal.
	setCity(t, e, "carol", "Rome")
	e.kc.SetDown(true)
	rep = evaluate(t, e, t0)
	wantMembers(t, e, "milan")
	if len(rep.Changes) != 1 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "carol") {
		t.Errorf("report = %+v", rep)
	}
}

func TestProtectedAccountsNeverRuleMembers(t *testing.T) {
	e, store := evalEnv(t)
	setCity(t, e, "admin", "Milan")
	setCity(t, e, "portcullis-hub", "Milan")
	setRule(t, store, "milan", `city = "Milan"`,
		directory.Exception{User: "admin", Reason: "x", By: "root", Include: true, At: t0},
		directory.Exception{User: "portcullis-hub", Reason: "x", By: "root", Include: true, At: t0},
	)
	evaluate(t, e, t0)
	wantMembers(t, e, "milan", "bob", "carol")

	// Already a member (put there outside the Hub): left alone.
	setRule(t, store, "milan", `city = "Rome"`)
	if err := e.svc.LLDAP.AddUserToGroup(ctx, "admin", groupID(t, e, "milan")); err != nil {
		t.Fatal(err)
	}
	evaluate(t, e, t0)
	wantMembers(t, e, "milan", "admin", "dave")
}

func TestEvaluateSkipsBadRuleGroups(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "lldap_admin", `city = "Milan"`)
	setRule(t, store, "extra_admins", `city = "Milan"`)
	setRule(t, store, "nowhere", `city = "Milan"`)
	before := e.ll.GroupMembers("lldap_admin")
	rep := evaluate(t, e, t0)
	if len(rep.Changes) != 0 || len(rep.Errors) != 3 {
		t.Errorf("report = %+v", rep)
	}
	if !reflect.DeepEqual(e.ll.GroupMembers("lldap_admin"), before) || e.ll.HasGroup("nowhere") {
		t.Error("protected / missing rule group touched")
	}
}

func TestEvaluateCyclesAndManager(t *testing.T) {
	e, store := evalEnv(t)
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "carol", map[string][]string{"manager": {"bob"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "dave", map[string][]string{"manager": {"carol"}}, nil); err != nil {
		t.Fatal(err)
	}
	e.ll.AddGroup("team_bob")
	setRule(t, store, "team_bob", `manager reports-to "bob"`)
	rep := evaluate(t, e, t0)
	wantMembers(t, e, "team_bob", "carol", "dave")
	if len(rep.Cycles) != 0 {
		t.Errorf("cycles = %v", rep.Cycles)
	}
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "bob", map[string][]string{"manager": {"dave"}}, nil); err != nil {
		t.Fatal(err)
	}
	rep = evaluate(t, e, t0)
	if len(rep.Cycles) != 1 {
		t.Errorf("cycles = %v", rep.Cycles)
	}
}

func TestPending(t *testing.T) {
	e, _ := evalEnv(t)
	later := t0.Add(time.Hour)
	past := t0
	cfg := &directory.Config{Groups: map[string]*directory.GroupConfig{
		"contractors": {Expiry: map[string]time.Time{"Bob": later, "carol": t0, "dave": t0.Add(2 * time.Hour)}},
		"milan": {Rule: &rules.Expr{Op: rules.OpIs, Field: "city", Values: []string{"Milan"}}, Exceptions: []directory.Exception{
			{User: "alice", Include: true, Until: &later},
			{User: "carol", Include: true, Until: &past},
			{User: "dave", Include: true},
			{User: "eve", Include: false, Until: &later},
		}},
	}}
	got := e.svc.Pending(cfg, t0)
	want := []directory.Expiring{
		{User: "bob", Group: "contractors", At: later},
		{User: "alice", Group: "milan", At: later},
		{User: "dave", Group: "contractors", At: t0.Add(2 * time.Hour)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Pending = %+v, want %+v", got, want)
	}
}

func TestDesiredPure(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`,
		directory.Exception{User: "dave", Include: true, Reason: "r", At: t0})
	cfg, _ := store.Load()
	cfg.Groups["contractors"] = &directory.GroupConfig{}
	rep, err := e.svc.DesiredFromLLDAP(ctx, cfg, t0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]bool{"milan": {"bob": true, "carol": true, "dave": true}}
	if !reflect.DeepEqual(rep, want) {
		t.Errorf("desired = %v", rep)
	}
	wantMembers(t, e, "milan")
}

func TestRunEvaluatorKick(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.svc.RunEvaluator(runCtx, time.Hour); close(done) }()
	defer func() { cancel(); <-done }()
	waitMembers(t, e, "milan", "bob", "carol")
	// A detail change outside a mutation waits for the next tick; any
	// mutation kicks an evaluation.
	setCity(t, e, "carol", "Rome")
	if err := e.svc.CreateGroup(ctx, "root", "other"); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, e, "milan", "bob")
}

func waitMembers(t *testing.T, e *env, group string, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if reflect.DeepEqual(e.ll.GroupMembers(group), want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s members = %v, want %v", group, e.ll.GroupMembers(group), want)
}
