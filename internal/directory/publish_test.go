package directory_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/rules"
)

// Publish: pending expiries, shared fields only, every user but the
// service account; OnChange fires after mutations, outside the lock.
func TestPublishAndOnChange(t *testing.T) {
	e := newEnv(t)
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.ll.AddGroup("contractors", "alice")
	var changes, inside atomic.Int32
	e.svc.OnChange = func() {
		changes.Add(1)
		// Evaluate takes the service lock: deadlocks if OnChange is
		// called with it held.
		if inside.Add(1) == 1 {
			if _, err := e.svc.Evaluate(ctx, time.Now()); err != nil {
				t.Errorf("Evaluate in OnChange: %v", err)
			}
		}
		inside.Add(-1)
	}

	for _, f := range []directory.Field{
		{Name: "cost_center", Label: "Cost center", Kind: directory.FieldKindText, ShareWithApps: true},
		{Name: "teams", Label: "Teams", Kind: directory.FieldKindText, Multi: true, ShareWithApps: true},
		{Name: "clearance", Label: "Clearance", Kind: directory.FieldKindText, AdminOnly: true},
	} {
		if err := e.svc.CreateField(ctx, asRoot, f); err != nil {
			t.Fatal(err)
		}
	}
	if n := changes.Load(); n != 3 {
		t.Errorf("OnChange after 3 field creates: %d", n)
	}
	if err := e.svc.SetDetails(ctx, asRoot, "alice", map[string][]string{"cost_center": {"CC-1"}, "teams": {"a", "b"}, "clearance": {"secret"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "portcullis-hub", map[string][]string{"cost_center": {"svc"}}, nil); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	if err := e.svc.SetMemberExpiry(ctx, asRoot, "contractors", "alice", &until); err != nil {
		t.Fatal(err)
	}
	if n := changes.Load(); n != 5 {
		t.Errorf("OnChange after details + expiry: %d", n)
	}
	// A refused mutation changes nothing.
	if err := e.svc.SetDetails(ctx, asRoot, "portcullis-hub", map[string][]string{"cost_center": {"x"}}); err == nil {
		t.Fatal("service account edited")
	}
	if n := changes.Load(); n != 5 {
		t.Errorf("OnChange after a refusal: %d", n)
	}

	pub, err := e.svc.Publish(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(pub.Expiring); got != fmt.Sprint([]directory.Expiring{{User: "alice", Group: "contractors", At: until}}) {
		t.Errorf("expiring = %s", got)
	}
	if len(pub.Fields) != 2 || pub.Fields[0].Name != "cost_center" || pub.Fields[1].Name != "teams" || !pub.Fields[1].Multi {
		t.Errorf("fields = %+v", pub.Fields)
	}
	want := map[string]map[string][]string{"alice": {"cost_center": {"CC-1"}, "teams": {"a", "b"}}}
	if !reflect.DeepEqual(pub.Users, want) {
		t.Errorf("users = %v", pub.Users)
	}

	// Broken directory.yaml: an error, never a partial view.
	e.svc.Store = &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	if err := os.WriteFile(e.svc.Store.Path, []byte("version: 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Publish(ctx, time.Now()); err == nil {
		t.Error("corrupt directory.yaml published")
	}
}

func graceOf(t *testing.T, store *directory.Store) []directory.GraceEntry {
	t.Helper()
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Grace
}

func pendingAt(t *testing.T, e *env, store *directory.Store, now time.Time) string {
	t.Helper()
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(e.svc.Pending(cfg, now))
}

// A failed removal keeps the expired entry (so it stays published and
// group-gate keeps denying); a successful one prunes it into a grace entry
// published for GracePeriod, then dropped.
func TestExpiryRemovalFailureAndGrace(t *testing.T) {
	for _, kind := range []string{"manual", "exception"} {
		t.Run(kind, func(t *testing.T) {
			e, store := evalEnv(t)
			group := "contractors"
			if kind == "manual" {
				e.ll.AddGroup(group, "dave")
				cfg, _ := store.Load()
				cfg.Groups[group] = &directory.GroupConfig{Expiry: map[string]time.Time{"dave": t0}}
				if err := store.Save(cfg); err != nil {
					t.Fatal(err)
				}
			} else {
				group = "milan"
				until := t0
				setRule(t, store, group, `city = "Milan"`,
					directory.Exception{User: "dave", Reason: "temp", By: "root", Include: true, Until: &until, At: t0.Add(-time.Hour)})
				evaluate(t, e, t0.Add(-time.Second))
			}
			if !memberIn(e, group, "dave") {
				t.Fatal("setup: dave not a member")
			}
			want := fmt.Sprint([]directory.Expiring{{User: "dave", Group: group, At: t0}})

			e.ll.SetFailRemove(true)
			rep := evaluate(t, e, t0.Add(time.Second))
			if len(rep.Errors) == 0 || !memberIn(e, group, "dave") {
				t.Fatalf("removal did not fail: %+v", rep)
			}
			if got := pendingAt(t, e, store, t0.Add(time.Second)); got != want {
				t.Errorf("after failed removal: pending = %s, want %s", got, want)
			}
			if g := graceOf(t, store); len(g) != 0 {
				t.Errorf("grace before removal: %+v", g)
			}

			e.ll.SetFailRemove(false)
			pruned := t0.Add(time.Minute)
			evaluate(t, e, pruned)
			if memberIn(e, group, "dave") {
				t.Fatal("dave still a member")
			}
			cfg, _ := store.Load()
			if gc := cfg.Groups[group]; gc != nil && (len(gc.Expiry) != 0 || len(gc.Exceptions) != 0) {
				t.Errorf("entry not pruned: %+v", gc)
			}
			if g := graceOf(t, store); len(g) != 1 || g[0].User != "dave" || g[0].Group != group || !g[0].At.Equal(t0) || !g[0].Until.Equal(pruned.Add(directory.GracePeriod)) {
				t.Errorf("grace = %+v", g)
			}
			if got := pendingAt(t, e, store, pruned.Add(5*time.Minute)); got != want {
				t.Errorf("during grace: pending = %s", got)
			}

			evaluate(t, e, pruned.Add(directory.GracePeriod))
			if g := graceOf(t, store); len(g) != 0 {
				t.Errorf("grace not dropped: %+v", g)
			}
			if got := pendingAt(t, e, store, pruned.Add(directory.GracePeriod)); got != "[]" {
				t.Errorf("after grace: pending = %s", got)
			}
		})
	}
}

func memberIn(e *env, group, user string) bool {
	for _, m := range e.ll.GroupMembers(group) {
		if m == user {
			return true
		}
	}
	return false
}

func seedGrace(t *testing.T, store *directory.Store, user, group string) {
	t.Helper()
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Grace = append(cfg.Grace, directory.GraceEntry{User: user, Group: group, At: t0, Until: time.Now().Add(time.Hour)},
		directory.GraceEntry{User: "other", Group: group, At: t0, Until: time.Now().Add(time.Hour)})
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
}

func wantGraceOnlyOther(t *testing.T, store *directory.Store, label string) {
	t.Helper()
	if g := graceOf(t, store); len(g) != 1 || g[0].User != "other" {
		t.Errorf("%s: grace = %+v", label, g)
	}
}

// Granting the membership again, by any path, ends its grace entry.
func TestRegrantClearsGrace(t *testing.T) {
	future := time.Now().Add(48 * time.Hour)
	t.Run("AddMember", func(t *testing.T) {
		e, store := evalEnv(t)
		e.ll.AddGroup("temps")
		seedGrace(t, store, "dave", "temps")
		if err := e.svc.AddMember(ctx, asRoot, "temps", "dave"); err != nil {
			t.Fatal(err)
		}
		wantGraceOnlyOther(t, store, "AddMember")
	})
	t.Run("SetMemberExpiry", func(t *testing.T) {
		e, store := evalEnv(t)
		e.ll.AddGroup("temps", "dave")
		seedGrace(t, store, "dave", "temps")
		if err := e.svc.SetMemberExpiry(ctx, asRoot, "temps", "dave", &future); err != nil {
			t.Fatal(err)
		}
		wantGraceOnlyOther(t, store, "SetMemberExpiry")
	})
	t.Run("AddException", func(t *testing.T) {
		e, store := evalEnv(t)
		setRule(t, store, "milan", `city = "Milan"`)
		seedGrace(t, store, "dave", "milan")
		if err := e.svc.AddException(ctx, asRoot, "milan", directory.Exception{User: "dave", Reason: "back", Include: true, Until: &future}); err != nil {
			t.Fatal(err)
		}
		wantGraceOnlyOther(t, store, "AddException")
	})
	t.Run("rule match", func(t *testing.T) {
		e, store := evalEnv(t)
		setRule(t, store, "milan", `city = "Milan"`)
		seedGrace(t, store, "bob", "milan")
		evaluate(t, e, time.Now())
		if !memberIn(e, "milan", "bob") {
			t.Fatal("bob not added")
		}
		wantGraceOnlyOther(t, store, "rule match")
	})
	t.Run("ConvertApply keep", func(t *testing.T) {
		e, store := evalEnv(t)
		e.ll.AddGroup("temps", "dave")
		seedGrace(t, store, "dave", "temps")
		rule, err := rules.Parse(`city = "Milan"`)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.svc.ConvertApply(ctx, asRoot, "temps", rule, []string{"dave"}); err != nil {
			t.Fatal(err)
		}
		wantGraceOnlyOther(t, store, "ConvertApply")
	})
}

// A past expiry whose removal failed is still published by Publish.
func TestPublishKeepsPastExpiry(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("contractors", "dave")
	cfg, _ := store.Load()
	past := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	cfg.Groups["contractors"] = &directory.GroupConfig{Expiry: map[string]time.Time{"dave": past}}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	pub, err := e.svc.Publish(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(pub.Expiring); got != fmt.Sprint([]directory.Expiring{{User: "dave", Group: "contractors", At: past}}) {
		t.Errorf("expiring = %s", got)
	}
}

// Rule groups the evaluator skips: an expired "added" exception of a
// current member stays (published, denying) and is reported every run
// until they are removed or an admin re-adds them; everything else
// expired is dropped.
func TestSkippedRuleGroupExpiredExceptions(t *testing.T) {
	until := t0
	later := t0.Add(time.Hour)
	skippedEnv := func(t *testing.T) (*env, *directory.Store) {
		e, store := evalEnv(t)
		setRule(t, store, "milan", `city = "Milan"`,
			directory.Exception{User: "dave", Reason: "temp", By: "root", Include: true, Until: &until, At: t0.Add(-time.Hour)},
			directory.Exception{User: "carol", Reason: "leave", By: "root", Include: false, Until: &until, At: t0.Add(-time.Hour)},
			directory.Exception{User: "bob", Reason: "temp", By: "root", Include: true, Until: &later, At: t0.Add(-time.Hour)})
		evaluate(t, e, t0.Add(-time.Second))
		if !memberIn(e, "milan", "dave") {
			t.Fatal("setup: dave not added")
		}
		base := e.svc.AdminGroups
		e.svc.AdminGroups = func() map[string]bool { m := base(); m["milan"] = true; return m }
		return e, store
	}
	daveExpired := fmt.Sprint([]directory.Expiring{{User: "dave", Group: "milan", At: t0}, {User: "bob", Group: "milan", At: later}})
	bobOnly := fmt.Sprint([]directory.Expiring{{User: "bob", Group: "milan", At: later}})
	exceptionsOf := func(t *testing.T, store *directory.Store) string {
		cfg, _ := store.Load()
		var out []string
		for _, ex := range cfg.Groups["milan"].Exceptions {
			out = append(out, ex.User)
		}
		return strings.Join(out, ",")
	}

	t.Run("still member: kept and reported", func(t *testing.T) {
		e, store := skippedEnv(t)
		for i := 0; i < 2; i++ {
			rep := evaluate(t, e, t0.Add(time.Duration(i+1)*time.Second))
			if !strings.Contains(strings.Join(rep.Errors, "\n"), "milan: dave's temporary access expired but the evaluator doesn't manage this group") {
				t.Errorf("run %d: errors = %v", i, rep.Errors)
			}
			if got := pendingAt(t, e, store, t0.Add(time.Second)); got != daveExpired {
				t.Errorf("run %d: pending = %s", i, got)
			}
		}
		// Expired "kept out" exception dropped, future one kept.
		if got := exceptionsOf(t, store); got != "dave,bob" {
			t.Errorf("exceptions = %s", got)
		}
		if !memberIn(e, "milan", "dave") {
			t.Error("skipped group's membership changed")
		}
	})
	t.Run("removed from group: dropped", func(t *testing.T) {
		e, store := skippedEnv(t)
		evaluate(t, e, t0.Add(time.Second))
		e.ll.RemoveMember("milan", "dave")
		evaluate(t, e, t0.Add(2*time.Second))
		if got := pendingAt(t, e, store, t0.Add(2*time.Second)); got != bobOnly {
			t.Errorf("pending = %s", got)
		}
		if g := graceOf(t, store); len(g) != 0 {
			t.Errorf("grace = %+v", g)
		}
	})
	t.Run("admin re-adds: dropped", func(t *testing.T) {
		e, store := skippedEnv(t)
		// The time check uses the wall clock: make the exception past now.
		cfg, _ := store.Load()
		past := time.Now().Add(-time.Minute)
		cfg.Groups["milan"].Exceptions[0].Until = &past
		if err := store.Save(cfg); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.AddMember(ctx, asRoot, "milan", "dave"); err != nil {
			t.Fatal(err)
		}
		if got := exceptionsOf(t, store); strings.Contains(got, "dave") || !memberIn(e, "milan", "dave") {
			t.Errorf("after re-add: exceptions %s, member %v", got, memberIn(e, "milan", "dave"))
		}
		// Nothing left to confirm: a second re-add is "already a member".
		if err := e.svc.AddMember(ctx, asRoot, "milan", "dave"); status(err) != 409 {
			t.Errorf("second re-add: %v", err)
		}
		// Not a member, expired exception: AddMember adds and drops it.
		cfg, _ = store.Load()
		cfg.Groups["milan"].Exceptions = append(cfg.Groups["milan"].Exceptions,
			directory.Exception{User: "alice", Reason: "temp", By: "root", Include: true, Until: &past, At: t0.Add(-time.Hour)})
		if err := store.Save(cfg); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.AddMember(ctx, asRoot, "milan", "alice"); err != nil {
			t.Fatal(err)
		}
		if got := exceptionsOf(t, store); strings.Contains(got, "alice") || !memberIn(e, "milan", "alice") {
			t.Errorf("after add: exceptions %s", got)
		}
	})
	t.Run("missing in LLDAP: pruned", func(t *testing.T) {
		e, store := evalEnv(t)
		setRule(t, store, "ghost", `city = "Milan"`,
			directory.Exception{User: "dave", Reason: "temp", By: "root", Include: true, Until: &until, At: t0.Add(-time.Hour)},
			directory.Exception{User: "bob", Reason: "temp", By: "root", Include: true, Until: &later, At: t0.Add(-time.Hour)})
		evaluate(t, e, t0.Add(time.Second))
		if got := pendingAt(t, e, store, t0.Add(time.Second)); got != fmt.Sprint([]directory.Expiring{{User: "bob", Group: "ghost", At: later}}) {
			t.Errorf("pending = %s", got)
		}
	})
}

// CreateUser's group adds end the new account's grace entries; DeleteUser
// purges the deleted account's.
func TestCreateDeleteUserGrace(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("temps")
	seedGrace(t, store, "zed", "temps")
	if _, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Groups: []string{"temps"},
		Onboarding: directory.OnboardPassword, Generate: true}); err != nil {
		t.Fatal(err)
	}
	if !memberIn(e, "temps", "zed") {
		t.Fatal("zed not added")
	}
	wantGraceOnlyOther(t, store, "CreateUser")

	seedGrace(t, store, "dave", "milan")
	if _, err := e.svc.DeleteUser(ctx, asRoot, "dave", "dave"); err != nil {
		t.Fatal(err)
	}
	for _, g := range graceOf(t, store) {
		if g.User == "dave" {
			t.Errorf("grace of deleted user kept: %+v", g)
		}
	}
}
