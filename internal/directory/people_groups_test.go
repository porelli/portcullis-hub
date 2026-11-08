package directory_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// includeOf is user's include ("added by hand") entry of group, or nil.
func includeOf(t *testing.T, store *directory.Store, group, user string) *directory.Exception {
	t.Helper()
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	gc := cfg.Groups[group]
	if gc == nil {
		return nil
	}
	for i := range gc.Exceptions {
		if ex := gc.Exceptions[i]; ex.Include && strings.EqualFold(ex.User, user) {
			return &ex
		}
	}
	return nil
}

func errMsg(err error) string {
	var de *directory.Error
	if errors.As(err, &de) {
		return de.Msg
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// On a rule group the add is an include exception: a reason is required.
func TestAddMemberRuleGroupNeedsReason(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	for _, reason := range []string{"", "   "} {
		err := e.svc.AddMember(ctx, asRoot, "milan", directory.MemberAdd{Username: "dave", Reason: reason})
		if status(err) != 400 || errMsg(err) != "a reason is required: milan is rule-based" {
			t.Errorf("reason %q: %v (status %d)", reason, err, status(err))
		}
	}
	if includeOf(t, store, "milan", "dave") != nil || memberIn(e, "milan", "dave") {
		t.Error("refused add stored something")
	}
	if a := newestAudit(t, e, "group.exception"); a.Result != "refused" || a.Target != "milan" {
		t.Errorf("audit = %+v", a)
	}
	// Delegates keep their powers: only admins add.
	if err := e.svc.AddMember(ctx, callerFor(t, e, "bob"), "milan", directory.MemberAdd{Username: "dave", Reason: "x"}); status(err) != 403 {
		t.Errorf("non-admin add = %v", err)
	}
}

func TestAddMemberRuleGroupStoresInclude(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	past := time.Now().Add(-time.Hour)
	wantStatus(t, "past until", e.svc.AddMember(ctx, asRoot, "milan", directory.MemberAdd{Username: "dave", Reason: "covers", Until: &past}), 400)
	wantStatus(t, "unknown user", e.svc.AddMember(ctx, asRoot, "milan", directory.MemberAdd{Username: "ghost", Reason: "covers"}), 404)
	wantStatus(t, "protected", e.svc.AddMember(ctx, asRoot, "milan", directory.MemberAdd{Username: "admin", Reason: "covers"}), 409)

	until := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	if err := e.svc.AddMember(ctx, asRoot, "milan", directory.MemberAdd{Username: "DAVE", Reason: " covers Milan ", Until: &until}); err != nil {
		t.Fatal(err)
	}
	ex := includeOf(t, store, "milan", "dave")
	if ex == nil || ex.User != "dave" || ex.Reason != "covers Milan" || ex.By != "root" || ex.Until == nil || !ex.Until.Equal(until) {
		t.Fatalf("entry = %+v", ex)
	}
	a := newestAudit(t, e, "group.exception")
	if a.Result != "ok" || a.Target != "milan" || a.Detail != "add user=dave include=true until="+until.Format(time.RFC3339)+" reason=covers Milan" {
		t.Errorf("audit = %+v", a)
	}
	evaluate(t, e, time.Now())
	if !memberIn(e, "milan", "dave") {
		t.Error("dave not added by the evaluator")
	}
}

// Someone who already matches can be added by hand: the entry is stored
// and keeps them in when they stop matching.
func TestAddMemberRuleGroupAlreadyMatching(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	setCity(t, e, "alice", "Milan")
	evaluate(t, e, time.Now())
	if !memberIn(e, "milan", "alice") {
		t.Fatal("setup: alice doesn't match")
	}
	// Control: bob also matches, has no entry, and goes once he stops.
	if !memberIn(e, "milan", "bob") {
		t.Fatal("setup: bob doesn't match")
	}
	if err := e.svc.AddMember(ctx, asRoot, "milan", directory.MemberAdd{Username: "alice", Reason: "keeps access"}); err != nil {
		t.Fatal(err)
	}
	if includeOf(t, store, "milan", "alice") == nil {
		t.Fatal("entry not stored")
	}
	setCity(t, e, "alice", "Rome")
	setCity(t, e, "bob", "Rome")
	evaluate(t, e, time.Now())
	if !memberIn(e, "milan", "alice") {
		t.Error("alice removed although added by hand")
	}
	if memberIn(e, "milan", "bob") {
		t.Error("control: bob kept without an entry")
	}
	evaluate(t, e, time.Now())
	if !memberIn(e, "milan", "alice") || includeOf(t, store, "milan", "alice") == nil {
		t.Error("second run dropped alice or her entry")
	}
}

func TestAddMemberManualUntil(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("temps")
	past := time.Now().Add(-time.Hour)
	wantStatus(t, "past until", e.svc.AddMember(ctx, asRoot, "temps", directory.MemberAdd{Username: "dave", Until: &past}), 400)
	if memberIn(e, "temps", "dave") {
		t.Fatal("refused add added dave")
	}
	wantStatus(t, "lldap_admin until", e.svc.AddMember(ctx, asRoot, "lldap_admin", directory.MemberAdd{Username: "dave", Until: &past}), 409)

	until := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	if err := e.svc.AddMember(ctx, asRoot, "temps", directory.MemberAdd{Username: "dave", Reason: "ignored", Until: &until}); err != nil {
		t.Fatal(err)
	}
	if !memberIn(e, "temps", "dave") {
		t.Fatal("dave not added")
	}
	cfg, _ := store.Load()
	if gc := cfg.Groups["temps"]; gc == nil || !gc.Expiry["dave"].Equal(until) || len(gc.Exceptions) != 0 {
		t.Errorf("temps = %+v", gc)
	}
	a := newestAudit(t, e, "group.add_member")
	if a.Result != "ok" || a.Detail != "user=dave until="+until.Format(time.RFC3339) {
		t.Errorf("audit = %+v", a)
	}
	// Plain add: unchanged (core e2e sends only the username).
	if err := e.svc.AddMember(ctx, asRoot, "temps", directory.MemberAdd{Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	if a := newestAudit(t, e, "group.add_member"); a.Detail != "bob" {
		t.Errorf("plain add audit = %+v", a)
	}
	cfg, _ = store.Load()
	if _, ok := cfg.Groups["temps"].Expiry["bob"]; ok {
		t.Error("plain add set an expiry")
	}
}

func TestSetMemberExpiryRuleHandAdded(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`,
		directory.Exception{User: "carol", Reason: "away", By: "root", At: time.Now()})
	if err := e.svc.AddMember(ctx, asRoot, "milan", directory.MemberAdd{Username: "dave", Reason: "covers"}); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
	if err := e.svc.SetMemberExpiry(ctx, asRoot, "milan", "Dave", &future); err != nil {
		t.Fatal(err)
	}
	if ex := includeOf(t, store, "milan", "dave"); ex == nil || ex.Until == nil || !ex.Until.Equal(future) || ex.Reason != "covers" {
		t.Fatalf("entry = %+v", ex)
	}
	if a := newestAudit(t, e, "group.expiry"); a.Result != "ok" || !strings.HasPrefix(a.Detail, "user=dave until="+future.Format(time.RFC3339)) {
		t.Errorf("audit = %+v", a)
	}
	if err := e.svc.SetMemberExpiry(ctx, asRoot, "milan", "dave", nil); err != nil {
		t.Fatal(err)
	}
	if ex := includeOf(t, store, "milan", "dave"); ex == nil || ex.Until != nil {
		t.Fatalf("cleared entry = %+v", ex)
	}
	past := time.Now().Add(-time.Hour)
	wantStatus(t, "past", e.svc.SetMemberExpiry(ctx, asRoot, "milan", "dave", &past), 400)
	// In by the rule only, or kept out: no entry to end.
	wantStatus(t, "rule match", e.svc.SetMemberExpiry(ctx, asRoot, "milan", "bob", &future), 409)
	wantStatus(t, "kept out", e.svc.SetMemberExpiry(ctx, asRoot, "milan", "carol", &future), 409)
}

func TestGroupViewMatches(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	e.ll.AddGroup("nobody_here")
	setRule(t, store, "nobody_here", `city = "Paris"`)
	e.ll.AddGroup("temps", "dave")
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]directory.GroupView{}
	for _, g := range ov.Groups {
		byName[g.Name] = g
	}
	if got := byName["milan"].Matches; !reflect.DeepEqual(got, []string{"bob", "carol"}) {
		t.Errorf("milan matches = %#v", got)
	}
	if got := byName["nobody_here"].Matches; got == nil || len(got) != 0 {
		t.Errorf("nobody_here matches = %#v, want []", got)
	}
	if got := byName["temps"].Matches; got != nil {
		t.Errorf("manual group matches = %#v", got)
	}
	b, _ := json.Marshal(byName["nobody_here"])
	if !strings.Contains(string(b), `"matches":[]`) {
		t.Errorf("rule group JSON = %s", b)
	}
	b, _ = json.Marshal(byName["temps"])
	if strings.Contains(string(b), `"matches"`) {
		t.Errorf("manual group JSON = %s", b)
	}
	// Admins through OverviewFor too; non-admins never.
	ov, err = e.svc.OverviewFor(ctx, asRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range ov.Groups {
		if g.Name == "milan" && len(g.Matches) != 2 {
			t.Errorf("OverviewFor admin: %#v", g.Matches)
		}
	}
	ov, err = e.svc.OverviewFor(ctx, callerFor(t, e, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range ov.Groups {
		if g.Matches != nil {
			t.Errorf("non-admin sees matches of %s: %#v", g.Name, g.Matches)
		}
	}
	pv, err := e.svc.PeopleOverview(ctx, asRoot)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(pv); strings.Contains(string(b), `"matches"`) {
		t.Errorf("people view carries matches: %s", b)
	}
}

func TestCreateUserRuleGroups(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	e.ll.AddGroup("fresh")
	setRule(t, store, "fresh", `city is empty`)
	e.ll.AddGroup("temps")
	req := func(user string, groups []string, reasons map[string]string) directory.CreateRequest {
		return directory.CreateRequest{Username: user, Email: user + "@example.org", DisplayName: "Z", Groups: groups, Reasons: reasons,
			Onboarding: directory.OnboardPassword, Generate: true}
	}
	// A rule group the new person won't match needs a reason.
	_, err := e.svc.CreateUser(ctx, asRoot, req("zed", []string{"temps", "milan"}, map[string]string{"temps": "x"}))
	if status(err) != 400 || !strings.Contains(errMsg(err), "milan") {
		t.Errorf("no reason = %v", err)
	}
	if e.ll.HasUser("zed") {
		t.Fatal("refused create created zed")
	}
	// With one: an include entry with the new person's id.
	if _, err := e.svc.CreateUser(ctx, asRoot, req("zed", []string{"temps", "milan"}, map[string]string{"milan": " new hire "})); err != nil {
		t.Fatal(err)
	}
	if ex := includeOf(t, store, "milan", "zed"); ex == nil || ex.User != "zed" || ex.Reason != "new hire" || ex.By != "root" || ex.Until != nil {
		t.Fatalf("entry = %+v", ex)
	}
	if !memberIn(e, "temps", "zed") {
		t.Error("manual group not added")
	}
	evaluate(t, e, time.Now())
	if !memberIn(e, "milan", "zed") {
		t.Error("zed not added to milan by the evaluator")
	}
	// A rule the new person matches (no details yet) needs none, and
	// stores nothing.
	if _, err := e.svc.CreateUser(ctx, asRoot, req("yan", []string{"fresh"}, nil)); err != nil {
		t.Fatal(err)
	}
	if includeOf(t, store, "fresh", "yan") != nil {
		t.Error("matching person got an entry")
	}
	evaluate(t, e, time.Now())
	if !memberIn(e, "fresh", "yan") {
		t.Error("yan not added to fresh")
	}
	// Unknown group: still 400.
	if _, err := e.svc.CreateUser(ctx, asRoot, req("xia", []string{"nope"}, nil)); status(err) != 400 {
		t.Errorf("unknown group = %v", err)
	}
}

// The invite's entries are saved after every step that can still delete
// the new user: a failed password leaves none behind.
func TestCreateUserRuleGroupPasswordFails(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	e.ll.FailPassword = 53
	_, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Groups: []string{"milan"},
		Reasons: map[string]string{"milan": "new hire"}, Onboarding: directory.OnboardPassword, Password: "a-good-password-1"})
	if err == nil || e.ll.HasUser("zed") {
		t.Fatalf("err = %v, zed exists %v", err, e.ll.HasUser("zed"))
	}
	if ex := includeOf(t, store, "milan", "zed"); ex != nil {
		t.Errorf("entry left behind: %+v", ex)
	}
}

// Saving the entries fails: the new user is deleted.
func TestCreateUserRuleGroupSaveFails(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	dir := filepath.Dir(store.Path)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	_, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "zed", Email: "zed@example.org", Groups: []string{"milan"},
		Reasons: map[string]string{"milan": "new hire"}, Onboarding: directory.OnboardPassword, Generate: true})
	os.Chmod(dir, 0700)
	if err == nil || e.ll.HasUser("zed") {
		t.Fatalf("err = %v, zed exists %v", err, e.ll.HasUser("zed"))
	}
	if ex := includeOf(t, store, "milan", "zed"); ex != nil {
		t.Errorf("entry stored: %+v", ex)
	}
}

// Each invite entry is audited as group.exception too; a reason for a
// group that isn't a rule group in groups is refused, named.
func TestCreateUserRuleGroupAuditAndReasons(t *testing.T) {
	e, store := evalEnv(t)
	setRule(t, store, "milan", `city = "Milan"`)
	e.ll.AddGroup("temps")
	req := func(user string, groups []string, reasons map[string]string) directory.CreateRequest {
		return directory.CreateRequest{Username: user, Email: user + "@example.org", Groups: groups, Reasons: reasons,
			Onboarding: directory.OnboardPassword, Generate: true}
	}
	for _, c := range []struct {
		reasons map[string]string
		name    string
	}{
		{map[string]string{"milan": "x", "temps": "y"}, "temps"}, // manual group
		{map[string]string{"milan": "x", "rome": "y"}, "rome"},   // not in groups
	} {
		_, err := e.svc.CreateUser(ctx, asRoot, req("zed", []string{"milan", "temps"}, c.reasons))
		if status(err) != 400 || !strings.Contains(errMsg(err), `"`+c.name+`"`) {
			t.Errorf("reasons %v = %v", c.reasons, err)
		}
		if e.ll.HasUser("zed") {
			t.Fatal("refused create created zed")
		}
	}
	if _, err := e.svc.CreateUser(ctx, asRoot, req("zed", []string{"milan", "temps"}, map[string]string{"milan": "new hire"})); err != nil {
		t.Fatal(err)
	}
	ex := includeOf(t, store, "milan", "zed")
	a := newestAudit(t, e, "group.exception")
	if ex == nil || a.Result != "ok" || a.Target != "milan" || a.Actor != "root" || a.Detail != "add user=zed include=true until=never reason=new hire" {
		t.Errorf("entry %+v, audit %+v", ex, a)
	}
	if a := newestAudit(t, e, "user.create"); a.Result != "ok" || !strings.Contains(a.Detail, "added_by_hand=milan reason=new hire") {
		t.Errorf("user.create audit = %+v", a)
	}
}

// An invitee who matches a rule group whose adds are blocked is told so.
func TestCreateUserBlockedRuleGroupWarns(t *testing.T) {
	e, store := evalEnv(t)
	e.ll.AddGroup("fresh")
	setRule(t, store, "fresh", `city is empty`)
	cfg, _ := store.Load()
	cfg.Permissions[directory.PermInvite] = "fresh" // a guarding group on a field delegates edit
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.CreateUser(ctx, asRoot, directory.CreateRequest{Username: "yan", Email: "yan@example.org", Groups: []string{"fresh"},
		Onboarding: directory.OnboardPassword, Generate: true})
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(res.Warnings, "\n")
	if !strings.Contains(w, "yan won't be added to fresh for now: fresh is the invite permission group") {
		t.Errorf("warnings = %q", w)
	}
}
