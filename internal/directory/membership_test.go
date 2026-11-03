package directory_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
)

// privEnv is an env with a store, an admin-only field (clearance) and
// one delegates can edit (office_location), and app immich whose
// privileged option has a row for office_milan.
func privEnv(t *testing.T) (*env, *directory.Store) {
	t.Helper()
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store
	for _, f := range []directory.Field{
		{Name: "office_location", Label: "Office", Kind: directory.FieldKindText},
		{Name: "clearance", Label: "Clearance", Kind: directory.FieldKindText, AdminOnly: true},
	} {
		if err := e.svc.CreateField(ctx, asRoot, f); err != nil {
			t.Fatal(err)
		}
	}
	e.svc.Apps = func() []directory.App {
		return []directory.App{{ID: "immich", Name: "Immich", Enabled: true, AccessGroup: "users_immich", AdminGroup: "admin_immich", PrivilegedGroups: []string{"office_milan"}}}
	}
	return e, store
}

func TestMembershipExcludesServiceAccountAndMarksExpired(t *testing.T) {
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store
	e.ll.AddUser("Bob", "bob@example.org", "Bob", "")
	id := e.ll.AddGroup("users_app", "alice", "Bob", "portcullis-hub")
	cfg, _ := store.Load()
	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	cfg.Groups["users_app"] = &directory.GroupConfig{Expiry: map[string]time.Time{"alice": past}}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	m, err := e.svc.Membership(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Users["portcullis-hub"]; ok {
		t.Errorf("service account listed: %+v", m.Users)
	}
	if m.Users["bob"]["users_app"] != id || m.Users["alice"]["users_app"] != id {
		t.Errorf("users = %+v (group id %d)", m.Users, id)
	}
	if _, ok := m.Users["root"]; !ok {
		t.Errorf("root (no app groups) missing: %+v", m.Users)
	}
	g := m.Groups["users_app"]
	if g.ID != id || strings.Join(g.Members, ",") != "alice,bob" {
		t.Errorf("group = %+v", g)
	}
	if !m.Expired["alice"]["users_app"] || m.Expired["bob"]["users_app"] {
		t.Errorf("expired = %+v", m.Expired)
	}

	// LLDAP unavailable: a 503 *Error.
	e.svc.LLDAP = brokenDir{e.svc.LLDAP}
	if _, err := e.svc.Membership(ctx, time.Now()); status(err) != 503 {
		t.Errorf("unavailable = %v", err)
	}
}

func TestPrivilegeProblem(t *testing.T) {
	e, _ := privEnv(t)
	e.ll.AddGroup("editors")
	e.ll.AddGroup("office_milan")
	e.ll.AddGroup("everyone")
	e.ll.AddGroup("cleared")
	if p, err := e.svc.PrivilegeProblem(ctx, "editors"); err != nil || p != "" {
		t.Errorf("manual group = %q %v", p, err)
	}
	if err := e.svc.ConvertApply(ctx, asRoot, "cleared", mustRule(t, `clearance = "high"`), nil); err != nil {
		t.Fatal(err)
	}
	if p, err := e.svc.PrivilegeProblem(ctx, "cleared"); err != nil || p != "" {
		t.Errorf("admin-only rule group = %q %v", p, err)
	}
	// office_milan is guarding (immich's privileged row): its rule is
	// written straight to the store, as if it became guarding later.
	if err := e.svc.ConvertApply(ctx, asRoot, "everyone", mustRule(t, `not clearance = "none"`), nil); err != nil {
		t.Fatal(err)
	}
	if p, err := e.svc.PrivilegeProblem(ctx, "everyone"); err != nil || !strings.Contains(p, "no details") {
		t.Errorf("empty-matching rule = %q %v", p, err)
	}
	cfg, _ := e.svc.Store.Load()
	cfg.Groups["office_milan"] = &directory.GroupConfig{Rule: mustRule(t, `office_location = "Milan"`)}
	if err := e.svc.Store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if p, err := e.svc.PrivilegeProblem(ctx, "office_milan"); err != nil || p != "its rule uses fields delegates can edit: office_location" {
		t.Errorf("rule group = %q %v", p, err)
	}
	if _, err := e.svc.PrivilegeProblem(ctx, "ghost"); status(err) != 404 {
		t.Errorf("missing = %v", err)
	}
	// Membership carries the same answer per group.
	m, err := e.svc.Membership(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if m.Privilege["office_milan"] == "" || m.Privilege["editors"] != "" || m.Privilege["cleared"] != "" {
		t.Errorf("membership privilege = %+v", m.Privilege)
	}
}

func TestPrivilegedGroupsAreGuarding(t *testing.T) {
	e, store := privEnv(t)
	e.ll.AddGroup("office_milan")
	if err := e.svc.ConvertApply(ctx, asRoot, "office_milan", mustRule(t, `clearance = "high"`), nil); err != nil {
		t.Fatal(err)
	}
	err := e.svc.SetGroupRule(ctx, asRoot, "office_milan", mustRule(t, `office_location = "Milan"`))
	wantStatus(t, "SetGroupRule", err, 409)
	if err == nil || !strings.Contains(err.Error(), "a privileged value of app immich") {
		t.Errorf("reason = %v", err)
	}
	// Turning admin_only off on a field its rule uses: 409.
	off := false
	_, err = e.svc.PatchField(ctx, asRoot, "clearance", directory.FieldPatch{AdminOnly: &off})
	wantStatus(t, "PatchField admin_only off", err, 409)

	// A rule that became privileged later (written straight to the store)
	// adds nobody (addsBlocked).
	e.ll.AddUser("bob", "bob@example.org", "Bob", "")
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "bob", map[string][]string{"office_location": {"Milan"}, "clearance": {"high"}}, nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ := store.Load()
	cfg.Groups["office_milan"].Rule = mustRule(t, `office_location = "Milan"`)
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	rep, err := e.svc.Evaluate(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got := e.ll.GroupMembers("office_milan"); len(got) != 0 {
		t.Errorf("office_milan members = %v (report %+v)", got, rep)
	}
	// The created_by exclusion: a delegate-created account isn't added.
	cfg, _ = store.Load()
	cfg.Groups["office_milan"].Rule = mustRule(t, `clearance = "high"`)
	cfg.CreatedBy["bob"] = "delegate"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Evaluate(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got := e.ll.GroupMembers("office_milan"); len(got) != 0 {
		t.Errorf("delegate-created account added: %v", got)
	}
	// Without the privileged row the group is an ordinary one again.
	e.svc.Apps = func() []directory.App { return nil }
	if err := e.svc.SetGroupRule(ctx, asRoot, "office_milan", mustRule(t, `office_location = "Milan"`)); err != nil {
		t.Errorf("ordinary group: %v", err)
	}
}

func TestReservedAttrPrefix(t *testing.T) {
	e := newEnv(t)
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store
	err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: directory.ReservedAttrPrefix + "x", Label: "X", Kind: directory.FieldKindText})
	wantStatus(t, "CreateField ps_x", err, 409)
	if err := e.svc.CreateField(ctx, asRoot, directory.Field{Name: "city", Label: "City", Kind: directory.FieldKindText}); err != nil {
		t.Fatal(err)
	}
	// A Hub-owned claim attribute, and a ps_ field someone wrote into
	// directory.yaml by hand.
	attr := directory.ReservedAttrPrefix + "0123456789ab"
	if err := e.svc.LLDAP.AddUserAttribute(ctx, attr, false); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.LLDAP.SetUserAttributes(ctx, "alice", map[string][]string{attr: {"admin"}, "city": {"Milan"}}, nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ := store.Load()
	cfg.Fields = append(cfg.Fields, directory.Field{Name: attr, Label: "Claim", Kind: directory.FieldKindText})
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ov)
	if strings.Contains(string(b), attr) {
		t.Errorf("overview shows %s: %s", attr, b)
	}
	if !strings.Contains(string(b), "Milan") {
		t.Errorf("overview lost city: %s", b)
	}
	pv, err := e.svc.PeopleOverview(ctx, asRoot)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(pv); strings.Contains(string(b), attr) {
		t.Errorf("people overview shows %s", attr)
	}
	// Import: a ps_ column is refused, current values never show it.
	rev, err := e.svc.ImportReview(ctx, asRoot, []string{"username", attr}, [][]string{{"alice", "admin"}})
	if err == nil {
		if b, _ := json.Marshal(rev); strings.Contains(string(b), "\"admin\"") && !strings.Contains(string(b), "reserved") {
			t.Errorf("import review took %s: %s", attr, b)
		}
	}
	rev, err = e.svc.ImportReview(ctx, asRoot, []string{"username", "city"}, [][]string{{"alice", "Rome"}})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(rev); strings.Contains(string(b), attr) {
		t.Errorf("import review shows %s: %s", attr, b)
	}
}

func TestGroupDeletedHook(t *testing.T) {
	e := newEnv(t)
	id := e.ll.AddGroup("office_milan", "alice")
	type call struct {
		actor, name string
		id          int
	}
	var calls []call
	e.svc.GroupDeleted = func(_ context.Context, actor, name string, gid int) []string {
		calls = append(calls, call{actor, name, gid})
		return []string{"purged rows"}
	}
	// A failing LLDAP delete: no call.
	real := e.svc.LLDAP
	e.svc.LLDAP = failGroupDelete{real}
	if _, err := e.svc.DeleteGroup(ctx, asRoot, "office_milan", "office_milan"); err == nil {
		t.Fatal("failing delete succeeded")
	}
	if len(calls) != 0 {
		t.Fatalf("hook called for a failed delete: %+v", calls)
	}
	e.svc.LLDAP = real
	if _, err := e.svc.DeleteGroup(ctx, asRoot, "ghost", "ghost"); err == nil {
		t.Fatal("deleting a missing group succeeded")
	}
	if len(calls) != 0 {
		t.Fatalf("hook called for a missing group: %+v", calls)
	}
	res, err := e.svc.DeleteGroup(ctx, asRoot, "office_milan", "office_milan")
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != (call{"root", "office_milan", id}) {
		t.Errorf("calls = %+v (id %d)", calls, id)
	}
	if !strings.Contains(strings.Join(res.Warnings, ";"), "purged rows") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

// brokenDir is an LLDAP that is unavailable.
type brokenDir struct{ directory.Directory }

func (brokenDir) Available() error { return errUnavailable }

var errUnavailable = &directory.Error{Status: 503, Msg: "LLDAP credentials missing"}

func TestMembershipCarriesUUID(t *testing.T) {
	e := newEnv(t)
	m, err := e.svc.Membership(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	want := e.ll.UUIDOf("alice")
	if want == "" || m.UUIDs["alice"] != want {
		t.Errorf("uuids[alice] = %q, want %q (%+v)", m.UUIDs["alice"], want, m.UUIDs)
	}
	if _, ok := m.UUIDs["portcullis-hub"]; ok {
		t.Errorf("service account in UUIDs: %+v", m.UUIDs)
	}
	if m.UUIDs["root"] == "" || m.UUIDs["root"] == want {
		t.Errorf("uuids[root] = %q", m.UUIDs["root"])
	}
}

func TestUserDeletedHook(t *testing.T) {
	e := newEnv(t)
	type call struct{ actor, name string }
	var calls []call
	e.svc.UserDeleted = func(_ context.Context, actor, name string) []string {
		calls = append(calls, call{actor, name})
		return []string{"purged entries"}
	}
	real := e.svc.LLDAP
	e.svc.LLDAP = failUserDelete{real}
	if _, err := e.svc.DeleteUser(ctx, asRoot, "alice", "alice"); err == nil {
		t.Fatal("failing delete succeeded")
	}
	if len(calls) != 0 {
		t.Fatalf("hook called for a failed delete: %+v", calls)
	}
	e.svc.LLDAP = real
	res, err := e.svc.DeleteUser(ctx, &directory.Caller{User: "Root", Admin: true}, "alice", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != (call{"root", "alice"}) {
		t.Errorf("calls = %+v", calls)
	}
	if !strings.Contains(strings.Join(res.Warnings, ";"), "purged entries") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

type failUserDelete struct{ directory.Directory }

func (failUserDelete) DeleteUser(context.Context, string) error {
	return errors.New("simulated LLDAP failure")
}
