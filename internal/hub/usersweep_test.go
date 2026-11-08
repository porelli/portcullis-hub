package hub

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
)

// Guarded stale-record sweep (usersweep.go): each guard pauses or skips
// the Keycloak revalidation; an audited, typed resume restarts it.

type fakeLDAPUsers struct {
	mu    sync.Mutex
	users []string
	err   error
	svc   string
}

func (f *fakeLDAPUsers) ListUsers(ctx context.Context) ([]lldap.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := make([]lldap.User, 0, len(f.users))
	for _, u := range f.users {
		out = append(out, lldap.User{ID: u})
	}
	return out, nil
}
func (f *fakeLDAPUsers) ServiceUser() string { return f.svc }
func (f *fakeLDAPUsers) set(users ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = users
}

type fakeRevalidator struct {
	mu   sync.Mutex
	runs int
	err  error
}

func (f *fakeRevalidator) RevalidateUsers(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.runs++
	return 0, nil
}
func (f *fakeRevalidator) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

// people returns admin, the service account and n more users.
func people(n int) []string {
	out := []string{"admin", "portcullis-hub"}
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("u%02d", i))
	}
	return out
}

func newSweep(t *testing.T) (*fixture, *fakeLDAPUsers, *fakeRevalidator) {
	t.Helper()
	f := newFixture(t)
	ll := &fakeLDAPUsers{svc: "portcullis-hub", users: people(18)} // 20 users
	kc := &fakeRevalidator{}
	f.h.SetUserSweep(ll, kc)
	return f, ll, kc
}

func TestUserSweepRunsAndKeepsBaseline(t *testing.T) {
	f, ll, kc := newSweep(t)
	if !f.h.RunUserSweep(context.Background()) || kc.count() != 1 {
		t.Fatal("healthy LLDAP: no sweep")
	}
	if st := f.h.UserSweep(); st.LastOKCount != 20 || st.Paused || st.Skipped != "" || !st.Configured {
		t.Errorf("status = %+v", st)
	}
	// A small drop (-2) and a big relative drop of only 2 accounts both pass.
	ll.set(people(16)...)
	if !f.h.RunUserSweep(context.Background()) {
		t.Error("a drop of 2 accounts paused the sweep")
	}
	// The baseline survives a restart (state file).
	f.h.SetUserSweep(ll, kc)
	if st := f.h.UserSweep(); st.LastOKCount != 18 {
		t.Errorf("baseline after restart = %d", st.LastOKCount)
	}
}

func TestUserSweepPausesOnCountDrop(t *testing.T) {
	f, ll, kc := newSweep(t)
	f.h.RunUserSweep(context.Background())
	ll.set(people(13)...) // 20 → 15: −5 (25 %, > 2)
	if f.h.RunUserSweep(context.Background()) || kc.count() != 1 {
		t.Fatal("swept after a 25 % drop")
	}
	st := f.h.UserSweep()
	if !st.Paused || !strings.Contains(st.Reason, "15 users, 20 at the last cleanup") || st.Skipped != "" || !st.SkippedSince.IsZero() {
		t.Errorf("status = %+v", st)
	}
	// Sticky: LLDAP back to normal doesn't resume by itself.
	ll.set(people(18)...)
	if f.h.RunUserSweep(context.Background()) || kc.count() != 1 {
		t.Error("a paused sweep ran")
	}
	// 4 of 20 (20 %, not more) is not a pause.
	f2, ll2, _ := newSweep(t)
	f2.h.RunUserSweep(context.Background())
	ll2.set(people(14)...)
	if !f2.h.RunUserSweep(context.Background()) {
		t.Error("a 20 % drop paused")
	}
}

func TestUserSweepPausesWithoutCoreAccounts(t *testing.T) {
	for name, users := range map[string][]string{
		"no admin":           people(18)[1:],
		"no service account": append([]string{"admin"}, people(18)[2:]...),
		"empty":              {},
	} {
		t.Run(name, func(t *testing.T) {
			f, ll, kc := newSweep(t)
			ll.set(users...)
			if f.h.RunUserSweep(context.Background()) || kc.count() != 0 {
				t.Fatal("swept")
			}
			if st := f.h.UserSweep(); !st.Paused || !strings.Contains(st.Reason, "LLDAP has no") {
				t.Errorf("status = %+v", st)
			}
		})
	}
}

func TestUserSweepSkipsWhileUnreachable(t *testing.T) {
	f, ll, kc := newSweep(t)
	ll.err = errors.New("connection refused")
	if f.h.RunUserSweep(context.Background()) || kc.count() != 0 {
		t.Fatal("swept with LLDAP down")
	}
	st := f.h.UserSweep()
	if st.Paused || !strings.Contains(st.Skipped, "unreachable") || st.SkippedSince.IsZero() {
		t.Errorf("status = %+v", st)
	}
	firstSkippedSince := st.SkippedSince
	// A second skip keeps the same SkippedSince.
	if f.h.RunUserSweep(context.Background()) {
		t.Error("swept with LLDAP still down")
	}
	st = f.h.UserSweep()
	if st.SkippedSince != firstSkippedSince {
		t.Errorf("SkippedSince changed: %v -> %v", firstSkippedSince, st.SkippedSince)
	}
	ll.err = nil
	if !f.h.RunUserSweep(context.Background()) {
		t.Error("not swept after LLDAP came back")
	}
	st = f.h.UserSweep()
	if st.Skipped != "" || !st.SkippedSince.IsZero() {
		t.Errorf("skip not cleared: %+v", st)
	}
	kc.err = errors.New("keycloak down")
	if f.h.RunUserSweep(context.Background()) || !strings.Contains(f.h.UserSweep().Skipped, "keycloak down") {
		t.Error("Keycloak failure not reported")
	}
	// Success clears Keycloak skip too.
	kc.err = nil
	if !f.h.RunUserSweep(context.Background()) {
		t.Error("not swept after Keycloak came back")
	}
	st = f.h.UserSweep()
	if st.Skipped != "" || !st.SkippedSince.IsZero() {
		t.Errorf("Keycloak skip not cleared: %+v", st)
	}
}

func TestUserSweepCorruptStatePauses(t *testing.T) {
	f, _, kc := newSweep(t)
	if err := os.WriteFile(f.h.sweep.path, []byte("{nope"), 0600); err != nil {
		t.Fatal(err)
	}
	if f.h.RunUserSweep(context.Background()) || kc.count() != 0 || !f.h.UserSweep().Paused {
		t.Error("corrupt baseline didn't pause")
	}
}

func TestUserSweepResume(t *testing.T) {
	f, ll, kc := newSweep(t)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	g := &fakeGroups{}
	f.h.SetGroups(g)
	ctx := context.Background()
	f.h.RunUserSweep(ctx)
	if _, err := f.h.ResumeUserSweep(ctx, directory.Human("alice"), SweepResumeConfirm); err == nil {
		t.Error("resumed a sweep that isn't paused")
	}
	ll.set(people(5)...)
	f.h.RunUserSweep(ctx)
	if _, err := f.h.ResumeUserSweep(ctx, directory.Human("alice"), "yes"); err == nil || !f.h.UserSweep().Paused {
		t.Errorf("wrong confirm: %v", err)
	}
	if e := audit.last(); e.Action != "keycloak.sweep_resume" || e.Result != "refused" {
		t.Errorf("audit = %+v", e)
	}
	if _, err := f.h.ResumeUserSweep(ctx, directory.Human(""), SweepResumeConfirm); err == nil {
		t.Error("no actor accepted")
	}
	g.actorErr = errors.New("not an administrator")
	if _, err := f.h.ResumeUserSweep(ctx, directory.Human("dana"), SweepResumeConfirm); err == nil || !f.h.UserSweep().Paused {
		t.Errorf("non-admin: %v", err)
	}
	g.actorErr = nil
	st, err := f.h.ResumeUserSweep(ctx, directory.Human("alice"), SweepResumeConfirm)
	if err != nil || st.Paused || st.LastOKCount != 7 || st.ResumedBy != "alice" {
		t.Fatalf("resume: %+v %v", st, err)
	}
	if e := audit.last(); e.Action != "keycloak.sweep_resume" || e.Result != "ok" || e.Actor != "alice" || !strings.Contains(e.Detail, "new baseline 7") {
		t.Errorf("audit = %+v", e)
	}
	if !f.h.RunUserSweep(ctx) || kc.count() != 2 {
		t.Error("not swept after the resume")
	}
	// The account checks still apply after a resume.
	ll.set(people(5)[1:]...)
	if f.h.RunUserSweep(ctx) || !f.h.UserSweep().Paused {
		t.Error("admin missing after a resume: swept")
	}
}
