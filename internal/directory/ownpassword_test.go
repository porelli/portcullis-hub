package directory_test

import (
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
)

// TestOwnPassword (contract §5.1 "Sign-in page"): the caller sets and
// removes their own password only; both sign them out of Keycloak and
// are audited signin.password; the set is recorded with set_by = the
// caller, the removal isn't; protected and reserved accounts refused.
func TestOwnPassword(t *testing.T) {
	e := newEnv(t)
	e.kc.Import("alice")
	var recorded []string
	e.svc.PasswordSet = func(user, uuid, actor string) error {
		recorded = append(recorded, user+"/"+actor)
		return nil
	}
	const pw = "correct horse battery staple 42"
	logouts := func() int { return e.kc.CountCalls("POST /admin/realms/portcullis/users/") }
	before := logouts()
	if _, err := e.svc.SetOwnPassword(ctx, directory.Human("Alice"), pw); err != nil {
		t.Fatal(err)
	}
	if e.ll.Password("alice") != pw {
		t.Error("the password wasn't set")
	}
	if logouts() == before {
		t.Error("not signed out of Keycloak")
	}
	if a := newestAudit(t, e, "signin.password"); a.Actor != "alice" || a.Target != "alice" || a.Detail != "self set" || a.Result != "ok" {
		t.Errorf("audit = %+v", a)
	}
	if strings.Join(recorded, ",") != "alice/alice" {
		t.Errorf("recorded %v", recorded)
	}
	if _, err := e.svc.SetOwnPassword(ctx, directory.Human("alice"), "short"); status(err) != 400 {
		t.Errorf("short: %v", err)
	}
	before = logouts()
	if _, err := e.svc.RemoveOwnPassword(ctx, directory.Human("alice")); err != nil {
		t.Fatal(err)
	}
	if got := e.ll.Password("alice"); got == pw || len(got) < 40 {
		t.Errorf("removal left %q", got)
	}
	if logouts() == before {
		t.Error("removal didn't sign out")
	}
	if a := newestAudit(t, e, "signin.password"); a.Detail != "self removed" || a.Result != "ok" {
		t.Errorf("removal audit = %+v", a)
	}
	if len(recorded) != 1 {
		t.Errorf("the removal was recorded: %v", recorded)
	}
	for _, u := range []string{"admin", "portcullis-hub", "portcullis-x"} {
		if _, err := e.svc.SetOwnPassword(ctx, directory.Human(u), pw); status(err) != 409 {
			t.Errorf("%s: %v", u, err)
		}
	}
}
