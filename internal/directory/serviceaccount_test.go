package directory_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/lldap/lldaptest"
	"github.com/portcullis/hub/internal/rules"
)

// TestOverviewHidesConfiguredServiceAccount: with a service account other
// than the default name, it — and an account still named portcullis-hub,
// which checkTarget protects too — is left out of users, members, a
// hand-written exception and a hand-written expiry entry, for an
// administrator and for anyone else; service_user names the configured
// one.
func TestOverviewHidesConfiguredServiceAccount(t *testing.T) {
	e := newEnv(t)
	ll := lldaptest.New(t, "svc-hub", svcPass)
	ll.AddUser("root", "root@example.org", "Root", "rootpass-123456", "lldap_admin")
	ll.AddUser("alice", "alice@example.org", "Alice", "alicepass-12345")
	ll.AddUser("portcullis-hub", "old-hub@example.org", "Old Hub", "")
	ll.AddGroup("office", "alice", "svc-hub", "portcullis-hub")
	ll.AddGroup("milan")
	credDir := t.TempDir()
	os.WriteFile(filepath.Join(credDir, "username"), []byte("svc-hub\n"), 0600)
	os.WriteFile(filepath.Join(credDir, "password"), []byte(svcPass+"\n"), 0600)
	e.svc.LLDAP = lldap.New(ll.HTTP.URL, ll.LDAPURL(), ll.BaseDN, credDir)
	e.ll = ll

	// directory.yaml written by hand: an expiry and exceptions naming them.
	store := &directory.Store{Path: filepath.Join(t.TempDir(), "directory.yaml")}
	e.svc.Store = store
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	expr, err := rules.Parse(`city = "Milan"`)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	cfg.Groups["office"] = &directory.GroupConfig{Expiry: map[string]time.Time{"svc-hub": until, "SVC-HUB": until, "alice": until}}
	cfg.Groups["milan"] = &directory.GroupConfig{Rule: expr, Exceptions: []directory.Exception{
		{User: "svc-hub", Reason: "x", By: "root", Include: true, At: until},
		{User: "portcullis-hub", Reason: "x", By: "root", Include: true, At: until},
		{User: "alice", Reason: "y", By: "root", Include: true, At: until},
	}}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}

	hidden := func(u string) bool { return strings.EqualFold(u, "svc-hub") || strings.EqualFold(u, "portcullis-hub") }
	check := func(who string, ov *directory.Overview) {
		t.Helper()
		if ov.ServiceUser != "svc-hub" {
			t.Errorf("%s: service_user = %q", who, ov.ServiceUser)
		}
		for _, u := range ov.Users {
			if hidden(u.Username) {
				t.Errorf("%s: users list %s", who, u.Username)
			}
		}
		seen := 0
		for _, g := range ov.Groups {
			if g.Name == "office" || g.Name == "milan" {
				seen++
			}
			for _, m := range append(append([]string{}, g.Members...), g.Matches...) {
				if hidden(m) {
					t.Errorf("%s: %s lists %s", who, g.Name, m)
				}
			}
			for _, x := range g.Exceptions {
				if hidden(x.User) {
					t.Errorf("%s: %s has an entry for %s", who, g.Name, x.User)
				}
			}
			for u := range g.Expiry {
				if hidden(u) {
					t.Errorf("%s: %s has an end for %s", who, g.Name, u)
				}
			}
			switch g.Name {
			case "office":
				if len(g.Members) != 1 || g.Members[0] != "alice" || len(g.Expiry) != 1 {
					t.Errorf("%s: office = members %v, expiry %v", who, g.Members, g.Expiry)
				}
			case "milan":
				if len(g.Exceptions) != 1 || g.Exceptions[0].User != "alice" {
					t.Errorf("%s: milan entries = %+v", who, g.Exceptions)
				}
			}
		}
		if seen != 2 {
			t.Errorf("%s: office / milan missing", who)
		}
	}
	ov, err := e.svc.Overview(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	check("admin", ov)
	ov, err = e.svc.OverviewFor(ctx, &directory.Caller{User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	check("alice", ov)
	// Both names stay protected.
	for _, u := range []string{"svc-hub", "portcullis-hub"} {
		wantStatus(t, "add "+u, e.svc.AddMember(ctx, asRoot, "office", directory.MemberAdd{Username: u}), 409)
	}
}
