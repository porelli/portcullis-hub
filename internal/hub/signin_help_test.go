package hub

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/state"
)

// adminPeople is fakePeople with the administrators filled in (the
// lldap_admin members), as the directory's Membership has them.
type adminPeople struct{ *fakePeople }

func (p adminPeople) Membership(ctx context.Context, now time.Time) (*directory.Membership, error) {
	m, err := p.fakePeople.Membership(ctx, now)
	if err != nil {
		return nil, err
	}
	m.Administrators = map[string]bool{}
	for _, u := range m.Groups[lldap.AdminGroup].Members {
		m.Administrators[strings.ToLower(u)] = true
	}
	return m, nil
}

// fakeHelp is the directory's CheckHelp: admins always; a sign_in_help
// holder on anyone but themselves and the administrators.
type fakeHelp struct {
	admins map[string]bool
	err    error
	// stale: a holder passes on any target (a decision made before a
	// promotion).
	stale bool
}

func (f *fakeHelp) CheckHelp(_ context.Context, c *directory.Caller, target string) error {
	switch {
	case f.err != nil:
		return f.err
	case c.Admin:
		return nil
	case !c.Perms[directory.PermSignInHelp]:
		return &directory.Error{Status: 403, Msg: "not allowed: needs sign_in_help"}
	case f.stale:
		return nil
	case strings.EqualFold(c.User, target) || f.admins[target] || invite.ProtectedName(target):
		return &directory.Error{Status: 403, Msg: "not allowed: " + target + " is an administrator (admins only)"}
	}
	return nil
}

var (
	helpAdmin  = &directory.Caller{User: "root", Admin: true}
	helpHolder = &directory.Caller{User: "bob", Perms: map[string]bool{directory.PermSignInHelp: true}}
	helpNobody = &directory.Caller{User: "carol", Perms: map[string]bool{directory.PermInvite: true}}
)

func newHelpFixture(t *testing.T, certs ...invite.CertRecord) *certFixture {
	t.Helper()
	c := newCertFixture(t, certs...)
	p := newFakePeople("alice", "bob", "carol", "portcullis-breakglass", "portcullis-hooks")
	p.addGroup(lldap.AdminGroup, "root", "ann")
	c.f.h.SetPeople(adminPeople{p})
	c.f.h.SetSignInHelp(&fakeHelp{admins: map[string]bool{"root": true, "ann": true, "admin": true}})
	setSignIn(c.f, func(si *state.SignIn) { si.Methods["yubikey_cert"] = true })
	return c
}

// TestPersonSignInView (D32): admins see everything they may do —
// setup_link, issue and revoke off for an administrator; a holder never
// issues or sets a password; anyone else 403; an unknown person 404.
func TestPersonSignInView(t *testing.T) {
	later := time.Now().Add(60 * 24 * time.Hour)
	c := newHelpFixture(t, invite.CertRecord{User: "alice", Serial: "0a:02", Kind: invite.KindBrowser, NotBefore: time.Now().Add(-time.Hour), NotAfter: later})
	h := c.f.h
	v, err := h.PersonSignInView(c.ctx, helpAdmin, "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if v.User != "alice" || len(v.Certificates) != 1 || v.Can != (HelpCan{SetupLink: true, RemovePasskeys: true, Revoke: true, Issue: true, Password: true}) {
		t.Errorf("admin on alice = %+v", v)
	}
	v, err = h.PersonSignInView(c.ctx, helpAdmin, "ann")
	if err != nil || v.Can != (HelpCan{RemovePasskeys: true, Password: true}) {
		t.Errorf("admin on ann = %+v %v", v, err)
	}
	v, err = h.PersonSignInView(c.ctx, helpHolder, "alice")
	if err != nil || v.Can != (HelpCan{SetupLink: true, RemovePasskeys: true, Revoke: true}) {
		t.Errorf("holder on alice = %+v %v", v, err)
	}
	for _, x := range []struct {
		c    *directory.Caller
		user string
		want int
	}{{helpHolder, "ann", 403}, {helpHolder, "bob", 403}, {helpNobody, "alice", 403}, {nil, "alice", 401},
		{helpAdmin, "nobody", 404}, {helpAdmin, "Not A Name", 400}, {helpHolder, "nobody", 404}} {
		if _, err := h.PersonSignInView(c.ctx, x.c, x.user); statusOf(err) != x.want {
			t.Errorf("%v on %s = %v, want %d", x.c, x.user, err, x.want)
		}
		if _, err := h.PersonSignInHistory(c.ctx, x.c, x.user, "", 10); statusOf(err) != x.want {
			t.Errorf("history %v on %s = %v, want %d", x.c, x.user, err, x.want)
		}
	}
	// The directory can't decide: 503.
	h.SetSignInHelp(nil)
	if _, err := h.PersonSignInView(c.ctx, helpAdmin, "alice"); statusOf(err) != 503 {
		t.Errorf("no directory = %v", err)
	}
}

// TestAdminCertificateTargets (D32, review I3): revoke and issue refuse
// an administrator target and the protected names for everyone, with
// D32's texts, before enroll; alice works.
func TestAdminCertificateTargets(t *testing.T) {
	later := time.Now().Add(60 * 24 * time.Hour)
	c := newHelpFixture(t,
		invite.CertRecord{User: "alice", Serial: "0a:01", Kind: invite.KindYubiKey, NotAfter: later},
		invite.CertRecord{User: "ann", Serial: "0c:01", Kind: invite.KindBrowser, NotAfter: later})
	h := c.f.h
	const adminText = "administrators' certificates are managed from the server: ./portcullis cert revoke <serial>"
	const protText = "this account's certificates are managed from the server: ./portcullis cert revoke <serial>"
	if err := h.RevokePersonCertificate(c.ctx, helpAdmin, "ann", "0c:01"); statusOf(err) != 409 || err.Error() != adminText {
		t.Errorf("revoke ann = %v", err)
	}
	if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "ann", "CSR", testProof); statusOf(err) != 409 || err.Error() != adminText {
		t.Errorf("issue ann = %v", err)
	}
	for _, u := range []string{"admin", "portcullis-hub", "portcullis-breakglass"} {
		if err := h.RevokePersonCertificate(c.ctx, helpAdmin, u, "01"); statusOf(err) != 409 || err.Error() != protText {
			t.Errorf("revoke %s = %v", u, err)
		}
		if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, u, "CSR", testProof); statusOf(err) != 409 || err.Error() != protText {
			t.Errorf("issue %s = %v", u, err)
		}
	}
	if n, _, r := c.ca.counts(); n != 0 || r != 0 || len(c.ca.issues) != 0 {
		t.Fatal("enroll was called for a refused target")
	}
	if c.fa.calls.Load() != 0 {
		t.Error("a proof was spent on a refused target")
	}
	// alice: revoked by the admin (no "as sign_in_help"), then by a holder.
	if err := h.RevokePersonCertificate(c.ctx, helpAdmin, "alice", "0A01"); err != nil {
		t.Fatal(err)
	}
	if e := c.audit.last(); e.Action != "cert.revoke" || e.Actor != "root" || e.Target != "alice" || e.Detail != "yubikey 0a:01" || e.Result != "ok" {
		t.Errorf("admin revoke audit = %+v", e)
	}
	if err := h.RevokePersonCertificate(c.ctx, helpHolder, "alice", "0a:01"); err != nil {
		t.Fatal(err)
	}
	if e := c.audit.last(); e.Actor != "bob" || e.Detail != "yubikey 0a:01; as sign_in_help" {
		t.Errorf("holder revoke audit = %+v", e)
	}
	if !slices.Equal(c.ca.revokes, []string{"alice/0a:01", "alice/0a:01"}) {
		t.Errorf("revokes %v", c.ca.revokes)
	}
	// Not alice's serial: 404; a holder on an administrator: 403; a
	// non-holder 403 — each audited refused.
	if err := h.RevokePersonCertificate(c.ctx, helpAdmin, "alice", "0c:01"); statusOf(err) != 404 {
		t.Errorf("ann's serial on alice = %v", err)
	}
	if err := h.RevokePersonCertificate(c.ctx, helpHolder, "ann", "0c:01"); statusOf(err) != 403 {
		t.Errorf("holder on ann = %v", err)
	}
	if err := h.RevokePersonCertificate(c.ctx, helpNobody, "alice", "0a:01"); statusOf(err) != 403 {
		t.Errorf("non-holder = %v", err)
	}
	if e := c.audit.last(); e.Action != "cert.revoke" || e.Result != "refused" || e.Actor != "carol" {
		t.Errorf("refused audit = %+v", e)
	}
	// Issue for alice by the admin.
	ic, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "alice", "CSR", testProof)
	if err != nil || ic.Serial != "99:aa" || !slices.Equal(c.ca.issues, []string{"alice|CSR"}) {
		t.Fatalf("issue alice = %+v %v (%v)", ic, err, c.ca.issues)
	}
	if e := c.audit.last(); e.Action != "cert.create" || e.Actor != "root" || e.Target != "alice" || e.Detail != "yubikey 99:aa until 2027-11-11" {
		t.Errorf("issue audit = %+v", e)
	}
	// A holder never issues.
	if _, err := h.IssueYubiKeyCertificate(c.ctx, helpHolder, "alice", "CSR", testProof); statusOf(err) != 403 {
		t.Errorf("holder issue = %v", err)
	}
}

// TestIssueYubiKeyFresh (D26): the proof is the admin's, under the
// people template, never password or browser_cert; no method may
// approve → 409 before the proof; yubikey_cert off 409; enroll's CSR
// text (400) passed through.
func TestIssueYubiKeyFresh(t *testing.T) {
	c := newHelpFixture(t)
	h := c.f.h
	for _, m := range []string{"password", "browser_cert"} {
		setSignIn(c.f, func(si *state.SignIn) { si.Methods["password"] = true })
		setPeopleRule(c.f, siLeaves("any", m, "security_key"))
		c.fa.method = m
		if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "alice", "CSR", testProof); statusOf(err) != 403 || err.Error() != freshauth.Message {
			t.Errorf("%s: %v", m, err)
		}
		if e := c.audit.last(); e.Result != "refused" || !strings.Contains(e.Detail, "pc_fresh names "+m) {
			t.Errorf("%s audit = %+v", m, e)
		}
	}
	setPeopleRule(c.f, siLeaves("any", "password"))
	calls := c.fa.calls.Load()
	if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "alice", "CSR", testProof); statusOf(err) != 409 ||
		err.Error() != "creating a certificate needs a passkey or YubiKey sign-in that people.example.org accepts" {
		t.Errorf("any[password]: %v", err)
	}
	if c.fa.calls.Load() != calls {
		t.Error("the proof was spent")
	}
	setPeopleRule(c.f, siLeaves("any", "security_key"))
	c.fa.method = "security_key"
	if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "alice", " ", testProof); statusOf(err) != 400 {
		t.Errorf("no CSR: %v", err)
	}
	c.ca.err = &invite.APIError{Status: 400, Message: "the CSR's signature doesn't verify"}
	if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "alice", "CSR", testProof); statusOf(err) != 400 || err.Error() != "the CSR's signature doesn't verify" {
		t.Errorf("enroll 400: %v", err)
	}
	c.ca.err = errors.New("enroll down")
	if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "alice", "CSR", testProof); statusOf(err) != 503 {
		t.Errorf("enroll down: %v", err)
	}
	c.ca.err = nil
	if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "alice", "CSR", testProof); err != nil {
		t.Errorf("security_key: %v", err)
	}
	setSignIn(c.f, func(si *state.SignIn) { si.Methods["yubikey_cert"] = false })
	if _, err := h.IssueYubiKeyCertificate(c.ctx, helpAdmin, "alice", "CSR", testProof); statusOf(err) != 409 {
		t.Errorf("yubikey_cert off: %v", err)
	}
}

// TestPersonSignInCan (review I2): can matches the routes for an admin
// and a holder on a non-admin, an administrator, admin, portcullis-hub
// and portcullis-hooks, and with yubikey_cert off.
func TestPersonSignInCan(t *testing.T) {
	c := newHelpFixture(t)
	h := c.f.h
	all := HelpCan{SetupLink: true, RemovePasskeys: true, Revoke: true, Issue: true, Password: true}
	for _, x := range []struct {
		caller *directory.Caller
		user   string
		ykOff  bool
		want   HelpCan
		status int
	}{
		{helpAdmin, "alice", false, all, 0},
		{helpAdmin, "alice", true, HelpCan{SetupLink: true, RemovePasskeys: true, Revoke: true, Password: true}, 0},
		{helpAdmin, "ann", false, HelpCan{RemovePasskeys: true, Password: true}, 0},
		{helpAdmin, "admin", false, HelpCan{}, 0},
		{helpAdmin, "portcullis-hub", false, HelpCan{}, 404}, // the service account is no person
		{helpAdmin, "portcullis-hooks", false, HelpCan{RemovePasskeys: true}, 0},
		{helpHolder, "alice", false, HelpCan{SetupLink: true, RemovePasskeys: true, Revoke: true}, 0},
		{helpHolder, "alice", true, HelpCan{SetupLink: true, RemovePasskeys: true, Revoke: true}, 0},
		{helpHolder, "ann", false, HelpCan{}, 403},
		{helpHolder, "admin", false, HelpCan{}, 403},
		{helpHolder, "portcullis-hub", false, HelpCan{}, 403},
		{helpHolder, "portcullis-hooks", false, HelpCan{}, 403},
	} {
		setSignIn(c.f, func(si *state.SignIn) { si.Methods["yubikey_cert"] = !x.ykOff })
		v, err := h.PersonSignInView(c.ctx, x.caller, x.user)
		if x.status != 0 {
			if statusOf(err) != x.status {
				t.Errorf("%s on %s: %v, want %d", x.caller.User, x.user, err, x.status)
			}
			continue
		}
		if err != nil || v.Can != x.want {
			t.Errorf("%s on %s (yubikey off %v): %+v %v, want %+v", x.caller.User, x.user, x.ykOff, v, err, x.want)
		}
	}
}

// TestCertTargetPromotionRace (review m1): a holder's help decided
// before alice became an administrator — the certificate routes' own
// snapshot refuses her (409), enroll isn't called; a non-holder's
// refusal carries no "as sign_in_help" (m2).
func TestCertTargetPromotionRace(t *testing.T) {
	later := time.Now().Add(60 * 24 * time.Hour)
	c := newHelpFixture(t, invite.CertRecord{User: "ann", Serial: "0c:01", Kind: invite.KindBrowser, NotAfter: later})
	h := c.f.h
	h.SetSignInHelp(&fakeHelp{stale: true})
	if err := h.RevokePersonCertificate(c.ctx, helpHolder, "ann", "0c:01"); statusOf(err) != 409 {
		t.Errorf("stale holder on ann = %v", err)
	}
	if err := h.CheckCertTarget(c.ctx, helpHolder, "ann"); statusOf(err) != 409 {
		t.Errorf("CheckCertTarget = %v", err)
	}
	if _, _, n := c.ca.counts(); n != 0 {
		t.Error("enroll was called")
	}
	if err := h.RevokePersonCertificate(c.ctx, helpNobody, "alice", "0c:01"); statusOf(err) != 403 {
		t.Errorf("non-holder = %v", err)
	}
	if e := c.audit.last(); e.Result != "refused" || strings.Contains(e.Detail, "sign_in_help") {
		t.Errorf("non-holder audit = %+v", e)
	}
}

// TestPersonViewMaxMinutes (final review M4): an administrator's view
// carries the configured length (the tab's "at most N min"); a holder's
// is 0.
func TestPersonViewMaxMinutes(t *testing.T) {
	c := newHelpFixture(t)
	h := c.f.h
	for cfg, want := range map[int]int{0: 30, 10: 10, 30: 30} {
		h.cfg.ImpersonationMaxMinutes = cfg
		v, err := h.PersonSignInView(c.ctx, helpAdmin, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if v.MaxMinutes != want {
			t.Errorf("config %d: max_minutes %d, want %d", cfg, v.MaxMinutes, want)
		}
	}
	if v, err := h.PersonSignInView(c.ctx, helpHolder, "alice"); err != nil || v.MaxMinutes != 0 {
		t.Errorf("holder: %+v %v", v, err)
	}
	b, _ := json.Marshal(&PersonSignIn{MaxMinutes: 10})
	if !strings.Contains(string(b), `"max_minutes":10`) {
		t.Errorf("json = %s", b)
	}
}
