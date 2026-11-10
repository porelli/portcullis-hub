package hub

import (
	"context"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/doctor"
)

// TestHubAuditCarriesActor (Task 7c): an instance delete by a via-AI
// actor — the instance.delete entry, the groups it deletes in Users &
// Groups and its refusal all carry via ai and the client; the op record
// keeps the user only.
func TestHubAuditCarriesActor(t *testing.T) {
	f, audit, _ := privFixture(t)
	dir, _ := hubDirectory(t, f)
	if err := f.h.CreateInstance("privapp", "privapp2", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.EnableAs("privapp2", directory.Human("root")); err != nil {
		t.Fatal(err)
	}

	// A refused delete (the id not typed) is audited refused, via ai.
	n := auditLen(audit)
	if _, err := f.h.DeleteInstance("privapp2", "wrong", aiActor); errStatus(err) != 400 {
		t.Fatalf("untyped delete = %v, want 400", err)
	}
	got := entriesSince(audit, n)
	wantVia(t, "refused delete", got, "instance.delete")
	if len(got) != 1 || got[0].Result != "refused" || got[0].Target != "privapp2" {
		t.Errorf("refused delete entries = %+v", got)
	}

	n = auditLen(audit)
	op, err := f.h.StartDelete("privapp2", "privapp2", aiActor)
	if err != nil {
		t.Fatal(err)
	}
	rec := waitOp(t, f.h, "privapp2", op.OpID)
	if !rec.OK {
		t.Fatalf("delete = %+v", rec)
	}
	if rec.Actor != "root" {
		t.Errorf("op record actor = %q, want the user only", rec.Actor)
	}
	var del []directory.AuditEntry
	for _, e := range entriesSince(audit, n) {
		if e.Action == "instance.delete" {
			del = append(del, e)
		}
	}
	wantVia(t, "instance delete", del, "instance.delete")
	if len(del) != 1 || del[0].Result != "ok" || del[0].Target != "privapp2" {
		t.Errorf("instance.delete entries = %+v", del)
	}
	gd := dirEntries(t, dir, "group.delete")
	if len(gd) != 2 {
		t.Errorf("group.delete entries = %+v, want privapp2's two groups", gd)
	}
	wantVia(t, "instance delete's groups", gd, "group.delete")
}

// TestRevokeLeaverFixCarriesActor (Task 7c, 7b carry): the revoke_leaver
// doctor fix applied by a via-AI actor writes doctor.fix and the
// credential.revoke it causes, both with via ai and the client;
// revoked_by stays the user.
func TestRevokeLeaverFixCarriesActor(t *testing.T) {
	ctx := context.Background()
	c := credSvcFixture(t)
	f := c.f
	c.create(t, "bob")
	c.people.removeMember("users_"+smbID, "bob")
	got := findingsOf(t, f, doctor.KindCredentialWithoutAccess)
	if len(got) != 1 {
		t.Fatalf("canary = %+v", got)
	}
	plan, err := f.h.PreviewFix(ctx, got[0].FP, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := auditLen(c.audit)
	// A revocation touches data (G45, Task 20): from the AI it runs only
	// with the confirmation the tool consumed.
	confirmed := aiActor
	confirmed.Confirmation = "AAAA-BBBB-CCCC"
	op, err := f.h.ApplyFix(ctx, got[0].FP, nil, plan.Hash, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	if r := waitInstanceOp(t, f, smbID, op.OpID); !r.OK || r.Actor != "root" {
		t.Fatalf("op = %+v, want ok by root", r)
	}
	settle(f)
	entries := entriesSince(c.audit, n)
	wantVia(t, "revoke_leaver", entries, "doctor.fix", "credential.revoke")
	for _, e := range entries {
		if e.Action == "credential.revoke" && (e.Target != smbID+"/"+smbKey+"/bob" || e.Result != "ok") {
			t.Errorf("credential.revoke = %+v", e)
		}
	}
	if m, _ := credOf(f.h, smbID, "bob"); m.RevokedBy != "root" {
		t.Errorf("revoked_by = %q, want the user only", m.RevokedBy)
	}
}

// TestAccessChangesAudited (Task 7c fix round 1, G37): a settings save's
// policy and public-exception changes are settings.change entries with
// scope policy / public and before -> after, by the actor with via /
// client; a refused one is refused; public tokens appear as a count,
// never their values; an unchanged policy writes nothing.
func TestAccessChangesAudited(t *testing.T) {
	f := newCloudFixture(t)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	saveAs := func(u SettingsUpdate) ([]directory.AuditEntry, error) {
		t.Helper()
		n := auditLen(audit)
		_, err := f.h.SaveSettings("cloud", u, aiActor)
		f.h.Wait()
		return entriesSince(audit, n), err
	}
	want := func(what string, got []directory.AuditEntry, target, detail, result string) {
		t.Helper()
		wantVia(t, what, got, "settings.change")
		for _, e := range got {
			if e.Target == target {
				if e.Detail != detail || e.Result != result {
					t.Errorf("%s: %s = %q %s, want %q %s", what, target, e.Detail, e.Result, detail, result)
				}
				return
			}
		}
		t.Errorf("%s: no entry for %s in %+v", what, target, got)
	}

	got, err := saveAs(SettingsUpdate{SignInTemplate: pickTemplate("strong")})
	if err != nil {
		t.Fatal(err)
	}
	want("template set", got, "cloud/sign_in_template", "scope=sign_in_template: default -> strong", "ok")

	if got, err = saveAs(SettingsUpdate{SignInTemplate: pickTemplate("strong")}); err != nil || len(got) != 0 {
		t.Errorf("unchanged template: %v, entries %+v", err, got)
	}

	got, err = saveAs(SettingsUpdate{SignInTemplate: pickTemplate("basic")})
	if errStatus(err) != 409 {
		t.Fatalf("disabled template = %v, want 409", err)
	}
	want("template refused", got, "cloud/sign_in_template", "", "refused")

	got, err = saveAs(SettingsUpdate{SignInTemplate: pickTemplate("")})
	if err != nil {
		t.Fatal(err)
	}
	want("template inherit", got, "cloud/sign_in_template", "scope=sign_in_template: strong -> default", "ok")

	got, err = saveAs(SettingsUpdate{PublicAccess: boolp(false)})
	if err != nil {
		t.Fatal(err)
	}
	want("public off", got, "cloud/public_access", "scope=public: default -> off", "ok")

	got, err = saveAs(SettingsUpdate{PublicAccess: boolp(true), PublicMode: strp("listed"), PublicTokens: listp("tok-SECRET-1", "tok-SECRET-2")})
	if err != nil {
		t.Fatal(err)
	}
	want("public on", got, "cloud/public_access", "scope=public: off -> on", "ok")
	want("public tokens", got, "cloud/public_tokens", "scope=public: 0 tokens -> 2 tokens", "ok")

	got, err = saveAs(SettingsUpdate{PublicTokens: listp("tok-SECRET-1", "tok-SECRET-3")})
	if err != nil {
		t.Fatal(err)
	}
	want("public tokens replaced", got, "cloud/public_tokens", "scope=public: 2 tokens -> 2 tokens (changed)", "ok")

	got, err = saveAs(SettingsUpdate{PublicTokens: listp("bad token!")})
	if errStatus(err) != 400 {
		t.Fatalf("bad token = %v, want 400", err)
	}
	want("public tokens refused", got, "cloud/public_tokens", "", "refused")

	audit.mu.Lock()
	defer audit.mu.Unlock()
	for _, e := range audit.entries {
		if strings.Contains(e.Detail+e.Error, "tok-SECRET") || strings.Contains(e.Detail+e.Error, "bad token") {
			t.Errorf("a public token in the audit: %+v", e)
		}
	}
}

// TestRefusedPublicTokenNeverAudited (Task 7c fix round 1, security
// review): a save refused while it carries public tokens audits a fixed
// error ("public token refused" + the refusal class), never the error's
// text — so no form of a submitted token (raw, %q-quoted, a URL's
// segment) reaches the audit.
func TestRefusedPublicTokenNeverAudited(t *testing.T) {
	f := newCloudFixture(t)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	inputs := []string{`raw tok!SECRET1`, `tok"SECRET2`, "https://cloud.example.org/s/seg!SECRET3", "https://other.example.org/x/SECRET4"}
	for _, in := range inputs {
		n := auditLen(audit)
		_, err := f.h.SaveSettings("cloud", SettingsUpdate{PublicMode: strp("listed"), PublicTokens: listp(in)}, aiActor)
		if errStatus(err) != 400 {
			t.Fatalf("%q: %v, want 400", in, err)
		}
		got := entriesSince(audit, n)
		wantVia(t, in, got, "settings.change")
		for _, e := range got {
			if e.Result != "refused" || e.Error != "public token refused (400)" {
				t.Errorf("%q: entry %s = %s %q, want refused with the fixed error", in, e.Target, e.Result, e.Error)
			}
		}
	}
	audit.mu.Lock()
	defer audit.mu.Unlock()
	for _, e := range audit.entries {
		if strings.Contains(e.Detail+e.Error, "SECRET") {
			t.Errorf("a token form in the audit: %+v", e)
		}
	}
}
