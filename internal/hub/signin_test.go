package hub

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

func signInFixture(t *testing.T) (*fixture, *fakeAudit) {
	t.Helper()
	f := newInstanceFixture(t, nil)
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	// The lockout guard sees an administrator who can meet anything
	// (signin_guard_test.go tests the guard itself).
	ableAdmin(f.h)
	return f, audit
}

func siLeaves(op string, ls ...string) signin.Node {
	n := signin.Node{Op: op}
	for _, l := range ls {
		n.Items = append(n.Items, signin.Node{Leaf: l})
	}
	return n
}

var siAdmin = directory.Human("root")

func TestSetMethodRefusals(t *testing.T) {
	f, audit := signInFixture(t)
	ctx := context.Background()
	if _, err := f.h.SetMethod(ctx, "sms", true, siAdmin); statusOf(err) != 404 {
		t.Errorf("unknown: %v", err)
	}
	if e := audit.last(); e.Action != "signin.method" || e.Result != "refused" || e.Target != "sms" || e.Detail != "on" {
		t.Errorf("unknown audit = %+v", e)
	}
	if _, err := f.h.SetMethod(ctx, signin.Password, true, directory.Human("")); statusOf(err) != 401 {
		t.Errorf("no actor: %v", err)
	}
	// Strong keeps yubikey_cert, Standard the passkeys: nothing needs
	// security_key yet (an "any" group drops an unusable way in).
	if _, err := f.h.SetMethod(ctx, signin.SecurityKey, false, siAdmin); err != nil {
		t.Fatalf("security_key off with Strong only: %v", err)
	}
	if _, err := f.h.SetMethod(ctx, signin.SecurityKey, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	// YubiKey + certificate needs both of its methods; on the Hub page.
	if _, err := f.h.SetTemplateEnabled(ctx, "yubikey-and-certificate", true, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetCoreTemplate(ctx, "hub", "yubikey-and-certificate", siAdmin); err != nil {
		t.Fatal(err)
	}
	for _, m := range []signin.Method{signin.SecurityKey, signin.YubiKeyCert} {
		_, err := f.h.SetMethod(ctx, m, false, siAdmin)
		if statusOf(err) != 409 || !strings.Contains(err.Error(), "YubiKey + certificate") || !strings.Contains(err.Error(), "Hub") {
			t.Errorf("%s off: %v", m, err)
		}
		if e := audit.last(); e.Action != "signin.method" || e.Result != "refused" || e.Target != string(m) || e.Detail != "on -> off" {
			t.Errorf("%s audit = %+v", m, e)
		}
	}
	ch, err := f.h.SetMethod(ctx, signin.Password, true, siAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "signin.method" || e.Result != "ok" || e.Target != "password" || e.Detail != "off -> on" || e.Actor != "root" {
		t.Errorf("audit = %+v", e)
	}
	if !ch.View.Methods[0].On || ch.View.Methods[0].ID != signin.Password || ch.Restarts == nil || ch.Warnings == nil || len(ch.Warnings) != 0 {
		t.Errorf("change = %+v", ch)
	}
	// Unchanged: nothing saved, nothing audited.
	n := len(audit.entries)
	if _, err := f.h.SetMethod(ctx, signin.Password, true, siAdmin); err != nil || len(audit.entries) != n {
		t.Errorf("unchanged: %v, %d entries", err, len(audit.entries)-n)
	}
	// Committed to state.yaml.
	h2 := reopen(t, f)
	if v, _ := h2.SignInView(ctx); !v.Methods[0].On || v.Core["hub"] != "yubikey-and-certificate" {
		t.Errorf("after reopen = %+v", v)
	}
}

func TestTemplateEnableDisableInUse(t *testing.T) {
	f, audit := signInFixture(t)
	ctx := context.Background()
	_, err := f.h.SetTemplateEnabled(ctx, "standard", false, siAdmin)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "the default") {
		t.Errorf("disable the default: %v", err)
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "strong", false, siAdmin); statusOf(err) != 409 || !strings.Contains(err.Error(), "Hub, People") {
		t.Errorf("disable strong (hub, people): %v", err)
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "nope", false, siAdmin); statusOf(err) != 404 {
		t.Errorf("unknown: %v", err)
	}
	if _, err := f.h.SaveTemplate(ctx, "mine", TemplateInput{Name: "Mine", Rule: siLeaves("any", "security_key", "passkey_device")}, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "mine", false, siAdmin); err != nil {
		t.Fatalf("disable an unused template: %v", err)
	}
	if e := audit.last(); e.Action != "signin.template_enabled" || e.Result != "ok" || e.Target != "mine" || e.Detail != "on -> off" {
		t.Errorf("audit = %+v", e)
	}
	// Basic drops password while it is off (any group): it can be enabled.
	// YubiKey + certificate can't be met once security_key is off.
	if _, err := f.h.SetMethod(ctx, signin.SecurityKey, false, siAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "yubikey-and-certificate", true, siAdmin); statusOf(err) != 409 || !strings.Contains(err.Error(), "can't be met") {
		t.Errorf("enable an unmeetable template: %v", err)
	}
	if e := audit.last(); e.Action != "signin.template_enabled" || e.Result != "refused" {
		t.Errorf("audit = %+v", e)
	}
	if _, err := f.h.SetTemplateEnabled(ctx, "basic", true, siAdmin); err != nil {
		t.Errorf("enable basic with password off: %v", err)
	}
	// A disabled template can't be picked.
	if _, err := f.h.SetDefaultTemplate(ctx, "mine", siAdmin); statusOf(err) != 409 {
		t.Errorf("default disabled: %v", err)
	}
	if _, err := f.h.SetCoreTemplate(ctx, "portal", "mine", siAdmin); statusOf(err) != 409 {
		t.Errorf("core disabled: %v", err)
	}
	if _, err := f.h.SetCoreTemplate(ctx, "auth", "", siAdmin); statusOf(err) != 400 {
		t.Errorf("core auth: %v", err)
	}
	if _, err := f.h.SetDefaultTemplate(ctx, "nope", siAdmin); statusOf(err) != 404 {
		t.Errorf("default unknown: %v", err)
	}
	if _, err := f.h.SetDefaultTemplate(ctx, "strong", siAdmin); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "signin.default" || e.Detail != "standard -> strong" {
		t.Errorf("audit = %+v", e)
	}
	if _, err := f.h.SetCoreTemplate(ctx, "hub", "", siAdmin); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "signin.core" || e.Target != "hub" || e.Detail != "strong -> default" {
		t.Errorf("audit = %+v", e)
	}
	if err := f.h.SetAddStronger(true, siAdmin); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "signin.add_stronger" || e.Detail != "off -> on" {
		t.Errorf("audit = %+v", e)
	}
}

func TestDeleteTemplate(t *testing.T) {
	f, audit := signInFixture(t)
	ctx := context.Background()
	if err := f.h.DeleteTemplate(ctx, "basic", siAdmin); statusOf(err) != 409 {
		t.Errorf("built-in: %v", err)
	}
	if err := f.h.DeleteTemplate(ctx, "nope", siAdmin); statusOf(err) != 404 {
		t.Errorf("unknown: %v", err)
	}
	for _, id := range []string{"mine", "theirs"} {
		if _, err := f.h.SaveTemplate(ctx, id, TemplateInput{Name: id, Rule: siLeaves("any", "security_key")}, true, siAdmin); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.h.DeleteTemplate(ctx, "mine", siAdmin); err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Action != "signin.template_delete" || e.Result != "ok" || e.Target != "mine" {
		t.Errorf("audit = %+v", e)
	}
	f.h.mu.Lock()
	f.h.st.Instances["grafana"] = state.Instance{ID: "grafana", Template: "grafana", SignInTemplate: "theirs"}
	f.h.mu.Unlock()
	err := f.h.DeleteTemplate(ctx, "theirs", siAdmin)
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "Grafana") {
		t.Errorf("picked by an instance: %v", err)
	}
	if e := audit.last(); e.Action != "signin.template_delete" || e.Result != "refused" {
		t.Errorf("audit = %+v", e)
	}
	v, _ := f.h.SignInView(ctx)
	for _, tv := range v.Templates {
		if tv.ID == "mine" {
			t.Error("mine still listed")
		}
		if tv.ID == "theirs" && (len(tv.UsedBy) != 1 || tv.UsedBy[0].Kind != UseInstance || tv.UsedBy[0].ID != "grafana") {
			t.Errorf("theirs used_by = %+v", tv.UsedBy)
		}
	}
}

func TestSaveTemplateValidates(t *testing.T) {
	f, audit := signInFixture(t)
	ctx := context.Background()
	deep := signin.Node{Op: "all", Items: []signin.Node{{Op: "any", Items: []signin.Node{{Op: "all", Items: []signin.Node{siLeaves("any", "password", "security_key")}}}}}}
	if _, err := f.h.SaveTemplate(ctx, "deep", TemplateInput{Name: "Deep", Rule: deep}, true, siAdmin); statusOf(err) != 400 {
		t.Errorf("depth 4: %v", err)
	}
	if e := audit.last(); e.Action != "signin.template" || e.Result != "refused" {
		t.Errorf("audit = %+v", e)
	}
	if _, err := f.h.SaveTemplate(ctx, "Bad", TemplateInput{Name: "Bad", Rule: siLeaves("any", "security_key")}, true, siAdmin); statusOf(err) != 400 {
		t.Errorf("id Bad: %v", err)
	}
	for _, name := range []string{"", " padded", strings.Repeat("x", 49), "two\nlines", "zero\u200bwidth"} {
		if _, err := f.h.SaveTemplate(ctx, "named", TemplateInput{Name: name, Rule: siLeaves("any", "security_key")}, true, siAdmin); statusOf(err) != 400 {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if _, err := f.h.SaveTemplate(ctx, "strong", TemplateInput{Name: "Strong 2", Rule: siLeaves("any", "security_key")}, true, siAdmin); statusOf(err) != 409 {
		t.Errorf("create existing: %v", err)
	}
	if _, err := f.h.SaveTemplate(ctx, "nope", TemplateInput{Name: "Nope", Rule: siLeaves("any", "security_key")}, false, siAdmin); statusOf(err) != 404 {
		t.Errorf("update unknown: %v", err)
	}
	// An enabled template is never left with no way in.
	if _, err := f.h.SaveTemplate(ctx, "strong", TemplateInput{Name: "Strong", Rule: siLeaves("all", "password", "security_key")}, false, siAdmin); statusOf(err) != 409 {
		t.Errorf("unmeetable edit: %v", err)
	}
	if _, err := f.h.SaveTemplate(ctx, "pw", TemplateInput{Name: "Password", Rule: siLeaves("any", "password")}, true, siAdmin); statusOf(err) != 409 {
		t.Errorf("unmeetable create: %v", err)
	}
	// A disabled built-in can be edited to anything valid.
	if _, err := f.h.SaveTemplate(ctx, "basic", TemplateInput{Name: "Basic", Rule: siLeaves("any", "password")}, false, siAdmin); err != nil {
		t.Errorf("edit disabled basic: %v", err)
	}
	if e := audit.last(); e.Action != "signin.template" || e.Result != "ok" || !strings.Contains(e.Detail, "rule ") {
		t.Errorf("audit = %+v", e)
	}
	ch, err := f.h.SaveTemplate(ctx, "strong", TemplateInput{Name: "Strong keys", Rule: siLeaves("any", "security_key", "yubikey_cert")}, false, siAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if e := audit.last(); e.Detail != `name "Strong" -> "Strong keys"` {
		t.Errorf("audit = %+v", e)
	}
	for _, tv := range ch.View.Templates {
		if tv.ID == "strong" && (!tv.BuiltIn || !tv.Enabled || tv.Name != "Strong keys" || tv.Score.Tenths != 35) {
			t.Errorf("strong = %+v", tv)
		}
	}
}

func TestPreviewTemplateStoresNothing(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	path := filepath.Join(f.data, "state.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rule := signin.Node{Op: "all", Items: []signin.Node{
		{Op: "any", Items: []signin.Node{siLeaves("all", "password", "security_key"), siLeaves("all", "family:yubikey", "family:passkey")}},
		{Leaf: "family:certificate"},
	}}
	p, err := f.h.PreviewTemplate(ctx, "draft", TemplateInput{Name: "Draft", Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	on := map[signin.Method]bool{signin.PasskeySynced: true, signin.PasskeyDevice: true, signin.SecurityKey: true, signin.YubiKeyCert: true}
	u, err := signin.Usable(rule, on)
	if err != nil {
		t.Fatal(err)
	}
	if p.Sentence != signin.Sentence(u) || p.Score != signin.ScoreOf(rule, on) || p.Problem != "" || p.Affected == nil {
		t.Errorf("preview = %+v", p)
	}
	// D4 example: password off drops all[password, security_key]: 4.4 / 5.
	if p.Score.Tenths != 44 {
		t.Errorf("score = %v", p.Score)
	}
	if p, err := f.h.PreviewTemplate(ctx, "", TemplateInput{Rule: siLeaves("all", "password")}); err != nil || p.Problem == "" || p.Score.Tenths != 0 {
		t.Errorf("unmeetable preview = %+v, %v", p, err)
	}
	if _, err := f.h.PreviewTemplate(ctx, "Bad", TemplateInput{Rule: rule}); statusOf(err) != 400 {
		t.Errorf("bad id: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("state.yaml changed")
	}
	if v, _ := f.h.SignInView(ctx); len(v.Templates) != 4 {
		t.Errorf("templates = %d", len(v.Templates))
	}
}

func TestSignInFailedSaveUndone(t *testing.T) {
	f, audit := signInFixture(t)
	ctx := context.Background()
	// state.yaml can't be replaced: the change is undone in memory.
	if err := os.Chmod(f.data, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(f.data, 0755) })
	if _, err := f.h.SetMethod(ctx, signin.Password, true, siAdmin); statusOf(err) != 500 {
		t.Fatalf("save failure: %v", err)
	}
	if e := audit.last(); e.Action != "signin.method" || e.Result != "error" {
		t.Errorf("audit = %+v", e)
	}
	if v, _ := f.h.SignInView(ctx); v.Methods[0].On {
		t.Error("password still on in memory")
	}
}

func TestSignInHelpers(t *testing.T) {
	f, _ := signInFixture(t)
	ctx := context.Background()
	f.h.mu.RLock()
	c, ok := f.h.compiledLocked("standard")
	_, okDisabled := f.h.compiledLocked("basic")
	pick := f.h.templateForInstanceLocked(f.h.findLocked("grafana"))
	f.h.mu.RUnlock()
	if !ok || okDisabled || signin.ValidateCompiled(c) != nil || pick != "standard" {
		t.Errorf("compiled %v %v %v, pick %q", c, ok, okDisabled, pick)
	}
	if _, err := f.h.SaveTemplate(ctx, "mine", TemplateInput{Name: "Mine", Rule: siLeaves("any", "security_key")}, true, siAdmin); err != nil {
		t.Fatal(err)
	}
	f.h.mu.Lock()
	f.h.st.Instances["grafana"] = state.Instance{ID: "grafana", Template: "grafana", SignInTemplate: "mine"}
	pick = f.h.templateForInstanceLocked(f.h.findLocked("grafana"))
	f.h.mu.Unlock()
	if pick != "mine" {
		t.Errorf("pick = %q", pick)
	}
}

func TestInitPersistsSeededSignIn(t *testing.T) {
	f, _ := signInFixture(t)
	path := filepath.Join(f.data, "state.yaml")
	os.WriteFile(path, []byte("sources:\n  - {name: local, path: "+f.src+"}\n"), 0600)
	h2 := reopen(t, f)
	t.Cleanup(h2.Wait)
	h2.Init()
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "sign_in:") || !strings.Contains(string(b), "yubikey-and-certificate") {
		t.Errorf("state.yaml after Init:\n%s", b)
	}
}
