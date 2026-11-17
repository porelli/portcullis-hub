package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

var rootActor = directory.Actor{User: "root"}

func TestHostGroupTemplateUnusable409(t *testing.T) {
	f := newHostFixture(t)
	// A template no phishing-resistant method can meet: password only.
	f.h.mu.Lock()
	f.h.st.SignIn.Templates["pwonly"] = state.SignInTemplate{Name: "Password", Rule: signin.Node{Leaf: "password"}, Enabled: true}
	f.h.mu.Unlock()
	err := f.h.SaveHostGroup(context.Background(), rootActor, "db", state.SSHHostGroup{Template: "pwonly"}, true, nil)
	if sshStatusOf(err) != 409 && !strings.Contains(errText(err), "can't be met") {
		t.Errorf("unusable template = %v", err)
	}
	if err := f.h.SaveHostGroup(context.Background(), rootActor, "db", state.SSHHostGroup{Template: "strong"}, true, nil); err != nil {
		t.Errorf("strong = %v", err)
	}
	if err := f.h.SaveHostGroup(context.Background(), directory.Actor{User: "root", Via: directory.ViaAI}, "db2", state.SSHHostGroup{}, true, nil); err == nil {
		t.Error("a host group via AI")
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestUpdateHostNeedsFresh(t *testing.T) {
	f := newHostFixture(t)
	f.h.mu.Lock()
	f.h.st.SSH.HostGroups["db"] = state.SSHHostGroup{}
	f.h.mu.Unlock()
	in := HostInput{Names: []string{"web-2.example.com"}, HostGroups: []string{"web"}}
	// Unchanged: no proof needed.
	if err := f.h.UpdateHost(context.Background(), rootActor, "web-2", in, nil); err != nil {
		t.Errorf("unchanged = %v", err)
	}
	in.HostGroups = []string{"web", "db"}
	if err := f.h.UpdateHost(context.Background(), rootActor, "web-2", in, nil); err == nil {
		t.Error("a host group added without a fresh sign-in")
	}
	if err := f.h.UpdateHost(context.Background(), directory.Actor{User: "root", Via: directory.ViaAI}, "web-2", in, &freshauth.Proof{Code: "c"}); err == nil {
		t.Error("a host changed via AI")
	}
	if err := f.h.UpdateHost(context.Background(), rootActor, "web-2", in, &freshauth.Proof{Code: "c"}); err != nil {
		t.Errorf("with a fresh sign-in = %v", err)
	}
	if got := f.h.st.SSH.Hosts["web-2"].HostGroups; strings.Join(got, ",") != "db,web" {
		t.Errorf("groups %v", got)
	}
	in.Names = []string{"other.example.com"}
	if err := f.h.UpdateHost(context.Background(), rootActor, "web-2", in, nil); err == nil {
		t.Error("names changed without a fresh sign-in")
	}
}

func TestHostCertificateNeedsSecurityKeyAdmin(t *testing.T) {
	f := newHostFixture(t)
	f.h.mu.Lock()
	g := f.h.st.SSH.HostGroups["web"]
	g.Patterns = []string{"*.lab.example.com"}
	f.h.st.SSH.HostGroups["web"] = g
	f.h.mu.Unlock()
	key := hostKey(t)
	req := HostKeyRequest{HostGroup: "web", PublicKey: key, Names: []string{"web-9.lab.example.com"}}
	f.h.SetFreshAuth(ListenerHub, fakeFresh{method: "passkey_device"})
	if _, err := f.h.SignHostKey(context.Background(), rootActor, req, freshauth.Proof{}); err == nil || sshStatusOf(err) != 403 && !strings.Contains(err.Error(), "security key") {
		t.Errorf("passkey_device = %v", err)
	}
	f.h.SetFreshAuth(ListenerHub, fakeFresh{method: "security_key"})
	ans, err := f.h.SignHostKey(context.Background(), rootActor, req, freshauth.Proof{})
	if err != nil || ans.Certificate == "" {
		t.Fatalf("security_key = %+v %v", ans, err)
	}
	req.Names = []string{"evil.example.org"}
	if _, err := f.h.SignHostKey(context.Background(), rootActor, req, freshauth.Proof{}); sshStatusOf(err) != 409 {
		t.Errorf("a name outside the patterns = %v", err)
	}
	req.Names = []string{"web-1.example.com"} // a managed host of web
	if _, err := f.h.SignHostKey(context.Background(), rootActor, req, freshauth.Proof{}); err != nil {
		t.Errorf("a managed host's name = %v", err)
	}
	if _, err := f.h.SignHostKey(context.Background(), directory.Actor{User: "root", Via: directory.ViaAI}, req, freshauth.Proof{}); err == nil {
		t.Error("a host key signed via AI")
	}
	if e := f.audit.lastOf("ssh.host_certificate.issue"); e.Actor != "root" || !strings.Contains(e.Detail, "key SHA256:") {
		t.Errorf("audit %+v", e)
	}
	// The CLI route: an administrator with security_key.
	sf := newSignFixture(t, "alice", "security_key")
	_, err = sf.h.SignHostKeyCLI(context.Background(), cliapi.HostCertRequest{Code: "x", HostGroup: "web", PublicKey: key, Names: []string{"web-1.example.com"}}, "192.0.2.5")
	if sshStatusOf(err) != 403 {
		t.Errorf("alice (not an administrator) = %v", err)
	}
}

func TestAccessPreviewRootFilterHub(t *testing.T) {
	f := newSSHFixture(t)
	f.compile(t)
	rows, err := f.h.SSHAccess("host", "web-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Person != "alice" || !rows[0].Sudo {
		t.Errorf("root-only rows %+v", rows)
	}
	if _, err := f.h.SSHAccess("host", "nope", false); err == nil {
		t.Error("unknown host")
	}
	if rows, _ := f.h.SSHAccess("person", "bob", false); len(rows) != 2 {
		t.Errorf("bob's rows %+v", rows)
	}
}

func TestPersonSSHAccess(t *testing.T) {
	f := newSignFixture(t, "alice", "security_key")
	if _, err := f.h.SignSSH(context.Background(), f.request(t, f.signer), "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	v := f.h.PersonSSHAccess("alice")
	if len(v.HostGroups) != 2 || v.HostGroups[0].ID != "all" || !v.HostGroups[0].Sudo || v.HostGroups[1].Accounts[0] != "alice" {
		t.Errorf("groups %+v", v.HostGroups)
	}
	if len(v.Certificates) != 2 {
		t.Errorf("certificates %+v", v.Certificates)
	}
	n, err := f.h.RevokeAllSSH(rootActor, "alice", "test")
	if err != nil || n != 1 {
		t.Errorf("revoke all = %d %v", n, err)
	}
}

func TestImportBreakglass(t *testing.T) {
	f := newSSHFixture(t)
	p := filepath.Join(t.TempDir(), "breakglass.jsonl")
	f.h.cfg.SSHBreakglassFile = p
	os.WriteFile(p, []byte(`{"time":"2026-11-15T08:00:00Z","user":"alice","host_group":"web","principals":["u:alice@web"],"key_fp":"SHA256:x","serial":"77","valid_before":"2026-11-15T09:00:00Z","note":"hub down"}
not json
{"time":"2026-11-15T08:00:00Z","user":"bob","extra":1,"serial":"78"}

`), 0o600)
	n, bad := f.h.ImportBreakglass()
	if n != 1 || bad != 2 {
		t.Errorf("imported %d malformed %d", n, bad)
	}
	e := f.audit.lastOf("ssh.certificate.breakglass")
	if e.Target != "alice" || !strings.Contains(e.Detail, "serial=77") || !strings.Contains(e.Detail, "note=hub down") {
		t.Errorf("audit %+v", e)
	}
	// Once only.
	if n, _ := f.h.ImportBreakglass(); n != 0 {
		t.Errorf("imported again: %d", n)
	}
	if in := f.h.doctorSSHIn(); in.BreakglassImported != 1 {
		t.Errorf("doctor input %d", in.BreakglassImported)
	}
}
