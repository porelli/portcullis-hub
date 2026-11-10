package signinreset

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

func TestSignInResetCore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")
	st := state.New()
	si := &st.SignIn
	si.Templates["mine"] = state.SignInTemplate{Name: "Mine", Rule: signin.Node{Op: signin.OpAny, Items: []signin.Node{{Leaf: "yubikey_cert"}}}, Enabled: true}
	si.Core["hub"] = "mine"
	si.Methods[string(signin.SecurityKey)] = false
	si.Methods[string(signin.PasskeySynced)] = false
	std := si.Templates["standard"]
	std.Name, std.Rule = "Changed", signin.Node{Op: signin.OpAny, Items: []signin.Node{{Leaf: "passkey_device"}}}
	si.Templates["standard"] = std
	si.Passwords["bob"] = state.PasswordRecord{SetBy: "root"}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	// A running Hub holds the data directory's lock: refused, untouched.
	release, err := fsutil.TryLock(filepath.Join(dir, state.LockFile))
	if err != nil {
		t.Fatal(err)
	}
	if code := Main([]string{"reset-core"}, dir, &out); code != 1 || !strings.Contains(out.String(), "the Hub is running") {
		t.Errorf("under a running Hub = %d: %s", code, out.String())
	}
	if st2, err := state.Load(path); err != nil || st2.SignIn.Core["hub"] != "mine" {
		t.Errorf("state changed under the lock: %v", err)
	}
	release()
	out.Reset()
	if code := Main([]string{"reset-core"}, dir, &out); code != 0 {
		t.Fatalf("Main = %d: %s", code, out.String())
	}
	for _, want := range []string{"core page hub: mine -> standard", "core page people: strong -> standard", "template standard: restored", "method security_key: off -> on", "method passkey_synced: off -> on"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	got, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	g := got.SignIn
	if g.Core["hub"] != "standard" || g.Core["people"] != "standard" {
		t.Errorf("core = %v", g.Core)
	}
	var b signin.Template
	for _, x := range signin.Builtins() {
		if x.ID == "standard" {
			b = x
		}
	}
	gs := g.Templates["standard"]
	x, _ := json.Marshal(gs.Rule)
	y, _ := json.Marshal(b.Rule)
	if string(x) != string(y) || !gs.Enabled || gs.Name != "Standard" || !gs.BuiltIn {
		t.Errorf("standard = %+v", gs)
	}
	for _, m := range []signin.Method{signin.PasskeySynced, signin.PasskeyDevice, signin.SecurityKey, signin.YubiKeyCert} {
		if !g.Methods[string(m)] {
			t.Errorf("%s off", m)
		}
	}
	if g.Methods[string(signin.BrowserCert)] || g.Methods[string(signin.Password)] {
		t.Errorf("methods = %v", g.Methods)
	}
	// Everything else is kept.
	if _, ok := g.Templates["mine"]; !ok || g.Passwords["bob"].SetBy != "root" || g.Core["portal"] != "" {
		t.Errorf("kept = %+v", g)
	}
	entries, err := (&directory.AuditLog{Path: filepath.Join(dir, "audit.jsonl")}).Recent(10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
	if e := entries[0]; e.Action != "signin.reset_core" || e.Actor != "cli" || e.Result != "ok" || !strings.Contains(e.Detail, "mine -> standard") {
		t.Errorf("audit entry = %+v", e)
	}

	// Again: nothing to change, still exit 0 and audited.
	out.Reset()
	if code := Main([]string{"reset-core"}, dir, &out); code != 0 || !strings.Contains(out.String(), "nothing to change") {
		t.Errorf("second run = %d: %s", code, out.String())
	}
	if code := Main(nil, dir, &out); code != 2 {
		t.Errorf("no args = %d", code)
	}
	if code := Main([]string{"reset-core", "--force"}, dir, &out); code != 2 {
		t.Errorf("extra args = %d", code)
	}
	if code := Main([]string{"reset-core"}, filepath.Join(dir, "nope"), &out); code != 1 {
		t.Errorf("missing state = %d", code)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0600 {
		t.Errorf("state mode = %v, %v", fi, err)
	}
}
