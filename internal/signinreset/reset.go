// Package signinreset is `hub signin reset-core` (contract §8.1 "Lockout
// guard and signin reset-core", plan D17): the CLI's recovery when no
// administrator can sign in to the Hub. It runs against the Hub's data
// directory while the Hub is stopped (core's `./portcullis signin
// reset-core` stops it first and starts it after): `hub` and `people` go
// back to the built-in Standard template, Standard's rule is restored and
// enabled, and its methods are switched back on — browser_cert is never
// switched on by the reset (it stays as it was: off unless an admin
// switched it on; forcing it off could leave an enabled template that
// needs it unmeetable, and such a state.yaml never loads).
// Audited `signin.reset_core`, actor `cli`.
package signinreset

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/state"
)

// standard is the built-in Standard template.
func standard() signin.Template {
	for _, b := range signin.Builtins() {
		if b.ID == state.DefaultSignInTemplate {
			return b
		}
	}
	panic("signinreset: no built-in standard template")
}

// standardMethods are the methods the reset switches on: Standard's
// families' members except browser_cert (a copied certificate file is
// never what a lockout recovery opens).
var standardMethods = []signin.Method{signin.PasskeySynced, signin.PasskeyDevice, signin.SecurityKey, signin.YubiKeyCert}

const usage = "usage: hub signin reset-core"

// Main runs `hub signin <args>` against dataDir, printing what changed
// to out: 0 done (also when nothing had to change), 1 failed, 2 usage.
func Main(args []string, dataDir string, out io.Writer) int {
	if len(args) != 1 || args[0] != "reset-core" {
		fmt.Fprintln(out, usage)
		return 2
	}
	changes, err := ResetCore(dataDir)
	for _, c := range changes {
		fmt.Fprintln(out, c)
	}
	if err != nil {
		fmt.Fprintf(out, "signin reset-core: %v\n", err)
		return 1
	}
	if len(changes) == 0 {
		fmt.Fprintln(out, "signin reset-core: nothing to change: hub and people already use Standard, which is enabled with its methods on")
	}
	return 0
}

// ResetCore applies the reset to <dataDir>/state.yaml and audits it in
// <dataDir>/audit.jsonl; it returns what changed (nil: nothing).
func ResetCore(dataDir string) ([]string, error) {
	path := filepath.Join(dataDir, "state.yaml")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s doesn't exist: is %s the Hub's data directory?", path, dataDir)
		}
		return nil, err
	}
	// Never under a running Hub: it would overwrite the reset with its
	// own state on its next save.
	release, err := fsutil.TryLock(filepath.Join(dataDir, state.LockFile))
	if err != nil {
		if errors.Is(err, fsutil.ErrLocked) {
			return nil, errors.New("the Hub is running on this data directory: stop it first (./portcullis signin reset-core does)")
		}
		return nil, err
	}
	defer release()
	st, err := state.Load(path)
	if err != nil {
		return nil, err
	}
	st.EnsureSignIn()
	si := &st.SignIn
	var changes []string
	for _, k := range []string{"hub", "people"} {
		if si.Core[k] != state.DefaultSignInTemplate {
			changes = append(changes, fmt.Sprintf("core page %s: %s -> %s", k, coreName(si.Core[k]), state.DefaultSignInTemplate))
			si.Core[k] = state.DefaultSignInTemplate
		}
	}
	b := standard()
	t := si.Templates[b.ID]
	want := state.SignInTemplate{Name: b.Name, Rule: state.CloneNode(b.Rule), Enabled: true, BuiltIn: true}
	if t.Name != want.Name || !sameJSON(t.Rule, want.Rule) {
		changes = append(changes, fmt.Sprintf("template standard: restored to the built-in rule (%s)", signin.Sentence(want.Rule)))
	}
	if !t.Enabled {
		changes = append(changes, "template standard: enabled")
	}
	si.Templates[b.ID] = want
	for _, m := range standardMethods {
		if !si.Methods[string(m)] {
			changes = append(changes, fmt.Sprintf("method %s: off -> on", m))
			si.Methods[string(m)] = true
		}
	}
	audit := &directory.AuditLog{Path: filepath.Join(dataDir, "audit.jsonl")}
	detail := "nothing to change"
	if len(changes) > 0 {
		if err := st.Save(path); err != nil {
			_ = audit.Append(directory.AuditEntry{Actor: "cli", Action: "signin.reset_core", Target: "core", Detail: strings.Join(changes, "; "), Result: "error", Error: err.Error()})
			return nil, err
		}
		detail = strings.Join(changes, "; ")
	}
	if err := audit.Append(directory.AuditEntry{Actor: "cli", Action: "signin.reset_core", Target: "core", Detail: detail, Result: "ok"}); err != nil {
		return changes, fmt.Errorf("the reset was saved, but writing the audit log failed: %w", err)
	}
	return changes, nil
}

func coreName(id string) string {
	if id == "" {
		return "default"
	}
	return id
}

func sameJSON(a, b signin.Node) bool {
	x, err1 := a.MarshalJSON()
	y, err2 := b.MarshalJSON()
	return err1 == nil && err2 == nil && string(x) == string(y)
}
