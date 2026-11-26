package hub

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/keycloak"
)

// chatWithAdditions is v2ChatManifest after a template update: a new
// Keycloak client with its own generated secret, and a plain variable.
var chatWithAdditions = strings.Replace(v2ChatManifest, "env:\n  - key: CHAT_SECRET\n    generate: random\n",
	"  - client_id: chat-extra\n    secret_env: CHAT_EXTRA_SECRET\n    redirect_uri: https://{{HOST_CHAT}}/extra/cb\nenv:\n  - key: CHAT_SECRET\n    generate: random\n  - key: CHAT_EXTRA_SECRET\n    generate: random\n  - key: CHAT_PLAIN\n", 1)

func projUps(f *fixture, project string) int {
	n := 0
	for _, c := range f.runner.Calls() {
		if c == "up:"+project {
			n++
		}
	}
	return n
}

// TestTemplateUpdateAddsEnvAndClients (issue 4, contract §2 "Template
// updates"): after a template update adds a generate: random variable
// and a Keycloak client using it, the next start of an existing instance
// writes the variable (existing values kept) and registers the client
// with exactly that secret before compose up runs.
func TestTemplateUpdateAddsEnvAndClients(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	before := readEnvFile(f.h.envPath("chat-b"))
	if before["CHAT_SECRET"] == "" {
		t.Fatal("no CHAT_SECRET after enable")
	}
	writeFile(t, f.src+"/chat/manifest.yaml", chatWithAdditions)
	f.h.Discover()
	var upsAtRegister = -1
	f.idp.registerHook = func(id string) {
		if strings.HasSuffix(id, "chat-extra") {
			upsAtRegister = projUps(f, "portcullis-chat-b")
		}
	}
	ups := projUps(f, "portcullis-chat-b")
	if err := f.h.RestartApp("chat-b"); err != nil {
		t.Fatal(err)
	}
	env := readEnvFile(f.h.envPath("chat-b"))
	if env["CHAT_SECRET"] != before["CHAT_SECRET"] {
		t.Error("an existing generated value changed")
	}
	if len(env["CHAT_EXTRA_SECRET"]) != 32 {
		t.Errorf("CHAT_EXTRA_SECRET = %q, want a generated value", env["CHAT_EXTRA_SECRET"])
	}
	if v, ok := env["CHAT_PLAIN"]; !ok || v != "" {
		t.Errorf("CHAT_PLAIN = %q %v, want present and empty", v, ok)
	}
	var secret string
	f.idp.mu.Lock()
	for _, s := range f.idp.specs {
		if strings.HasSuffix(s.ClientID, "chat-extra") {
			secret = s.Secret
		}
	}
	f.idp.mu.Unlock()
	if secret == "" || secret != env["CHAT_EXTRA_SECRET"] {
		t.Errorf("registered secret %q, env %q", secret, env["CHAT_EXTRA_SECRET"])
	}
	if upsAtRegister != ups {
		t.Errorf("the client was registered after compose up (ups %d at register, %d before)", upsAtRegister, ups)
	}
	if projUps(f, "portcullis-chat-b") <= ups {
		t.Error("the instance was not started")
	}
	// The next start registers nothing again.
	n := len(f.idp.specs)
	if err := f.h.RestartApp("chat-b"); err != nil {
		t.Fatal(err)
	}
	if len(f.idp.specs) != n {
		t.Errorf("a later start registered again: %v", f.idp.specs[n:])
	}
}

// TestTemplateUpdateClientRegistrationFails (review N1): a failed
// registration refuses the start before compose up and writes nothing
// to the .env; the next start registers with the same values it kept.
func TestTemplateUpdateClientRegistrationFails(t *testing.T) {
	f := chatB(t)
	writeFile(t, f.src+"/chat/manifest.yaml", chatWithAdditions)
	f.h.Discover()
	f.idp.mu.Lock()
	f.idp.registerErr = errors.New("keycloak down")
	f.idp.mu.Unlock()
	ups := projUps(f, "portcullis-chat-b")
	err := f.h.RestartApp("chat-b")
	if statusOf(err) != 502 || !strings.Contains(err.Error(), "chat-extra") || !strings.Contains(err.Error(), "was not started") {
		t.Fatalf("restart = %v", err)
	}
	if projUps(f, "portcullis-chat-b") != ups {
		t.Error("compose up ran after a failed registration")
	}
	env := readEnvFile(f.h.envPath("chat-b"))
	if _, ok := env["CHAT_EXTRA_SECRET"]; ok {
		t.Error("the new secret was written to the .env before its client was registered")
	}
	if _, ok := env["CHAT_PLAIN"]; ok {
		t.Error("the new variable was written to the .env before the registration")
	}
	kept := readEnvFile(f.h.pendingEnvPath("chat-b"))["CHAT_EXTRA_SECRET"]
	if len(kept) != 32 {
		t.Fatalf("pending value = %q", kept)
	}
	f.idp.mu.Lock()
	f.idp.registerErr = nil
	f.idp.mu.Unlock()
	if err := f.h.RestartApp("chat-b"); err != nil {
		t.Fatal(err)
	}
	if got := readEnvFile(f.h.envPath("chat-b"))["CHAT_EXTRA_SECRET"]; got != kept {
		t.Errorf("retry wrote %q, want the kept %q", got, kept)
	}
	if got := extraSecret(f); got != kept {
		t.Errorf("registered %q, want %q", got, kept)
	}
	if fileExists(f.h.pendingEnvPath("chat-b")) {
		t.Error("pending file left behind")
	}
}

// extraSecret is the last secret chat-b-chat-extra was registered with.
func extraSecret(f *fixture) string {
	f.idp.mu.Lock()
	defer f.idp.mu.Unlock()
	s := ""
	for _, sp := range f.idp.specs {
		if strings.HasSuffix(sp.ClientID, "chat-extra") {
			s = sp.Secret
		}
	}
	return s
}

// TestTemplateUpdateCrashAfterRegister (review N1): the Hub dies after
// registering the new client and before writing the .env. The app hasn't
// started; the next start registers again with the same kept value
// (idempotent), then writes it — the .env never holds a secret Keycloak
// doesn't have.
func TestTemplateUpdateCrashAfterRegister(t *testing.T) {
	f := chatB(t)
	writeFile(t, f.src+"/chat/manifest.yaml", chatWithAdditions)
	f.h.Discover()
	crash := errors.New("simulated crash")
	f.h.testHookAdoptRegistered = func(string) error { return crash }
	ups := projUps(f, "portcullis-chat-b")
	if err := f.h.RestartApp("chat-b"); !errors.Is(err, crash) {
		t.Fatalf("restart = %v", err)
	}
	first := extraSecret(f)
	if first == "" {
		t.Fatal("not registered before the crash")
	}
	if _, ok := readEnvFile(f.h.envPath("chat-b"))["CHAT_EXTRA_SECRET"]; ok || projUps(f, "portcullis-chat-b") != ups {
		t.Fatal("the .env was written or the app started before the crash point")
	}
	f.h.testHookAdoptRegistered = nil
	n := len(f.idp.specs)
	if err := f.h.RestartApp("chat-b"); err != nil {
		t.Fatal(err)
	}
	if len(f.idp.specs) == n {
		t.Error("the next start didn't register again")
	}
	if got := extraSecret(f); got != first {
		t.Errorf("re-registered with %q, want the same %q", got, first)
	}
	if got := readEnvFile(f.h.envPath("chat-b"))["CHAT_EXTRA_SECRET"]; got != first {
		t.Errorf(".env = %q, want %q", got, first)
	}
}

// TestTemplateUpdateRenamedSecretRefused (review N2): a client that
// already exists in Keycloak getting a new secret variable is refused 409
// before anything is registered or written (its secret would change under
// the running app); disable and enable apply it.
func TestTemplateUpdateRenamedSecretRefused(t *testing.T) {
	f := chatB(t)
	renamed := strings.Replace(v2ChatManifest, "secret_env: CHAT_SECRET", "secret_env: CHAT_SECRET2", 1) + "  - key: CHAT_SECRET2\n    generate: random\n"
	writeFile(t, f.src+"/chat/manifest.yaml", renamed)
	f.h.Discover()
	n := len(f.idp.specs)
	err := f.h.RestartApp("chat-b")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "disable and enable") {
		t.Fatalf("restart = %v, want 409", err)
	}
	if len(f.idp.specs) != n {
		t.Errorf("a live client was re-registered: %v", f.idp.specs[n:])
	}
	if _, ok := readEnvFile(f.h.envPath("chat-b"))["CHAT_SECRET2"]; ok {
		t.Error("the renamed variable was written")
	}
	if err := f.h.Disable("chat-b"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatalf("enable after the rename = %v", err)
	}
	if v := readEnvFile(f.h.envPath("chat-b"))["CHAT_SECRET2"]; v == "" {
		t.Error("enable didn't write the renamed variable")
	}
}

// TestTemplateUpdateFailurePaths (review N7): a client someone else owns
// (409), a failed access role (502), the second of two new clients
// failing (nothing written, the first reconciled with the same value at
// the retry), a failed lookup (502) and a Stop (reported as a Stop) all
// refuse the start before compose up and write nothing to the .env.
func TestTemplateUpdateFailurePaths(t *testing.T) {
	two := strings.Replace(chatWithAdditions, "env:\n", "  - client_id: chat-more\n    secret_env: CHAT_MORE_SECRET\n    redirect_uri: https://{{HOST_CHAT}}/more/cb\nenv:\n", 1) +
		"  - key: CHAT_MORE_SECRET\n    generate: random\n"
	for _, c := range []struct {
		name   string
		set    func(f *fixture)
		status int
		is     error
	}{
		{"conflict", func(f *fixture) {
			f.idp.registerErr = &keycloak.ConflictError{ClientID: "chat-b-chat-extra", Owner: "someone"}
		}, 409, nil},
		{"access role", func(f *fixture) { f.idp.accessErr = errors.New("role boom") }, 502, nil},
		{"second client", func(f *fixture) {
			f.idp.registerFail = map[string]error{"chat-b-chat-more": errors.New("more boom")}
		}, 502, nil},
		{"lookup", func(f *fixture) { f.idp.findErr = errors.New("lookup boom") }, 502, nil},
		{"stop", func(f *fixture) { f.idp.registerErr = context.Canceled }, 0, context.Canceled},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := chatB(t)
			m := two
			if c.name == "access role" {
				// Only a template whose sign-in Keycloak restricts has one.
				m = strings.Replace(two, "  group_access: true\n", "  group_access: true\n  keycloak_access_role: true\n", 1)
			}
			writeFile(t, f.src+"/chat/manifest.yaml", m)
			f.h.Discover()
			f.idp.mu.Lock()
			c.set(f)
			f.idp.mu.Unlock()
			ups := projUps(f, "portcullis-chat-b")
			f.h.mu.RLock()
			live := *f.h.findLocked("chat-b")
			f.h.mu.RUnlock()
			err := f.h.adoptTemplateEnvAdditions(context.Background(), &live)
			switch {
			case c.is != nil && !errors.Is(err, c.is):
				t.Errorf("err = %v, want it to wrap %v", err, c.is)
			case c.status != 0 && statusOf(err) != c.status:
				t.Errorf("err = %v, want %d", err, c.status)
			}
			if c.is != nil && !isStopErr(err) {
				t.Errorf("a Stop isn't reported as one: %v", err)
			}
			env := readEnvFile(f.h.envPath("chat-b"))
			for _, k := range []string{"CHAT_EXTRA_SECRET", "CHAT_MORE_SECRET", "CHAT_PLAIN"} {
				if _, ok := env[k]; ok {
					t.Errorf("%s written after a failure", k)
				}
			}
			if projUps(f, "portcullis-chat-b") != ups {
				t.Error("compose up ran")
			}
			if c.name != "second client" {
				return
			}
			first := extraSecret(f)
			f.idp.mu.Lock()
			f.idp.registerFail = nil
			f.idp.mu.Unlock()
			if err := f.h.RestartApp("chat-b"); err != nil {
				t.Fatal(err)
			}
			if got := extraSecret(f); got != first || readEnvFile(f.h.envPath("chat-b"))["CHAT_EXTRA_SECRET"] != first {
				t.Errorf("first client re-registered with %q / env %q, want %q", got, readEnvFile(f.h.envPath("chat-b"))["CHAT_EXTRA_SECRET"], first)
			}
		})
	}
}

// TestTemplateUpdateNoKeycloak: without Keycloak the new variables are
// written and the start goes on, as at enable.
func TestTemplateUpdateNoKeycloak(t *testing.T) {
	f := chatB(t)
	writeFile(t, f.src+"/chat/manifest.yaml", chatWithAdditions)
	f.h.Discover()
	f.h.idp = nil
	if err := f.h.RestartApp("chat-b"); err != nil {
		t.Fatal(err)
	}
	if v := readEnvFile(f.h.envPath("chat-b"))["CHAT_EXTRA_SECRET"]; len(v) != 32 {
		t.Errorf("CHAT_EXTRA_SECRET = %q", v)
	}
}

// TestTemplateUpdateDriftApply: the drift banner's apply (the path the
// test server took, contract §2) gets the same: no more "required
// variable … is missing a value".
func TestTemplateUpdateDriftApply(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.src+"/chat/manifest.yaml", chatWithAdditions)
	f.h.Discover()
	if err := f.h.ResolveDrift("chat-b", ActionApply); err != nil {
		t.Fatal(err)
	}
	if env := readEnvFile(f.h.envPath("chat-b")); len(env["CHAT_EXTRA_SECRET"]) != 32 {
		t.Errorf("CHAT_EXTRA_SECRET = %q", env["CHAT_EXTRA_SECRET"])
	}
}
