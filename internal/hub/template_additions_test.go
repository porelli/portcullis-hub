package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/runtime"
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
	kept := readPendingEnv(f.h.pendingEnvPath("chat-b")).Values["CHAT_EXTRA_SECRET"]
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

// renamedChat is v2ChatManifest with client chat's secret_env renamed
// to a new generated variable.
var renamedChat = strings.Replace(v2ChatManifest, "secret_env: CHAT_SECRET", "secret_env: CHAT_SECRET2", 1) + "  - key: CHAT_SECRET2\n    generate: random\n"

// chatBRunning is chatB with compose simulated (containers run) and the
// template renaming chat's secret_env.
func chatBRunning(t *testing.T) *fixture {
	t.Helper()
	f := newInstanceFixture(t, nil)
	f.h.SetAudit(&fakeAudit{})
	simulateCompose(f, 0)
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	if running, _ := f.h.projectRunning(context.Background(), "chat-b"); !running {
		t.Fatal("chat-b doesn't run")
	}
	writeFile(t, f.src+"/chat/manifest.yaml", renamedChat)
	f.h.Discover()
	return f
}

// chatSecretOf is the last secret client id was registered with.
func chatSecretOf(f *fixture, id string) string {
	f.idp.mu.Lock()
	defer f.idp.mu.Unlock()
	s := ""
	for _, sp := range f.idp.specs {
		if sp.ClientID == id {
			s = sp.Secret
		}
	}
	return s
}

// TestTemplateUpdateRenamedSecretRefused (review N2, R1): a client that
// already exists getting a new secret variable is refused 409 while the
// app's containers run (a restart prepares before it stops anything):
// nothing is registered or written. Disable and enable apply it.
func TestTemplateUpdateRenamedSecretRefused(t *testing.T) {
	f := chatBRunning(t)
	n := len(f.idp.specs)
	err := f.h.RestartApp("chat-b")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "still uses the old one") {
		t.Fatalf("restart = %v, want 409", err)
	}
	if len(f.idp.specs) != n {
		t.Errorf("a live client was re-registered: %v", f.idp.specs[n:])
	}
	if _, ok := readEnvFile(f.h.envPath("chat-b"))["CHAT_SECRET2"]; ok {
		t.Error("the renamed variable was written")
	}
	if running, _ := f.h.projectRunning(context.Background(), "chat-b"); !running {
		t.Error("the refused restart took the app down")
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

// TestTemplateUpdateRenamedSecretRotatesWhenStopped (review R1): a backup
// stops the app and starts it again; with its containers down the renamed
// client's secret is rotated (registered first, then written) and the app
// comes back — the nightly backup never leaves it down.
func TestTemplateUpdateRenamedSecretRotatesWhenStopped(t *testing.T) {
	f := chatBRunning(t)
	if _, err := f.h.BackupInstance("chat-b", directory.Human("root")); err != nil {
		t.Fatalf("backup = %v", err)
	}
	v := readEnvFile(f.h.envPath("chat-b"))["CHAT_SECRET2"]
	if len(v) != 32 {
		t.Fatalf("CHAT_SECRET2 = %q", v)
	}
	if got := chatSecretOf(f, "chat-b"); got != v {
		t.Errorf("chat-b registered with %q, env %q", got, v)
	}
	if running, _ := f.h.projectRunning(context.Background(), "chat-b"); !running {
		t.Error("the app didn't come back after the backup")
	}
}

// TestTemplateUpdateRenamedSecretStartOfStoppedApp (review R1): a start
// of an enabled app whose containers are down (drift "start") rotates.
func TestTemplateUpdateRenamedSecretStartOfStoppedApp(t *testing.T) {
	f := chatBRunning(t)
	if err := f.h.downByName(context.Background(), "chat-b"); err != nil {
		t.Fatal(err)
	}
	if err := f.h.ResolveDrift("chat-b", ActionStart); err != nil {
		t.Fatalf("start = %v", err)
	}
	if v := readEnvFile(f.h.envPath("chat-b"))["CHAT_SECRET2"]; v == "" || chatSecretOf(f, "chat-b") != v {
		t.Errorf("not rotated: env %q, registered %q", v, chatSecretOf(f, "chat-b"))
	}
}

// TestTemplateUpdateRenamedSecretUnknownRunning (review R1): when the
// engine can't say whether the containers run, they count as running.
func TestTemplateUpdateRenamedSecretUnknownRunning(t *testing.T) {
	f := chatBRunning(t)
	f.engine.mu.Lock()
	f.engine.listErr = errors.New("engine down")
	f.engine.mu.Unlock()
	f.h.mu.RLock()
	live := *f.h.findLocked("chat-b")
	f.h.mu.RUnlock()
	if err := f.h.adoptTemplateEnvAdditions(context.Background(), &live); statusOf(err) != 409 {
		t.Errorf("adopt = %v, want 409", err)
	}
}

// TestTemplateUpdateStalePendingNotOurs (review R2): a kept value for the
// same variable name but another client doesn't make a live client's
// rotation "ours": still 409 while it runs.
func TestTemplateUpdateStalePendingNotOurs(t *testing.T) {
	f := chatBRunning(t)
	if err := writePendingEnv(f.h.pendingEnvPath("chat-b"), pendingEnv{Values: map[string]string{"CHAT_SECRET2": "x"}, Clients: map[string]string{"CHAT_SECRET2": "chat-b-gone"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.RestartApp("chat-b"); statusOf(err) != 409 {
		t.Errorf("restart = %v, want 409", err)
	}
}

// TestTemplateUpdateRenamedForeignClient (review R5): a client with that
// id that another owner holds isn't refused with "disable and enable":
// RegisterClient's conflict answers (409, not this instance's).
func TestTemplateUpdateRenamedForeignClient(t *testing.T) {
	f := chatBRunning(t)
	f.idp.mu.Lock()
	f.idp.owners = map[string]string{"chat-b": "someone"}
	f.idp.registerFail = map[string]error{"chat-b": &keycloak.ConflictError{ClientID: "chat-b", Owner: "someone"}}
	f.idp.mu.Unlock()
	err := f.h.RestartApp("chat-b")
	if statusOf(err) != 409 || !strings.Contains(err.Error(), "isn't this instance's") || strings.Contains(err.Error(), "disable and enable") {
		t.Errorf("restart = %v", err)
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

// dropEnvKey removes key's lines from id's .env (as if the template had
// just declared it).
func dropEnvKey(t *testing.T, f *fixture, id, key string) {
	t.Helper()
	var keep []string
	for _, l := range strings.Split(readFile(t, f.h.envPath(id)), "\n") {
		if !strings.HasPrefix(l, key+"=") {
			keep = append(keep, l)
		}
	}
	writeFile(t, f.h.envPath(id), strings.Join(keep, "\n"))
}

// TestTemplateUpdateAIClient (review R3, N7): an AI page's ai_client
// whose generated secret variable is new is ensured through the AI path
// with exactly the new value before it is written (Keycloak's client
// then has the .env's secret); an ai_client ensure failure refuses the
// start (502) with nothing written.
func TestTemplateUpdateAIClient(t *testing.T) {
	kc, c := hubAIRealm(t)
	a := chatFixture23(t, nil)
	a.h.SetAIKeycloak(c)
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	a.enable(t, "ai-chat")
	old := readEnvFile(a.h.envPath("ai-chat"))["CHAT_MCP_SECRET"]
	if old == "" || kc.ClientByClientID(chatMCPID) == nil {
		t.Fatal("no ai_client after enable")
	}
	dropEnvKey(t, a.fixture, "ai-chat", "CHAT_MCP_SECRET")
	if err := a.h.RestartApp("ai-chat"); err != nil {
		t.Fatal(err)
	}
	now := readEnvFile(a.h.envPath("ai-chat"))["CHAT_MCP_SECRET"]
	if len(now) != 32 || now == old {
		t.Fatalf("CHAT_MCP_SECRET = %q (old %q)", now, old)
	}
	if got := kc.ClientByClientID(chatMCPID).Secret; got != now {
		t.Errorf("Keycloak's ai_client secret %q, .env %q", got, now)
	}

	// A failing ai_client ensure: 502, nothing written.
	fk := newFakeAIKC()
	fk.setFailClient(chatMCPID, errors.New("ai boom"))
	a.h.SetAIKeycloak(fk)
	dropEnvKey(t, a.fixture, "ai-chat", "CHAT_MCP_SECRET")
	if err := a.h.RestartApp("ai-chat"); statusOf(err) != 502 || !strings.Contains(err.Error(), chatMCPID) {
		t.Errorf("restart with a failing ai_client = %v, want 502", err)
	}
	if _, ok := readEnvFile(a.h.envPath("ai-chat"))["CHAT_MCP_SECRET"]; ok {
		t.Error("the ai_client's secret was written after a failed ensure")
	}
}

// TestProjectMayRun (review S2): only exited and dead — and created for a
// Docker or Podman container that never started — count as down; a
// Kubernetes "created" (a starting pod), Podman's "stopping" and any
// unknown state count as running; no container is down.
func TestProjectMayRun(t *testing.T) {
	f := newInstanceFixture(t, nil)
	set := func(states ...string) {
		f.engine.mu.Lock()
		f.engine.containers = nil
		for i, st := range states {
			f.engine.containers = append(f.engine.containers, container(fmt.Sprintf("c%d", i), "portcullis-grafana", "web", st))
		}
		f.engine.mu.Unlock()
	}
	for _, c := range []struct {
		runtime runtime.Kind
		states  []string
		want    bool
	}{
		{"", nil, false},
		{"", []string{"exited", "dead"}, false},
		{"", []string{"created", "exited"}, false},
		{runtime.KindPodman, []string{"created"}, false},
		{runtime.KindKubernetes, []string{"created"}, true},
		{runtime.KindKubernetes, []string{"exited"}, false},
		{runtime.KindPodman, []string{"stopping"}, true},
		{"", []string{"exited", "removing"}, true},
		{"", []string{"something-new"}, true},
		{"", []string{"running"}, true},
		{"", []string{"paused"}, true},
	} {
		f.h.cfg.Runtime = c.runtime
		set(c.states...)
		got, err := f.h.projectMayRun(context.Background(), "grafana")
		if err != nil || got != c.want {
			t.Errorf("%s %v: projectMayRun = %v %v, want %v", c.runtime, c.states, got, err, c.want)
		}
	}
	f.h.cfg.Runtime = ""
}

// TestTemplateUpdateRenamedSecretStoppingRefused (review S2): a
// container in a state that isn't clearly down (Podman's "stopping")
// counts as running: the rename is refused 409.
func TestTemplateUpdateRenamedSecretStoppingRefused(t *testing.T) {
	f := chatBRunning(t)
	f.engine.mu.Lock()
	for i := range f.engine.containers {
		if f.engine.containers[i].Project() == "portcullis-chat-b" {
			f.engine.containers[i].State = "stopping"
		}
	}
	f.engine.mu.Unlock()
	f.h.mu.RLock()
	live := *f.h.findLocked("chat-b")
	f.h.mu.RUnlock()
	if err := f.h.adoptTemplateEnvAdditions(context.Background(), &live); statusOf(err) != 409 {
		t.Errorf("adopt over a stopping container = %v, want 409", err)
	}
}

// TestTemplateUpdateRenamedUntaggedClient (review S1): an untagged
// existing client (one RegisterClient would adopt) is checked like this
// instance's: 409 while the app runs, never a silent rotation.
func TestTemplateUpdateRenamedUntaggedClient(t *testing.T) {
	f := chatBRunning(t)
	f.idp.mu.Lock()
	f.idp.owners = map[string]string{"chat-b": ""}
	f.idp.mu.Unlock()
	n := len(f.idp.specs)
	if err := f.h.RestartApp("chat-b"); statusOf(err) != 409 || !strings.Contains(err.Error(), "still uses the old one") {
		t.Errorf("restart = %v, want the 409", err)
	}
	if len(f.idp.specs) != n {
		t.Error("an untagged client was rotated under the running app")
	}
}

// TestTemplateUpdateGarbagePendingFile (review S4): an unreadable pending
// file is ignored: the values are generated again and no client counts
// as kept-for, so a renamed live client is still refused while it runs,
// and a new client still gets registered and written.
func TestTemplateUpdateGarbagePendingFile(t *testing.T) {
	f := chatBRunning(t)
	writeFile(t, f.h.pendingEnvPath("chat-b"), "CHAT_SECRET2=kept\nnot json")
	if err := f.h.RestartApp("chat-b"); statusOf(err) != 409 {
		t.Errorf("restart = %v, want 409", err)
	}
	g := chatB(t)
	writeFile(t, g.src+"/chat/manifest.yaml", chatWithAdditions)
	g.h.Discover()
	writeFile(t, g.h.pendingEnvPath("chat-b"), "{garbage")
	if err := g.h.RestartApp("chat-b"); err != nil {
		t.Fatal(err)
	}
	if v := readEnvFile(g.h.envPath("chat-b"))["CHAT_EXTRA_SECRET"]; len(v) != 32 || extraSecret(g) != v {
		t.Errorf("env %q, registered %q", v, extraSecret(g))
	}
}

// TestTemplateUpdateAIClientNoGeneratedValue (review R3, S4): an
// existing ai_client whose secret_env the update renames to a variable
// with no generated value is skipped — no running check, no 409 over the
// running app, nothing ensured, no rotation logged — and the start goes
// on with the variable written empty (unhealthy, as at enable).
func TestTemplateUpdateAIClientNoGeneratedValue(t *testing.T) {
	_, c := hubAIRealm(t)
	a := chatFixture23(t, nil)
	a.h.SetAIKeycloak(c)
	a.selectProviders(t, "ai-chat", "ollama-gpu")
	a.enable(t, "ai-chat")
	simulateCompose(a.fixture, 0)
	if err := a.h.RestartApp("ai-chat"); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.h.projectRunning(context.Background(), "ai-chat"); !r {
		t.Fatal("ai-chat doesn't run")
	}
	p := filepath.Join(a.src, "ai-chat", "manifest.yaml")
	m := strings.Replace(readFile(t, p), "    secret_env: CHAT_MCP_SECRET\n", "    secret_env: CHAT_MCP_PLAIN\n", 1)
	m = strings.Replace(m, "  - key: CHAT_MCP_SECRET\n    generate: random\n", "  - key: CHAT_MCP_SECRET\n    generate: random\n  - key: CHAT_MCP_PLAIN\n", 1)
	writeFile(t, p, m)
	a.h.Discover()
	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	if err := a.h.RestartApp("ai-chat"); err != nil {
		t.Fatalf("restart = %v (a skipped ai_client must not refuse the start)", err)
	}
	if v, ok := readEnvFile(a.h.envPath("ai-chat"))["CHAT_MCP_PLAIN"]; !ok || v != "" {
		t.Errorf("CHAT_MCP_PLAIN = %q %v, want written empty", v, ok)
	}
	if strings.Contains(logs.String(), "rotated before the start") {
		t.Errorf("a skipped ai_client was logged as rotated:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "no generated value: not registered") {
		t.Errorf("the skip isn't logged:\n%s", logs.String())
	}
}
