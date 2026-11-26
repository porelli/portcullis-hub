package hub

import (
	"errors"
	"strings"
	"testing"
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

// TestTemplateUpdateClientRegistrationFails: a failed registration
// refuses the start before compose up, and the new variables are taken
// out again, so the next start generates and registers them afresh —
// the app never runs with a secret Keycloak doesn't know.
func TestTemplateUpdateClientRegistrationFails(t *testing.T) {
	f := newInstanceFixture(t, nil)
	if err := f.h.CreateInstance("chat", "chat-b", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.h.Enable("chat-b"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.src+"/chat/manifest.yaml", chatWithAdditions)
	f.h.Discover()
	f.idp.mu.Lock()
	f.idp.registerErr = errors.New("keycloak down")
	f.idp.mu.Unlock()
	ups := projUps(f, "portcullis-chat-b")
	err := f.h.RestartApp("chat-b")
	if err == nil || !strings.Contains(err.Error(), "chat-extra") || !strings.Contains(err.Error(), "was not started") {
		t.Fatalf("restart = %v", err)
	}
	if projUps(f, "portcullis-chat-b") != ups {
		t.Error("compose up ran after a failed registration")
	}
	env := readEnvFile(f.h.envPath("chat-b"))
	if _, ok := env["CHAT_EXTRA_SECRET"]; ok {
		t.Error("the new secret stayed in the .env after a failed registration")
	}
	if _, ok := env["CHAT_PLAIN"]; ok {
		t.Error("the new variable stayed in the .env after a failed registration")
	}
	f.idp.mu.Lock()
	f.idp.registerErr = nil
	f.idp.mu.Unlock()
	if err := f.h.RestartApp("chat-b"); err != nil {
		t.Fatal(err)
	}
	if env := readEnvFile(f.h.envPath("chat-b")); len(env["CHAT_EXTRA_SECRET"]) != 32 {
		t.Errorf("retry: CHAT_EXTRA_SECRET = %q", env["CHAT_EXTRA_SECRET"])
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
