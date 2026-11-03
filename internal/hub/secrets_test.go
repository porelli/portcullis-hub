package hub

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/templates"
)

// secretFixture loads testdata/settings/secretapp: api_key (secret, env
// HEADSCALE_API_KEY) and token (secret, generate 32 alphanumeric, hook
// delivery), with an audit log, groups and simulated compose volumes.
func secretFixture(t *testing.T) (*fixture, *fakeAudit) {
	t.Helper()
	m := mustRead(t, filepath.Join("testdata", "settings", "secretapp", "manifest.yaml"))
	c := mustRead(t, filepath.Join("testdata", "settings", "secretapp", "compose.yml"))
	f := newInstanceFixtureExtra(t, nil, nil, map[string][2]string{"secretapp": {string(m), string(c)}})
	if f.h.Template("secretapp") == nil {
		t.Fatalf("secretapp fixture not loaded (see the log)")
	}
	audit := &fakeAudit{}
	f.h.SetAudit(audit)
	f.h.SetGroups(&fakeGroups{})
	simulateCompose(f, 0)
	return f, audit
}

func setSecret(v string) SecretChange { return SecretChange{Value: &v} }

func saveSecret(t *testing.T, f *fixture, id, key string, c SecretChange) {
	t.Helper()
	if _, err := f.h.SaveSettings(id, SettingsUpdate{Secrets: map[string]SecretChange{key: c}}, "admin"); err != nil {
		t.Fatalf("saving secret %s: %v", key, err)
	}
}

func storedSecrets(t *testing.T, f *fixture, id string) map[string]string {
	t.Helper()
	v, err := f.h.secretValues(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// captureLog sends the log to a buffer for the test.
func captureLog(t *testing.T) *lockedBuf {
	t.Helper()
	b := &lockedBuf{}
	prev := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return b
}

func auditText(a *fakeAudit) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, _ := json.Marshal(a.entries)
	return string(b)
}

func TestSecretWriteOnly(t *testing.T) {
	f, audit := secretFixture(t)
	saveSecret(t, f, "secretapp", "api_key", setSecret("s3cr3t"))

	if b := mustRead(t, filepath.Join(f.data, "state.yaml")); bytes.Contains(b, []byte("s3cr3t")) {
		t.Errorf("state.yaml holds the secret:\n%s", b)
	}
	entry, err := f.h.BackupInstance("secretapp", "root")
	if err != nil {
		t.Fatal(err)
	}
	_, data, _ := readArchive(t, archivePath(f, entry.Archive))
	if bytes.Contains(data["config/instance.yaml"], []byte("s3cr3t")) {
		t.Errorf("instance.yaml holds the secret:\n%s", data["config/instance.yaml"])
	}

	v, err := f.h.AppSettings("secretapp")
	if err != nil {
		t.Fatal(err)
	}
	if s := v.Secrets["api_key"]; !s.Set || s.UpdatedAt == nil || s.Generated {
		t.Errorf("api_key view = %+v", s)
	}
	if s := v.Secrets["token"]; s.Set || s.UpdatedAt != nil {
		t.Errorf("token view = %+v", s)
	}
	if b, _ := json.Marshal(v); bytes.Contains(b, []byte("s3cr3t")) {
		t.Errorf("the settings view echoes the secret: %s", b)
	}
	if env := "\n" + envOf(t, f, "secretapp"); !strings.Contains(env, "\nHEADSCALE_API_KEY='s3cr3t'\n") {
		t.Errorf("env:\n%s", env)
	}
	// The store: 0600 in a 0700 directory.
	if fi, err := os.Stat(f.h.secretsPath("secretapp")); err != nil || fi.Mode().Perm() != 0600 {
		t.Errorf("store mode: %v %v", fi, err)
	}
	if fi, err := os.Stat(f.h.secretsDir("secretapp")); err != nil || fi.Mode().Perm() != 0700 {
		t.Errorf("store dir mode: %v %v", fi, err)
	}
	if got := storedSecrets(t, f, "secretapp"); got["api_key"] != "s3cr3t" {
		t.Errorf("store = %v", got)
	}
	if a := auditText(audit); strings.Contains(a, "s3cr3t") || !strings.Contains(a, "scope=instance: replaced") {
		t.Errorf("audit = %s", a)
	}
}

func TestSecretGenerateAndClear(t *testing.T) {
	f, audit := secretFixture(t)
	saveSecret(t, f, "secretapp", "token", SecretChange{Generate: true})
	tok := storedSecrets(t, f, "secretapp")["token"]
	if len(tok) != 32 || strings.Trim(tok, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != "" {
		t.Errorf("generated token %d chars, not alphanumeric", len(tok))
	}
	v, _ := f.h.AppSettings("secretapp")
	if s := v.Secrets["token"]; !s.Set || !s.Generated {
		t.Errorf("token view = %+v", s)
	}
	if strings.Contains(envOf(t, f, "secretapp"), tok) {
		t.Error("a hook-delivered secret is in the env")
	}
	if a := auditText(audit); !strings.Contains(a, "scope=instance: generated") || strings.Contains(a, tok) {
		t.Errorf("audit = %s", a)
	}

	// Refusals: generate without generate:, an empty value, two actions.
	empty := ""
	for name, c := range map[string]struct {
		key  string
		c    SecretChange
		want string
	}{
		"no generate": {"api_key", SecretChange{Generate: true}, "api_key"},
		"empty value": {"api_key", SecretChange{Value: &empty}, "clearing needs an explicit action"},
		"two actions": {"token", SecretChange{Generate: true, Clear: true}, "exactly one"},
		"nothing":     {"token", SecretChange{}, "exactly one"},
	} {
		_, err := f.h.SaveSettings("secretapp", SettingsUpdate{Secrets: map[string]SecretChange{c.key: c.c}}, "admin")
		if statusOf(err) != 400 || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	saveSecret(t, f, "secretapp", "api_key", setSecret("s3cr3t"))
	saveSecret(t, f, "secretapp", "api_key", SecretChange{Clear: true})
	if _, ok := storedSecrets(t, f, "secretapp")["api_key"]; ok {
		t.Error("cleared secret still stored")
	}
	if env := "\n" + envOf(t, f, "secretapp"); !strings.Contains(env, "\nHEADSCALE_API_KEY=\n") || strings.Contains(env, "s3cr3t") {
		t.Errorf("env after clear:\n%s", env)
	}
	f.h.mu.RLock()
	_, meta := f.h.st.Settings["secretapp"].Secrets["api_key"]
	f.h.mu.RUnlock()
	if meta {
		t.Error("cleared secret keeps its metadata")
	}
	if a := auditText(audit); !strings.Contains(a, "scope=instance: cleared") {
		t.Errorf("audit = %s", a)
	}
	// The env is regenerated on enable with the empty value too.
	if err := f.h.Enable("secretapp"); err != nil {
		t.Fatal(err)
	}
	if got := composeReads(t, f.h.envPath("secretapp"))["HEADSCALE_API_KEY"]; got != "" {
		t.Errorf("enable wrote %q for a cleared secret", got)
	}
}

func TestSecretNeverEchoed(t *testing.T) {
	f, audit := secretFixture(t)
	logs := captureLog(t)
	const key = "k3y-4bcdef-value"
	saveSecret(t, f, "secretapp", "api_key", setSecret(key))
	saveSecret(t, f, "secretapp", "token", SecretChange{Generate: true})
	tok := storedSecrets(t, f, "secretapp")["token"]

	f.runner.upErr = &compose.Error{Command: "up", Err: errors.New("exit status 1"),
		Output: "env API_KEY=" + key + " token " + tok + "\nError: " + strings.Repeat("x", 590) + tok + "\n"}
	err := f.h.Enable("secretapp")
	var oe *OpError
	if !errors.As(err, &oe) {
		t.Fatalf("enable = %v", err)
	}
	opJSON, _ := json.Marshal(oe.Record)
	stored, _ := os.ReadFile(f.h.opPath("secretapp"))
	// The API answers the error the same way (httpapi audits it too).
	f.h.auditOp("admin", "instance.enable", "secretapp", "", err)
	f.h.auditOp("admin", "instance.backup", "secretapp", "", errors.New("raw "+key+" and "+tok))
	for name, s := range map[string]string{"error": oe.Error(), "op JSON": string(opJSON), "op record": string(stored), "audit": auditText(audit), "log": logs.String()} {
		if strings.Contains(s, key) || strings.Contains(s, tok) || strings.Contains(s, tok[:8]) {
			t.Errorf("%s echoes a secret: %s", name, s)
		}
	}
	if !strings.Contains(oe.Record.Output, "[redacted]") || !strings.Contains(auditText(audit), "[redacted]") {
		t.Errorf("not redacted: output %q", oe.Record.Output)
	}
	if !strings.Contains(auditText(audit), "replaced") {
		t.Errorf("audit lacks replaced: %s", auditText(audit))
	}
}

// P19: async operations (backup, restore, delete) redact the instance's
// stored secrets in their op records and audit entries too.
func TestSecretRedactedInAsyncOp(t *testing.T) {
	f, audit := secretFixture(t)
	saveSecret(t, f, "secretapp", "token", SecretChange{Generate: true})
	tok := storedSecrets(t, f, "secretapp")["token"]
	if err := f.h.Enable("secretapp"); err != nil {
		t.Fatal(err)
	}
	f.engine.vol().imageErr = errors.New("pull refused for " + tok)
	op, err := f.h.StartBackup("secretapp", "root")
	if err != nil {
		t.Fatal(err)
	}
	r := waitOp(t, f.h, "secretapp", op.OpID)
	stored, _ := os.ReadFile(f.h.opPath("secretapp"))
	if r.OK || !strings.Contains(r.Error, "[redacted]") || strings.Contains(r.Error, tok) || strings.Contains(string(stored), tok) {
		t.Errorf("async op record = %+v", r)
	}
	if a := auditText(audit); strings.Contains(a, tok) || !strings.Contains(a, "instance.backup") {
		t.Errorf("audit = %s", a)
	}
}

// Review Focus 1: env values are single-quoted, read back as written by
// the Hub and by compose; ' is refused naming the option; no generated
// alphabet has ' or \.
func TestEnvValueQuotingRoundTrip(t *testing.T) {
	f, _ := secretFixture(t)
	for _, v := range []string{"a$b", "x y#z", `"q"`, "$$x ${Y}"} {
		saveSecret(t, f, "secretapp", "api_key", setSecret(v))
		if got := parseEnv(mustRead(t, f.h.envPath("secretapp")))["HEADSCALE_API_KEY"]; got != v {
			t.Errorf("parseEnv: %q read back as %q", v, got)
		}
		if got := composeReads(t, f.h.envPath("secretapp"))["HEADSCALE_API_KEY"]; got != v {
			t.Errorf("compose: %q read back as %q", v, got)
		}
	}
	for _, v := range []string{"it's", `x\`, "a\nb"} {
		_, err := f.h.SaveSettings("secretapp", SettingsUpdate{Secrets: map[string]SecretChange{"api_key": setSecret(v)}}, "admin")
		if statusOf(err) != 400 || !strings.Contains(err.Error(), "api_key") || strings.Contains(err.Error(), v) {
			t.Errorf("%q: %v", v, err)
		}
	}
	// A hook-only secret may hold a backslash (it never goes to the env).
	saveSecret(t, f, "secretapp", "token", setSecret(`C:\x`))
	for cs := range templates.GenerateCharsets {
		for range 200 {
			v, err := generateSecret(&templates.GenerateSpec{Length: 64, Charset: cs})
			if err != nil || len(v) != 64 || strings.ContainsAny(v, "'\\ \n") {
				t.Fatalf("%s: %q %v", cs, v, err)
			}
			if _, err := envQuote(v); err != nil {
				t.Fatalf("%s: %q not quotable", cs, v)
			}
		}
	}
	if strings.ContainsAny(secretAlphabets[templates.CharsetASCIIPrintable], "'\\") || len(secretAlphabets[templates.CharsetASCIIPrintable]) != 92 {
		t.Errorf("ascii_printable = %q", secretAlphabets[templates.CharsetASCIIPrintable])
	}
}

// P18: the Expert env view masks secret variables; SaveEnv refuses any
// option's variable.
func TestSecretExpertEnv(t *testing.T) {
	f, _ := secretFixture(t)
	saveSecret(t, f, "secretapp", "api_key", setSecret("s3cr3t"))
	vars, _, err := f.h.Env("secretapp")
	if err != nil {
		t.Fatal(err)
	}
	if vars["HEADSCALE_API_KEY"] != "[set]" {
		t.Errorf("Env shows %q", vars["HEADSCALE_API_KEY"])
	}
	err = f.h.SaveEnv("secretapp", map[string]string{"HEADSCALE_API_KEY": "other"})
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "set it under Settings") {
		t.Errorf("SaveEnv of a secret variable = %v", err)
	}
	f2, _ := immichFixture(t)
	err = f2.h.SaveEnv("immich", map[string]string{"IMMICH_TRASH_DAYS": "3"})
	if statusOf(err) != 400 || !strings.Contains(err.Error(), "set it under Settings") || !strings.Contains(err.Error(), "trash_days") {
		t.Errorf("SaveEnv of an option variable = %v", err)
	}
	if err := f2.h.SaveEnv("immich", map[string]string{"FREE_VAR": "x"}); err != nil {
		t.Errorf("SaveEnv of a free variable = %v", err)
	}
	if s := storedSecrets(t, f, "secretapp")["api_key"]; s != "s3cr3t" {
		t.Errorf("store changed: %q", s)
	}
}

func TestSecretsInBackup(t *testing.T) {
	f, _ := secretFixture(t)
	if err := f.h.CreateInstance("secretapp", "secretapp-b", nil); err != nil {
		t.Fatal(err)
	}
	const key = "orig-api-key-1"
	saveSecret(t, f, "secretapp-b", "api_key", setSecret(key))
	saveSecret(t, f, "secretapp-b", "token", SecretChange{Generate: true})
	tok := storedSecrets(t, f, "secretapp-b")["token"]
	if err := f.h.Enable("secretapp-b"); err != nil {
		t.Fatal(err)
	}
	entry, err := f.h.BackupInstance("secretapp-b", "root")
	if err != nil {
		t.Fatal(err)
	}
	_, data, _ := readArchive(t, archivePath(f, entry.Archive))
	inArchive, err := parseSecrets(data[secretsMember])
	if err != nil || inArchive["api_key"] != key || inArchive["token"] != tok {
		t.Fatalf("%s = %v %v", secretsMember, inArchive, err)
	}
	for name, b := range data {
		if name != secretsMember && (bytes.Contains(b, []byte(key)) || bytes.Contains(b, []byte(tok))) {
			t.Errorf("archive member %s holds a secret", name)
		}
	}
	if !bytes.Contains(data["config/env"], []byte("\nHEADSCALE_API_KEY=\n")) {
		t.Errorf("config/env:\n%s", data["config/env"])
	}

	// Same instance: the archived secrets come back (store and env).
	saveSecret(t, f, "secretapp-b", "api_key", setSecret("changed-key"))
	saveSecret(t, f, "secretapp-b", "token", SecretChange{Clear: true})
	f.h.Wait()
	if _, err := f.h.RestoreInstance("secretapp-b", entry.Archive, "root"); err != nil {
		t.Fatal(err)
	}
	if got := storedSecrets(t, f, "secretapp-b"); got["api_key"] != key || got["token"] != tok {
		t.Errorf("restored store = %v", got)
	}
	if got := composeReads(t, f.h.envPath("secretapp-b"))["HEADSCALE_API_KEY"]; got != key {
		t.Errorf("restored env = %q", got)
	}
	f.h.mu.RLock()
	meta := f.h.st.Settings["secretapp-b"].Secrets
	f.h.mu.RUnlock()
	if _, ok := meta["token"]; !ok || len(meta) != 2 {
		t.Errorf("restored meta = %v", meta)
	}

	// A new id: copied, generate-declared ones regenerated.
	if _, err := f.h.RestoreInstanceAs(entry.Archive, "secretapp-c", "root"); err != nil {
		t.Fatal(err)
	}
	got := storedSecrets(t, f, "secretapp-c")
	if got["api_key"] != key || got["token"] == tok || len(got["token"]) != 32 {
		t.Errorf("restore-as store: api_key copied %v, token regenerated %v", got["api_key"] == key, got["token"] != tok)
	}
	if got := composeReads(t, f.h.envPath("secretapp-c"))["HEADSCALE_API_KEY"]; got != key {
		t.Errorf("restore-as env = %q", got)
	}
	v, _ := f.h.AppSettings("secretapp-c")
	if s := v.Secrets["token"]; !s.Set || !s.Generated {
		t.Errorf("restore-as token view = %+v", s)
	}

	// Delete removes the store.
	if _, err := f.h.DeleteInstance("secretapp-c", "secretapp-c", "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.h.secretsDir("secretapp-c")); !os.IsNotExist(err) {
		t.Errorf("settings store left after delete: %v", err)
	}
}
