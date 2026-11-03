package hub

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/policy"
)

// Final whole-branch review fixes (hub items H7-H18).

// sharedRoleField publishes a shared field grafana_role (header
// X-Forwarded-Attr-Grafana-Role, the header dash delivers) with a
// delegate-set value Admin for alice.
func sharedRoleField(f *fixture) {
	attrs := policy.BuildUserAttributes([]policy.AttrField{{Name: "grafana_role"}}, map[string]map[string][]string{"alice": {"grafana_role": {"Admin"}}}, nil)
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, &attrs, nil
	}, nil)
}

// H7: a freshly enabled instance whose first header delivery has not run
// (the directory is down) still declares its header on every gated
// host, so group-gate drops the same-named shared-field header there.
func TestFieldHeaderNeverReachesFreshInstance(t *testing.T) {
	f, people, _ := headerFixture(t, nil)
	sharedRoleField(f)
	people.set(func(p *fakePeople) { p.err = errors.New("lldap down") })
	if _, err := f.h.EnableAs(headerID, "root"); err != nil {
		t.Fatal(err)
	}
	settle(f)
	f.h.writePolicyLogged()
	doc, ok := readAttrs(t, f)
	if !ok {
		t.Fatal("no user-attributes.json")
	}
	for _, host := range []string{headerMain, headerExtra} {
		vals, declared := doc.Hosts[host][hdrSuffix]
		if !declared || len(vals) != 0 {
			t.Errorf("%s %s = %v (declared %v), want declared with no values", host, hdrSuffix, vals, declared)
		}
	}
	if _, ok := doc.Hosts[headerStatus]; ok {
		t.Errorf("the ungated host %s is declared: %v", headerStatus, doc.Hosts)
	}
	if doc.Fields["grafana_role"] == "" {
		t.Errorf("fields = %v: the shared field is still published for other hosts", doc.Fields)
	}
}

// H7: when the instance's gated hosts can't be resolved, the colliding
// shared-field header is not published at all (fail closed).
func TestFieldHeaderSuppressedWhenHostsUnknown(t *testing.T) {
	f, _, _ := headerFixture(t, nil)
	sharedRoleField(f)
	headerEnable(t, f)
	if doc, _ := readAttrs(t, f); doc.Fields["grafana_role"] == "" {
		t.Fatalf("fields = %v, want grafana_role published", doc.Fields)
	}
	f.h.mu.RLock()
	path := f.h.findLocked(headerID).ComposePath()
	f.h.mu.RUnlock()
	if err := os.WriteFile(path, []byte("services: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The directory state down (the kept file's fields and users).
	f.h.SetDirectory(func(context.Context) ([]policy.Expiring, *policy.UserAttributesDocument, error) {
		return nil, nil, errors.New("directory publish failed")
	}, nil)
	f.h.writePolicyLogged()
	doc, _ := readAttrs(t, f)
	if _, ok := doc.Fields["grafana_role"]; ok {
		t.Errorf("kept file: fields = %v, want grafana_role suppressed while dash-b's hosts are unknown", doc.Fields)
	}
	if v, ok := doc.Users["alice"]["grafana_role"]; ok {
		t.Errorf("kept file: alice's grafana_role = %v still published", v)
	}
	// The directory back: still suppressed.
	sharedRoleField(f)
	f.h.writePolicyLogged()
	doc, _ = readAttrs(t, f)
	if _, ok := doc.Fields["grafana_role"]; ok {
		t.Errorf("fields = %v: grafana_role published while dash-b's hosts are unknown", doc.Fields)
	}
	if v, ok := doc.Users["alice"]["grafana_role"]; ok {
		t.Errorf("alice's grafana_role = %v still published", v)
	}
}

// H8: an account deleted and re-created under the same name inside one
// debounce window (a new LLDAP uuid, its attributes gone with the old
// account) gets its claim written again, though its value is unchanged.
func TestClaimRewrittenForRecreatedAccount(t *testing.T) {
	f, people, store := claimFixture(t)
	quota := SettingAttr(claimID, "storage_quota")
	claimEnable(t, f, claimID)
	deliverNow(t, f, claimID, TriggerRetry)
	if got := store.values["dave"][quota]; len(got) != 1 {
		t.Fatalf("dave's quota = %v before the re-creation", got)
	}
	people.recreate("dave")
	people.addGroup("users_immich", "dave")
	store.mu.Lock()
	delete(store.values, "dave")
	store.mu.Unlock()
	before := len(store.calls())
	deliverNow(t, f, claimID, TriggerMembership)
	calls := store.calls()[before:]
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "dave +") || !strings.Contains(calls[0], quota+"=100") {
		t.Errorf("writes after dave's re-creation = %q, want dave's quota written", calls)
	}
	// Then unchanged.
	before = len(store.calls())
	deliverNow(t, f, claimID, TriggerMembership)
	if n := len(store.calls()) - before; n != 0 {
		t.Errorf("an unchanged run wrote %d times: %q", n, store.calls()[before:])
	}
}

// H13: a template update renames a secret option's env variable, then
// removes the option: neither Expert Env nor a backup's config/env ever
// shows the old line's value, and the prune blanks it in the .env.
func TestSecretEnvLineAfterTemplateUpdate(t *testing.T) {
	f, _ := secretFixture(t)
	const val = "s3cr3t-old-line"
	saveSecret(t, f, "secretapp", "api_key", setSecret(val))
	if err := f.h.Enable("secretapp"); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
	manifest := filepath.Join(f.src, "secretapp", "manifest.yaml")
	m := string(mustRead(t, manifest))
	renamed := strings.Replace(m, "{env: HEADSCALE_API_KEY}", "{env: HEADSCALE_KEY}", 1)
	writeFile(t, manifest, renamed)
	composePath := filepath.Join(f.src, "secretapp", "compose.yml")
	writeFile(t, composePath, strings.ReplaceAll(string(mustRead(t, composePath)), "HEADSCALE_API_KEY", "HEADSCALE_KEY"))
	f.h.Discover()
	if optionByKey(f.h.Template("secretapp"), "api_key") == nil {
		t.Fatal("rename not loaded")
	}
	f.h.pruneSettings()
	checkEnv := func(when string) {
		t.Helper()
		vars, _, err := f.h.Env("secretapp")
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range vars {
			if strings.Contains(v, val) {
				t.Errorf("%s: Expert Env shows %s=%q", when, k, v)
			}
		}
		entry, err := f.h.BackupInstance("secretapp", "root")
		if err != nil {
			t.Fatal(err)
		}
		_, data, _ := readArchive(t, archivePath(f, entry.Archive))
		for name, b := range data {
			if name != secretsMember && bytes.Contains(b, []byte(val)) {
				t.Errorf("%s: archive member %s holds the secret", when, name)
			}
		}
	}
	checkEnv("renamed")
	// Removed (and api_url's requires with it): the prune drops the
	// stored value and blanks its old .env line first.
	removed := strings.Replace(renamed, "    - key: api_key\n      label: API key\n      type: secret\n      applies: restart\n      delivery: [{env: HEADSCALE_KEY}]\n", "", 1)
	removed = strings.Replace(removed, "      requires: [api_key]\n", "", 1)
	writeFile(t, manifest, removed)
	f.h.Discover()
	if optionByKey(f.h.Template("secretapp"), "api_key") != nil {
		t.Fatal("update not loaded")
	}
	f.h.pruneSettings()
	if _, ok := storedSecrets(t, f, "secretapp")["api_key"]; ok {
		t.Fatal("the prune kept the dropped secret")
	}
	if b, _ := os.ReadFile(f.h.envPath("secretapp")); bytes.Contains(b, []byte(val)) {
		t.Errorf("the .env still holds the dropped secret:\n%s", b)
	}
	checkEnv("removed")
}
