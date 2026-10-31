package hub

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

const cloudManifest = `name: Cloud
category: productivity
auth:
  method: forward-auth
  group_access: true
  access_group: users_cloud
  public_access:
    enabled_by_default: true
    description: Public share links
    token_pattern: '^[A-Za-z0-9-]{1,32}$'
    paths:
      - prefix: "/s/{token}"
        description: Share page
      - prefix: /dist
        description: Assets
        supporting: true
      - prefix: /apps/text
        description: Text viewer
`

const cloudCompose = "services:\n  cloud:\n    image: nc\n    labels:\n" +
	"      traefik.http.routers.cloud.rule: Host(`cloud.${PORTCULLIS_DOMAIN:-portcullis.local}`)\n" +
	"      traefik.http.routers.cloud.middlewares: client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file\n" +
	"      traefik.http.routers.cloud-login.rule: Host(`cloud.${PORTCULLIS_DOMAIN:-portcullis.local}`) && PathPrefix(`/login`)\n" +
	"      traefik.http.routers.cloud-login.priority: \"100\"\n" +
	"      traefik.http.services.cloud.loadbalancer.server.port: \"80\"\n" +
	"  db:\n    image: pg\n"

func newCloudFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	writeFile(t, filepath.Join(f.src, "cloud", "manifest.yaml"), cloudManifest)
	writeFile(t, filepath.Join(f.src, "cloud", "compose.yml"), cloudCompose)
	f.h.Discover()
	if f.h.Template("cloud") == nil || f.h.Template("cloud").Public == nil {
		t.Fatal("cloud template not loaded with a public plan")
	}
	return f
}

func readOverride(t *testing.T, f *fixture, id string) string {
	t.Helper()
	ov, _ := os.ReadFile(filepath.Join(f.data, "overrides", id+".override.yml"))
	return string(ov)
}

func boolp(b bool) *bool          { return &b }
func strp(s string) *string       { return &s }
func listp(s ...string) *[]string { return &s }

func save(t *testing.T, f *fixture, u SettingsUpdate) {
	t.Helper()
	if u.Values == nil {
		u.Values = map[string]string{}
	}
	if err := f.h.SaveSettings("cloud", u); err != nil {
		t.Fatal(err)
	}
	f.h.Wait()
}

var priorityRe = regexp.MustCompile(`portcullis-public-cloud\.priority: "(\d+)"`)

func TestPublicListedNoTokensNoRouter(t *testing.T) {
	f := newCloudFixture(t)
	save(t, f, SettingsUpdate{Policy: &policy.AuthPolicy{Factors: []string{"mtls"}}})
	if err := f.h.Enable("cloud"); err != nil {
		t.Fatal(err)
	}
	ov := readOverride(t, f, "cloud")
	// On by default, listed mode, no shares: nothing opened, no downgrade.
	if strings.Contains(ov, "portcullis-public") || strings.Count(ov, "tls.options: protected@file") != 2 {
		t.Errorf("override:\n%s", ov)
	}
	if doc := readPolicy(t, f); len(doc.PublicPaths) != 0 {
		t.Errorf("public_paths = %v", doc.PublicPaths)
	}
	v, _ := f.h.AppSettings("cloud")
	if v.PublicAccess == nil || !v.PublicAccess.Enabled || v.PublicAccess.Explicit || v.PublicAccess.Mode != "listed" || v.PublicAccess.Active ||
		v.PublicAccess.PolicyTier != "protected@file" || v.PublicAccess.TierWhenActive != "authaware@file" {
		t.Errorf("view = %+v", v.PublicAccess)
	}
}

func TestPublicListedTokens(t *testing.T) {
	f := newCloudFixture(t)
	if err := f.h.Enable("cloud"); err != nil {
		t.Fatal(err)
	}
	save(t, f, SettingsUpdate{
		Policy:       &policy.AuthPolicy{Factors: []string{"mtls"}},
		PublicTokens: listp("https://cloud.example.org/s/AbC123/download", "AbC123", "Zz9", " "),
	})
	ov := readOverride(t, f, "cloud")
	for _, want := range []string{
		"traefik.http.routers.portcullis-public-cloud.rule: \"Host(`cloud.${PORTCULLIS_DOMAIN:-portcullis.local}`) && (Path(`/dist`) || PathPrefix(`/dist/`) || Path(`/s/AbC123`) || PathPrefix(`/s/AbC123/`) || Path(`/s/Zz9`) || PathPrefix(`/s/Zz9/`))\"",
		"portcullis-public-cloud.entrypoints: websecure",
		"portcullis-public-cloud.middlewares: portcullis-public-strip-cloud@docker,rate-limit@file,security-headers@file",
		"portcullis-public-cloud.service: \"cloud\"",
		"traefik.http.middlewares.portcullis-public-strip-cloud.headers.customrequestheaders.X-Forwarded-User: \"\"",
		"traefik.http.middlewares.portcullis-public-strip-cloud.headers.customrequestheaders.X-Auth-Request-Email: \"\"",
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("override lacks %s:\n%s", want, ov)
		}
	}
	if strings.Contains(ov, "/apps/text") || strings.Contains(ov, "portcullis-auth") {
		t.Errorf("listed mode opened a share-wide path or gated the public router:\n%s", ov)
	}
	// TLS tier rule: the mtls policy would be protected@file; with a public
	// router every router of the host shares authaware@file.
	if strings.Contains(ov, "protected@file") || strings.Count(ov, "tls.options: authaware@file") != 3 {
		t.Errorf("tier not downgraded for all routers:\n%s", ov)
	}
	m := priorityRe.FindStringSubmatch(ov)
	if m == nil {
		t.Fatalf("no priority:\n%s", ov)
	}
	if p, _ := strconv.Atoi(m[1]); p <= 100 || p <= len("Host(`cloud.${PORTCULLIS_DOMAIN:-portcullis.local}`)")+253 {
		t.Errorf("priority %d does not beat the app's routers", p)
	}

	doc := readPolicy(t, f)
	if strings.Join(doc.PublicPaths["cloud"], ",") != "/dist,/s/{token}" {
		t.Errorf("public_paths = %v", doc.PublicPaths)
	}
	raw, _ := os.ReadFile(filepath.Join(f.data, "group-gate-policy.json"))
	if strings.Contains(string(raw), "AbC123") {
		t.Error("share token leaked into the policy file")
	}
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	if strings.Join(st.PublicTokens["cloud"], ",") != "AbC123,Zz9" || strings.Join(st.Published["cloud"].PublicPaths, ",") != "/dist,/s/{token}" ||
		strings.Join(st.Published["cloud"].PublicSubdomains, ",") != "cloud" {
		t.Errorf("state tokens %v snapshot %+v", st.PublicTokens, st.Published["cloud"])
	}

	// Mode all: every share, share-wide paths too, tokens kept for later.
	save(t, f, SettingsUpdate{PublicMode: strp("all")})
	ov = readOverride(t, f, "cloud")
	if !strings.Contains(ov, "Path(`/apps/text`)") || !strings.Contains(ov, "PathPrefix(`/s/`)") || strings.Contains(ov, "AbC123") {
		t.Errorf("mode all:\n%s", ov)
	}
	// Remove all tokens and go back to listed: no router, tier restored.
	save(t, f, SettingsUpdate{PublicMode: strp("listed"), PublicTokens: listp()})
	ov = readOverride(t, f, "cloud")
	if strings.Contains(ov, "portcullis-public") || !strings.Contains(ov, "protected@file") {
		t.Errorf("empty list:\n%s", ov)
	}
	if doc := readPolicy(t, f); len(doc.PublicPaths) != 0 {
		t.Errorf("public_paths after emptying = %v", doc.PublicPaths)
	}
}

func TestPublicToggle(t *testing.T) {
	f := newCloudFixture(t)
	save(t, f, SettingsUpdate{PublicMode: strp("all")})
	if err := f.h.Enable("cloud"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readOverride(t, f, "cloud"), "portcullis-public-cloud.rule") {
		t.Fatal("router missing while on")
	}
	save(t, f, SettingsUpdate{PublicAccess: boolp(false)})
	if ov := readOverride(t, f, "cloud"); strings.Contains(ov, "portcullis-public") {
		t.Errorf("toggle off kept the router:\n%s", ov)
	}
	if doc := readPolicy(t, f); len(doc.PublicPaths) != 0 {
		t.Errorf("public_paths while off = %v", doc.PublicPaths)
	}
	// An explicit choice survives a template default change; "default"
	// hands control back to the template.
	writeFile(t, filepath.Join(f.src, "cloud", "manifest.yaml"), strings.Replace(cloudManifest, "enabled_by_default: true", "enabled_by_default: false", 1))
	f.h.Discover()
	save(t, f, SettingsUpdate{PublicAccess: boolp(true)})
	if !strings.Contains(readOverride(t, f, "cloud"), "portcullis-public-cloud.rule") {
		t.Error("explicit on ignored")
	}
	save(t, f, SettingsUpdate{PublicAccessDefault: true})
	if strings.Contains(readOverride(t, f, "cloud"), "portcullis-public") {
		t.Error("template default (off) not applied after reset")
	}
}

func TestPublicSettingsValidation(t *testing.T) {
	f := newCloudFixture(t)
	for name, u := range map[string]SettingsUpdate{
		"bad token":   {PublicTokens: listp("a`) || Host(`evil")},
		"foreign url": {PublicTokens: listp("https://cloud.example.org/apps/files/")},
		"dot token":   {PublicTokens: listp("..")},
		"bad mode":    {PublicMode: strp("some")},
		"too many": {PublicTokens: func() *[]string {
			var l []string
			for i := 0; i <= templates.MaxPublicTokens; i++ {
				l = append(l, "t"+strconv.Itoa(i))
			}
			return &l
		}()},
	} {
		u.Values = map[string]string{}
		if err := f.h.SaveSettings("cloud", u); statusOf(err) != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := f.h.SaveSettings("grafana", SettingsUpdate{Values: map[string]string{}, PublicAccess: boolp(true)}); statusOf(err) != 400 {
		t.Errorf("public access on an app without public_access: %v", err)
	}
	st, _ := state.Load(filepath.Join(f.data, "state.yaml"))
	if len(st.PublicTokens) != 0 || len(st.PublicMode) != 0 || len(st.PublicAccess) != 0 {
		t.Errorf("rejected updates changed state: %+v %+v %+v", st.PublicTokens, st.PublicMode, st.PublicAccess)
	}
}

func TestPublicSnapshotWhenTemplateMissing(t *testing.T) {
	f := newCloudFixture(t)
	save(t, f, SettingsUpdate{PublicMode: strp("all")})
	if err := f.h.Enable("cloud"); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(f.src, "cloud"))
	f.h.Discover()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	doc := readPolicy(t, f)
	if doc.Groups["cloud"] != "users_cloud" || strings.Join(doc.PublicPaths["cloud"], ",") != "/apps/text,/dist,/s" {
		t.Errorf("snapshot not enforced: groups %v public %v", doc.Groups, doc.PublicPaths)
	}
}

func TestPublicDrift(t *testing.T) {
	f := newCloudFixture(t)
	save(t, f, SettingsUpdate{PublicMode: strp("all")})
	if err := f.h.Enable("cloud"); err != nil {
		t.Fatal(err)
	}
	c := container("c1", "portcullis-cloud", "cloud", "running")
	f.engine.containers = []docker.Container{c}
	// Running without the public router while the Hub wants it.
	rep := f.h.Reconcile(context.Background())
	d := driftFor(rep, "cloud")
	if d == nil || d.Kind != DriftPublicAccess || d.Actions[0] != ActionApply {
		t.Fatalf("drift = %+v", rep.Items)
	}
	// Running with exactly the wanted router: no drift.
	c.Labels["traefik.http.routers.portcullis-public-cloud.rule"] = "Host(`cloud.example.org`) && (Path(`/apps/text`) || PathPrefix(`/apps/text/`) || Path(`/dist`) || PathPrefix(`/dist/`) || Path(`/s`) || PathPrefix(`/s/`))"
	f.engine.containers = []docker.Container{c}
	if d := driftFor(f.h.Reconcile(context.Background()), "cloud"); d != nil {
		t.Errorf("unexpected drift %+v", d)
	}
	// Admin turns it off but the containers still route it.
	f.runner.upErr = nil
	save(t, f, SettingsUpdate{PublicAccess: boolp(false)})
	if d := driftFor(f.h.Reconcile(context.Background()), "cloud"); d == nil || d.Kind != DriftPublicAccess {
		t.Errorf("stale public router not reported: %+v", d)
	}
	n := len(f.runner.Calls())
	if err := f.h.ResolveDrift("cloud", ActionApply); err != nil {
		t.Fatal(err)
	}
	if c := f.runner.Calls()[n:]; strings.Join(c, " ") != "up:portcullis-cloud" {
		t.Errorf("apply calls = %v", c)
	}
	// A not-enabled project still routing a public router says so.
	f.h.Disable("cloud")
	f.engine.containers = []docker.Container{c}
	if d := driftFor(f.h.Reconcile(context.Background()), "cloud"); d == nil || d.Kind != DriftNotEnabled || !strings.Contains(d.Message, "bypasses forward-auth") {
		t.Errorf("running_not_enabled with public router = %+v", d)
	}
}

func TestPublicExpertComposeOverlap(t *testing.T) {
	f := newCloudFixture(t)
	bad := strings.Replace(cloudCompose, "PathPrefix(`/login`)", "PathPrefix(`/s`)", 1)
	if err := f.h.SaveComposeFiles("cloud", bad, ""); statusOf(err) != 400 {
		t.Errorf("compose whose router overlaps a public path accepted: %v", err)
	}
}
