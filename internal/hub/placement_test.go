package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/compose-spec/compose-go/v2/cli"
	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// workerFake is a worker's agent backend as the Hub sees it: an engine
// (runtimetest.Fake), its /v1/info and the bundles pushed to it.
type workerFake struct {
	*runtimetest.Fake
	mu      sync.Mutex
	info    agentapi.Info
	infoErr error
	pullErr error
	bundles []map[string]string
}

func (w *workerFake) AgentInfo(context.Context) (agentapi.Info, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.info, w.infoErr
}

func (w *workerFake) Pull(ctx context.Context, ref string, fn func(int64, int64, bool)) error {
	w.Fake.Pull(ctx, ref, fn)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pullErr
}

func (w *workerFake) PushBundle(_ context.Context, id string, files fs.FS, m agentapi.BundleManifest) error {
	got := map[string]string{}
	for n := range m.Files {
		f, err := files.Open(n)
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(f)
		f.Close()
		got[n] = string(b)
	}
	w.mu.Lock()
	w.bundles = append(w.bundles, got)
	w.mu.Unlock()
	w.Fake.Signal(context.Background(), "bundle", id) // recorded in order
	return nil
}

func (w *workerFake) lastBundle() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.bundles) == 0 {
		return nil
	}
	return w.bundles[len(w.bundles)-1]
}

type placedFixture struct {
	*fixture
	w *workerFake
}

const relayImage = "ghcr.io/porelli/portcullis-relay:edge"

// newPlacedFixture: a ready worker "nas" (docker, amd64) behind a fake
// agent backend, and the templates of the placement tests.
func newPlacedFixture(t *testing.T) *placedFixture {
	t.Helper()
	f := newFixture(t)
	for id, files := range map[string][2]string{
		"tcpapp":   {"name: TCP\ncategory: misc\nai: {unsupported: t}\nplacement: primary_only\nauth: {method: forward-auth}\n", "services:\n  web:\n    image: tcp:1\n    labels:\n      traefik.http.routers.t.rule: Host(`${PORTCULLIS_HOST_T:-t.portcullis.local}`)\n"},
		"lowport":  {"name: Low\ncategory: misc\nai: {unsupported: t}\nauth: {method: forward-auth}\nports:\n  - key: LOW_PORT\n    container: 80\n    default: 80\n    service: web\n", "services:\n  web:\n    image: low:1\n    labels:\n      traefik.http.routers.low.rule: Host(`${PORTCULLIS_HOST_LOW:-low.portcullis.local}`)\n"},
		"filesapp": {"name: Files\ncategory: misc\nai: {unsupported: t}\nauth:\n  method: forward-auth\n", "services:\n  web:\n    image: files:1\n    restart: unless-stopped\n    volumes:\n      - ./templates/filesapp/conf.ini:/etc/conf.ini:ro\n      - data:/data\n    labels:\n      traefik.enable: \"true\"\n      traefik.http.routers.files.rule: Host(`${PORTCULLIS_HOST_FILES:-files.portcullis.local}`)\n      traefik.http.routers.files.middlewares: portcullis-auth@docker,portcullis-groups@docker\n      traefik.http.services.files.loadbalancer.server.port: \"8080\"\nvolumes:\n  data: {}\n"},
	} {
		writeFile(t, filepath.Join(f.src, id, "manifest.yaml"), files[0])
		writeFile(t, filepath.Join(f.src, id, "compose.yml"), files[1])
	}
	writeFile(t, filepath.Join(f.src, "filesapp", "conf.ini"), "[x]\n")
	f.h.Discover()
	for _, id := range []string{"tcpapp", "lowport", "filesapp"} {
		if f.h.Template(id) == nil {
			t.Fatalf("template %s not loaded", id)
		}
	}
	f.h.cfg.RelayImage = relayImage
	w := &workerFake{Fake: &runtimetest.Fake{Infos: map[string]runtime.UnitInfo{}, Volumes: map[string]runtime.Volume{}, States: map[string]runtime.State{}},
		info: agentapi.Info{AgentVersion: "0.1.0", Runtime: "docker", Arch: "amd64", DataDir: "/srv/w/worker-data", DockerRootDir: "/var/lib/docker",
			UnprivilegedPortStart: 1024, BindRoots: []string{"/srv", "/mnt"}}}
	f.h.mu.Lock()
	f.h.st.Servers = map[string]state.Server{"nas": {Name: "NAS", TunnelIP: "10.214.0.10", State: ServerReady}}
	f.h.mu.Unlock()
	f.h.setServer("nas", &serverRT{Name: "NAS", State: ServerReady, RT: w})
	return &placedFixture{fixture: f, w: w}
}

func (p *placedFixture) create(t *testing.T, template, server string) error {
	t.Helper()
	_, err := p.h.CreateInstanceAs(CreateRequest{Template: template, ID: template, Label: template, Server: server}, admin)
	return err
}

// TestPlacementRefusals: each refusal is a 409 before anything is
// created — no project, no client, no group, no state entry.
func TestPlacementRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		template string
		setup    func(p *placedFixture)
		want     string
	}{
		"offline":      {"filesapp", func(p *placedFixture) { p.h.setServer("nas", &serverRT{Name: "NAS", State: ServerOffline, RT: p.w}) }, "server NAS is offline"},
		"unknown":      {"filesapp", func(p *placedFixture) { p.h.setServer("nas", nil) }, "server nas is unknown"},
		"primary only": {"tcpapp", nil, "TCP can't run on a worker: "},
		"compat":       {"lowport", func(p *placedFixture) { p.w.info.Runtime, p.w.info.Rootless = "podman", true }, "can't run on NAS (podman): host port 80/tcp"},
		"no arch image": {"filesapp", func(p *placedFixture) {
			p.w.pullErr = errors.New("no matching manifest for linux/arm64 in the manifest list entries")
			p.w.info.Arch = "arm64"
		}, "files:1 has no arm64 image"},
		"revoked meanwhile": {"filesapp", func(p *placedFixture) {
			p.h.mu.Lock()
			s := p.h.st.Servers["nas"]
			s.Revoke = &state.RevokeSteps{}
			p.h.st.Servers["nas"] = s
			p.h.mu.Unlock()
		}, "server NAS is revoked"},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPlacedFixture(t)
			if c.setup != nil {
				c.setup(p)
			}
			err := p.create(t, c.template, "nas")
			if errStatus(err) != 409 || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v (want %q)", err, c.want)
			}
			p.h.mu.RLock()
			_, entry := p.h.st.Instances[c.template]
			p.h.mu.RUnlock()
			if entry {
				t.Error("a state entry was made")
			}
			for _, call := range p.w.Calls() {
				if !strings.HasPrefix(call, "pull ") {
					t.Errorf("the worker got %s", call)
				}
			}
			if len(p.idp.registered) != 0 || len(p.runner.Calls()) != 0 {
				t.Errorf("created: clients %v, primary %v", p.idp.registered, p.runner.Calls())
			}
		})
	}
}

// TestLifecycleOnWorker (Task 10 order): bundle, create and up on the
// worker, then the relay token, link.json and the relays on the primary;
// a down takes the relays down first.
func TestLifecycleOnWorker(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", "nas"); err != nil {
		t.Fatal(err)
	}
	if p.h.serverOf("filesapp") != "nas" {
		t.Fatalf("server %q", p.h.serverOf("filesapp"))
	}
	if err := p.h.Enable("filesapp"); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, c := range p.w.Calls() {
		if strings.HasPrefix(c, "signal bundle") || strings.HasPrefix(c, "create ") || strings.HasPrefix(c, "up ") {
			order = append(order, strings.Fields(c)[0])
		}
	}
	if strings.Join(order, ",") != "signal,create,up" {
		t.Errorf("worker order %v (%v)", order, p.w.Calls())
	}
	b := p.w.lastBundle()
	for _, n := range []string{"compose.yml", "env", "templates/filesapp/conf.ini"} {
		if _, ok := b[n]; !ok {
			t.Errorf("bundle lacks %s: %v", n, slices.Sorted(maps2keys(b)))
		}
	}
	// The relays on the primary, after the worker's up.
	p.runner.mu.Lock()
	creates := append([]string(nil), p.runner.creates...)
	p.runner.mu.Unlock()
	if pc := strings.Join(p.runner.Calls(), ","); !slices.Contains(creates, "portcullis-filesapp") || !strings.Contains(pc, "up:portcullis-filesapp") {
		t.Errorf("primary calls %s, creates %v", pc, creates)
	}
	if p.h.relayTokenSHA("filesapp") == "" {
		t.Error("no relay token")
	}
	relay, err := os.ReadFile(p.h.relayComposePath("filesapp"))
	if err != nil || !strings.Contains(string(relay), relayImage) || !strings.Contains(string(relay), "RELAY_TARGET: filesapp.web.relay") {
		t.Errorf("relay file %v:\n%s", err, relay)
	}
	if fi, err := os.Stat(p.h.relayComposePath("filesapp")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("relay file mode %v %v", fi, err)
	}
	// Down: relays first.
	before := len(p.runner.Calls())
	wbefore := len(p.w.Calls())
	if err := p.h.Disable("filesapp"); err != nil {
		t.Fatal(err)
	}
	if pc := p.runner.Calls()[before:]; len(pc) == 0 || pc[0] != "downbyname:portcullis-filesapp" {
		t.Errorf("primary on down %v", pc)
	}
	if !slices.ContainsFunc(p.w.Calls()[wbefore:], func(c string) bool { return strings.HasPrefix(c, "down ") }) {
		t.Errorf("worker on down %v", p.w.Calls()[wbefore:])
	}
}

func maps2keys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// TestLifecycleOfflineIs409: a placed instance's lifecycle while its
// server is offline is 409 "server NAS is offline"; nothing reaches it.
func TestLifecycleOfflineIs409(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", "nas"); err != nil {
		t.Fatal(err)
	}
	p.h.setServer("nas", &serverRT{Name: "NAS", State: ServerOffline, RT: p.w})
	calls := len(p.w.Calls())
	err := p.h.Enable("filesapp")
	if errStatus(err) != 409 || !strings.Contains(err.Error(), "server NAS is offline") {
		t.Errorf("enable: %v", err)
	}
	if got := p.w.Calls()[calls:]; len(got) != 0 {
		t.Errorf("the offline worker got %v", got)
	}
}

// TestRenderUsesTargetEngineFacts: a podman + SELinux worker under a
// docker primary: z relabels and restart: always only in the worker's
// render; the data files at the worker's <data>/appfiles.
func TestRenderUsesTargetEngineFacts(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", ""); err != nil {
		t.Fatal(err)
	}
	render := func() string {
		p.h.mu.Lock()
		defer p.h.mu.Unlock()
		v := p.h.findLocked("filesapp")
		out, err := p.h.renderOverrideLocked(v, p.h.st.Settings["filesapp"])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	primary := render()
	if strings.Contains(primary, "selinux: z") || strings.Contains(primary, "restart: always") {
		t.Errorf("docker primary render:\n%s", primary)
	}
	p.w.info.Runtime, p.w.info.Rootless, p.w.info.SELinux = "podman", true, true
	p.h.notePoll("nas", &p.w.info, "")
	p.h.mu.Lock()
	in := p.h.st.Instances["filesapp"]
	in.Server = "nas"
	p.h.st.Instances["filesapp"] = in
	p.h.noteServersLocked()
	p.h.mu.Unlock()
	worker := render()
	if !strings.Contains(worker, "selinux: z") || !strings.Contains(worker, "restart: always") {
		t.Errorf("podman+SELinux worker render:\n%s", worker)
	}
	if f := p.h.factsFor("filesapp"); f.AppFilesHost != "/srv/w/worker-data/appfiles" || f.Kind != runtime.KindPodman {
		t.Errorf("facts %+v", f)
	}
}

// TestFolderOfOtherServerRefused: a shared folder on the primary can't
// be bound by an instance on a worker (and the reverse).
func TestFolderOfOtherServerRefused(t *testing.T) {
	p := newPlacedFixture(t)
	p.h.mu.Lock()
	if p.h.st.Folders == nil {
		p.h.st.Folders = map[string]state.Folder{}
	}
	p.h.st.Folders["photos"] = state.Folder{Name: "Photos", Path: "/srv/photos", GID: 60001}
	p.h.mu.Unlock()
	f := state.Folder{Name: "Photos", Path: "/srv/photos", GID: 60001}
	rv := renderView{folders: map[string]state.Folder{"photos": f}}
	v := p.h.Template("grafana")
	var opt *templates.Option
	for i := range v.Manifest.Settings.Options {
		if v.Manifest.Settings.Options[i].Key == "media" {
			opt = &v.Manifest.Settings.Options[i]
		}
	}
	p.h.noteInstanceServer("grafana", "nas")
	_, err := p.h.folderMountIn(rv, v, opt, "folder:photos")
	if err == nil || !strings.Contains(err.Error(), "shared folder photos is on the primary, but grafana runs on server nas") {
		t.Errorf("worker instance, primary folder: %v", err)
	}
	f.Server = "nas"
	rv.folders["photos"] = f
	p.h.noteInstanceServer("grafana", "")
	_, err = p.h.folderMountIn(rv, v, opt, "folder:photos")
	if err == nil || !strings.Contains(err.Error(), "is on server nas, but grafana runs on the primary") {
		t.Errorf("primary instance, worker folder: %v", err)
	}
}

// TestLanOnlyUsesServerLocalNetworks: a placed instance's Local networks
// are its server's (default: the Hub's default list, never the primary's
// own setting).
func TestLanOnlyUsesServerLocalNetworks(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", "nas"); err != nil {
		t.Fatal(err)
	}
	mine := []string{"10.9.0.0/16"}
	p.h.mu.Lock()
	p.h.st.LocalNetworks = &mine
	got := p.h.localNetworksEnvForLocked("filesapp")
	s := p.h.st.Servers["nas"]
	theirs := []string{"192.168.7.0/24"}
	s.LocalNetworks = &theirs
	p.h.st.Servers["nas"] = s
	got2 := p.h.localNetworksEnvForLocked("filesapp")
	primary := p.h.localNetworksEnvForLocked("grafana")
	p.h.mu.Unlock()
	if got != strings.Join(DefaultLocalNetworks, ",") {
		t.Errorf("default for a worker: %q", got)
	}
	if got2 != "192.168.7.0/24" || primary != "10.9.0.0/16" {
		t.Errorf("worker %q primary %q", got2, primary)
	}
}

// TestOrphanForget: an orphaned instance is forgotten (state, clients
// removed, relays down on the primary), nothing on its worker touched;
// anything else refuses.
func TestOrphanForget(t *testing.T) {
	p := newPlacedFixture(t)
	if err := p.create(t, "filesapp", "nas"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.h.ForgetInstance("filesapp", "filesapp", admin); errStatus(err) != 409 {
		t.Errorf("forget a live one: %v", err)
	}
	p.h.mu.Lock()
	p.h.beginRevokeLocked("nas", false)
	p.h.mu.Unlock()
	calls := len(p.w.Calls())
	if _, err := p.h.ForgetInstance("filesapp", "wrong", admin); errStatus(err) != 400 {
		t.Errorf("no typed id: %v", err)
	}
	if _, err := p.h.ForgetInstance("filesapp", "filesapp", admin); err != nil {
		t.Fatal(err)
	}
	p.h.mu.RLock()
	_, still := p.h.st.Instances["filesapp"]
	p.h.mu.RUnlock()
	if still || p.h.serverOf("filesapp") != "" {
		t.Error("still in state")
	}
	if got := p.w.Calls()[calls:]; len(got) != 0 {
		t.Errorf("the revoked worker was touched: %v", got)
	}
	if !slices.Contains(p.runner.Calls(), "downbyname:portcullis-filesapp") {
		t.Errorf("relays not down: %v", p.runner.Calls())
	}
}

// relayLabelsOf is what compose would put on each relay container: the
// relay file loaded with compose-go (its $$ unescaped).
func relayLabelsOf(t *testing.T, file string) map[string]map[string]string {
	t.Helper()
	po, err := cli.NewProjectOptions([]string{file}, cli.WithName("relays"), cli.WithWorkingDirectory(filepath.Dir(file)),
		cli.WithConsistency(false), cli.WithoutEnvironmentResolution)
	if err != nil {
		t.Fatal(err)
	}
	proj, err := po.LoadProject(context.Background())
	if err != nil {
		t.Fatalf("the relay file doesn't load: %v", err)
	}
	out := map[string]map[string]string{}
	for n, s := range proj.Services {
		out[n] = s.Labels
	}
	return out
}

// checkRelayAuth: for every router of the instance (its loaded model),
// the relay carries the same middlewares — portcullis-auth and
// portcullis-groups included — and the same rule, entrypoints and TLS.
func checkRelayAuth(model map[string]map[string]string, relays map[string]map[string]string) error {
	for svc, labels := range model {
		routed := false
		for k, v := range labels {
			if templates.FoldKey(k) == "traefik.enable" && strings.EqualFold(v, "true") {
				routed = true
			}
		}
		if !routed {
			continue
		}
		r, ok := relays[svc]
		if !ok {
			return fmt.Errorf("service %s has no relay", svc)
		}
		for k, v := range labels {
			if !strings.HasPrefix(templates.FoldKey(k), "traefik.") {
				continue
			}
			if r[k] != v {
				return fmt.Errorf("service %s: %s is %q on the relay, %q on the primary", svc, k, r[k], v)
			}
		}
		for k := range r {
			if _, ok := labels[k]; !ok && strings.HasPrefix(k, "traefik.") {
				return fmt.Errorf("service %s: the relay adds %s", svc, k)
			}
		}
	}
	return nil
}

// relayCheck renders instance id's relays and compares them with the
// labels its containers would carry on the primary.
func relayCheck(t *testing.T, h *Hub, id string) (model, relays map[string]map[string]string) {
	t.Helper()
	h.cfg.RelayImage = relayImage
	h.newRelayToken(id)
	h.mu.RLock()
	v := *h.findLocked(id)
	h.mu.RUnlock()
	proj, err := h.loadRuntime(context.Background(), &v)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.RLock()
	b, err := h.renderRelaysLocked(&v, proj)
	h.mu.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	model = map[string]map[string]string{}
	for n, s := range proj.Services {
		model[n] = s.Labels
	}
	if b == nil {
		return model, map[string]map[string]string{}
	}
	file := filepath.Join(t.TempDir(), "relays.yml")
	os.WriteFile(file, b, 0o600)
	var parsed relayFile
	if err := yaml.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}
	for n, s := range parsed.Services {
		if s.Image != relayImage || s.User != "65534:65534" || !s.ReadOnly || !slices.Equal(s.CapDrop, []string{"ALL"}) || s.MemLimit != "64m" || s.PidsLimit != 64 {
			t.Errorf("%s relay %s: %+v", id, n, s)
		}
		if _, ok := s.Networks["portcullis-proxy"]; !ok {
			t.Errorf("%s relay %s networks %v", id, n, s.Networks)
		}
		for k := range s.Labels {
			if strings.HasPrefix(k, "com.docker.compose") {
				t.Errorf("%s relay %s carries %s", id, n, k)
			}
		}
	}
	return model, relayLabelsOf(t, file)
}

// TestRelayLabelsEqualPrimaryGoldens: for the golden instances (grafana,
// disks) and every VPN reach golden, the relay's labels are exactly the
// labels the instance's container carries on the primary.
func TestRelayLabelsEqualPrimaryGoldens(t *testing.T) {
	f, _ := goldenRun(t, false)
	for _, id := range []string{"grafana", "disks"} {
		model, relays := relayCheck(t, f.h, id)
		if err := checkRelayAuth(model, relays); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
	if _, r := relayCheck(t, f.h, "grafana"); !strings.Contains(r["web"]["traefik.http.routers.grafana.middlewares"], "portcullis-groups@docker") {
		t.Errorf("grafana relay middlewares %v", r["web"])
	}
	for _, mode := range []string{VPNModeApps, VPNModeServer} {
		for _, rc := range []struct {
			name string
			r    *state.Reach
		}{{"internet", nil}, {"vpn_any", &state.Reach{Mode: state.ReachVPN, Via: []string{"*"}}}, {"vpn_builtin", &state.Reach{Mode: state.ReachVPN, Via: []string{"builtin"}}}} {
			t.Run(mode+"_"+rc.name, func(t *testing.T) {
				v := newReachFixture(t, mode)
				v.wire(t, "mesh")
				v.devicesOut = devicesDoc("100.64.0.1")
				v.h.runVPNProvider(context.Background(), "mesh")
				if rc.r != nil {
					setReach(t, v, "cloud", *rc.r)
				}
				overrideOf(t, v, "cloud")
				model, relays := relayCheck(t, v.h, "cloud")
				if err := checkRelayAuth(model, relays); err != nil {
					t.Error(err)
				}
				if len(relays) == 0 {
					t.Error("no relay")
				}
			})
		}
	}
}

// TestRelayNeverDropsAuthMiddlewares: the check catches a relay that
// lost portcullis-groups (a mutation of the rendered relay).
func TestRelayNeverDropsAuthMiddlewares(t *testing.T) {
	f, _ := goldenRun(t, false)
	model, relays := relayCheck(t, f.h, "grafana")
	if err := checkRelayAuth(model, relays); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0)
	for k := range relays["web"] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	mutated := false
	for _, k := range keys {
		if strings.HasSuffix(k, ".middlewares") && strings.Contains(relays["web"][k], "portcullis-groups@docker") {
			relays["web"][k] = strings.ReplaceAll(relays["web"][k], "portcullis-groups@docker,", "")
			mutated = true
		}
	}
	if !mutated {
		t.Fatal("no portcullis-groups to remove")
	}
	if err := checkRelayAuth(model, relays); err == nil || !strings.Contains(err.Error(), "middlewares") {
		t.Errorf("a relay without portcullis-groups passed: %v", err)
	}
}
