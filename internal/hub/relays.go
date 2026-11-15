package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/templates"
)

// Relays and bundles (contract §17, Task 10). A placed instance's routed
// services are stood in for on the primary by relay containers (project
// portcullis-<id>, image HUB_RELAY_IMAGE), carrying exactly the Traefik
// labels the instance would carry on the primary — the same routers,
// middlewares (portcullis-auth, portcullis-groups, …) and TLS options —
// so access control is the primary's, unchanged. The instance itself
// runs on the worker from a bundle the Hub renders for it.

// The bundle's layout (internal/agent: the agent's names).
const (
	bundleCompose      = "compose.yml"
	bundleOverride     = "override.yml"
	bundleUserOverride = "user.yml"
	bundleEnv          = "env"
	bundleAppfiles     = "appfiles/"
	bundleCerts        = "certs/ca-bundle.crt"
	// Core's portcullis-link-data address of link's data CONNECT
	// listener (docker-compose.yml PORTCULLIS_LINK_DATA_WG_IP).
	defaultLinkDataWGIP = "172.31.254.130"
	linkDataPort        = 3129
	// RelayNetwork is the relays' network to link.
	RelayNetwork = "portcullis-link-data"
)

func (h *Hub) relayComposePath(id string) string {
	return filepath.Join(h.cfg.DataDir, "relays", id+".yml")
}

// unwrapRT is the runtime under a wrapper (placedRT), else rt.
func unwrapRT(rt runtime.Instances) runtime.Instances {
	if u, ok := rt.(interface{ Unwrap() runtime.Instances }); ok {
		return u.Unwrap()
	}
	return rt
}

var lbPortRe = regexp.MustCompile(`^traefik\.http\.services\.[^.]+\.loadbalancer\.server\.port$`)

// relayService is one relay in the relay compose file.
type relayService struct {
	Image       string            `yaml:"image"`
	User        string            `yaml:"user"`
	ReadOnly    bool              `yaml:"read_only"`
	CapDrop     []string          `yaml:"cap_drop"`
	SecurityOpt []string          `yaml:"security_opt"`
	MemLimit    string            `yaml:"mem_limit"`
	PidsLimit   int               `yaml:"pids_limit"`
	Restart     string            `yaml:"restart"`
	Networks    map[string]any    `yaml:"networks"`
	EnvFile     []string          `yaml:"env_file"`
	Environment map[string]string `yaml:"environment"`
	Labels      map[string]string `yaml:"labels"`
}

type relayFile struct {
	Name     string                  `yaml:"name"`
	Services map[string]relayService `yaml:"services"`
	Networks map[string]any          `yaml:"networks"`
}

// relayLabels are the traefik.* labels of a service in the loaded model:
// exactly what its container would carry on the primary (com.docker.*
// and anything else never copied).
func relayLabels(s types.ServiceConfig) map[string]string {
	out := map[string]string{}
	for k, v := range s.Labels {
		if strings.HasPrefix(templates.FoldKey(k), "traefik.") {
			out[k] = v
		}
	}
	return out
}

// routedServices are the model's services with traefik.enable=true.
func routedServices(model *types.Project) []string {
	var out []string
	for n, s := range model.Services {
		for k, v := range s.Labels {
			if templates.FoldKey(k) == "traefik.enable" && strings.EqualFold(strings.TrimSpace(v), "true") {
				out = append(out, n)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// renderRelaysLocked is instance t's relay compose file ("" content:
// nothing routed, no relay). Caller holds mu (read).
func (h *Hub) renderRelaysLocked(t *templates.Template, model *types.Project) ([]byte, error) {
	if !RelayImageOK(h.cfg.RelayImage) {
		return nil, errNoRelayImage()
	}
	routed := routedServices(model)
	if len(routed) == 0 {
		return nil, nil
	}
	server := h.st.Instances[t.ID].Server
	srvName := server
	if s, ok := h.st.Servers[server]; ok && s.Name != "" {
		srvName = s.Name
	}
	app := t.Manifest.Name
	if l := h.st.Instances[t.ID].Label; l != "" {
		app = l
	}
	core := readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env"))
	linkIP := strings.TrimSpace(core["PORTCULLIS_LINK_DATA_WG_IP"])
	if linkIP == "" {
		linkIP = defaultLinkDataWGIP
	}
	f := relayFile{Name: projectName(t.ID), Services: map[string]relayService{},
		Networks: map[string]any{"portcullis-proxy": map[string]any{"external": true}, RelayNetwork: map[string]any{"external": true}}}
	for _, n := range routed {
		s := model.Services[n]
		labels := relayLabels(s)
		var ports []int
		for k, v := range labels {
			if lbPortRe.MatchString(templates.FoldKey(k)) {
				p, err := strconv.Atoi(strings.TrimSpace(v))
				if err != nil || p < 1 || p > 65535 {
					return nil, statusErr(409, "%s: service %s: the port label %s isn't a port", t.ID, n, k)
				}
				ports = append(ports, p)
			}
		}
		if len(ports) == 0 {
			return nil, statusErr(409, "%s: service %s is routed without a traefik loadbalancer port label: it can't be relayed from a worker", t.ID, n)
		}
		sort.Ints(ports)
		listen := make([]string, len(ports))
		for i, p := range ports {
			listen[i] = ":" + strconv.Itoa(p)
		}
		restart := s.Restart
		if restart == "" {
			restart = "unless-stopped"
		}
		f.Services[n] = relayService{Image: h.cfg.RelayImage, User: "65534:65534", ReadOnly: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}, MemLimit: "64m", PidsLimit: 64, Restart: restart,
			Networks: map[string]any{"portcullis-proxy": map[string]any{}, RelayNetwork: map[string]any{}},
			EnvFile:  []string{h.relayEnvPath(t.ID)},
			Environment: map[string]string{"RELAY_LISTEN": strings.Join(listen, ","), "RELAY_TARGET": t.ID + "." + n + ".relay",
				"RELAY_LINK": fmt.Sprintf("%s:%d", linkIP, linkDataPort), "RELAY_APP_LABEL": app, "RELAY_SERVER_LABEL": srvName},
			Labels: labels}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	// compose interpolates: every $ of a label is literal.
	return []byte(strings.ReplaceAll(buf.String(), "$", "$$")), nil
}

// relaysUp brings instance id's relays up on the primary (after its up
// on the worker): its token (made once), link.json with its relay, then
// the relay project.
func (h *Hub) relaysUp(ctx context.Context, id string) error {
	if h.rt == nil {
		return nil
	}
	if h.relayTokenSHA(id) == "" {
		if err := h.newRelayToken(id); err != nil {
			return statusErr(500, "the relay token of %s: %v", id, err)
		}
	}
	h.mu.RLock()
	v := h.findLocked(id)
	var t templates.Template
	if v != nil {
		t = *v
	}
	h.mu.RUnlock()
	if v == nil {
		return statusErr(409, "instance %s does not resolve", id)
	}
	model, err := h.loadRuntime(ctx, &t)
	if err != nil {
		return statusErr(500, "%s: compose can't load the project for its relays", id)
	}
	h.mu.Lock()
	perr := h.publishLinkLocked()
	b, rerr := h.renderRelaysLocked(&t, model)
	h.mu.Unlock()
	if perr != nil {
		return statusErr(500, "link.json: %v", perr)
	}
	if rerr != nil {
		return rerr
	}
	if b == nil {
		return h.relaysDown(ctx, id)
	}
	p := h.relayComposePath(id)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := writeAtomic0600(p, b); err != nil {
		return err
	}
	rp := runtime.Project{Name: projectName(id), Instance: id, Files: compose.Project{Name: projectName(id), Files: []string{p}, ProjectDir: h.cfg.ProjectHostDir}}
	if err := h.rt.Create(ctx, rp); err != nil {
		return fmt.Errorf("relays of %s: %w", id, err)
	}
	if err := h.rt.Up(ctx, rp, nil); err != nil {
		return fmt.Errorf("relays of %s: %w", id, err)
	}
	return nil
}

// relaysDown takes instance id's relays down on the primary (before its
// down on the worker).
func (h *Hub) relaysDown(ctx context.Context, id string) error {
	if h.rt == nil {
		return nil
	}
	if err := h.rt.DownByName(ctx, projectName(id)); err != nil {
		return fmt.Errorf("relays of %s: %w", id, err)
	}
	return nil
}

func writeAtomic0600(p string, b []byte) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// memFS is a read-only in-memory fs.FS of bundle files.
type memFS map[string][]byte

type memFile struct {
	*bytes.Reader
	name string
	size int64
}

func (f *memFile) Stat() (fs.FileInfo, error) { return memInfo{f.name, f.size}, nil }
func (f *memFile) Close() error               { return nil }

type memInfo struct {
	name string
	size int64
}

func (i memInfo) Name() string       { return path.Base(i.name) }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return 0o444 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }

func (m memFS) Open(name string) (fs.File, error) {
	b, ok := m[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &memFile{Reader: bytes.NewReader(b), name: name, size: int64(len(b))}, nil
}

// bundleOf is instance id's bundle (contract §17.4): the files project(t)
// names (compose, Hub override, custom override, env), the template's
// support files, the instance's data files and the CA bundle, with the
// primary's modes; the manifest names the model's volumes.
func (h *Hub) bundleOf(ctx context.Context, id string) (memFS, agentapi.BundleManifest, error) {
	h.mu.RLock()
	v := h.findLocked(id)
	var t templates.Template
	if v != nil {
		t = *v
	}
	h.mu.RUnlock()
	m := agentapi.BundleManifest{Instance: id, Files: map[string]agentapi.FileEntry{}}
	if v == nil {
		return nil, m, statusErr(409, "instance %s does not resolve", id)
	}
	m.Template = t.TemplateID
	files := memFS{}
	add := func(name, src string, must bool) error {
		fi, err := os.Lstat(src)
		if errors.Is(err, fs.ErrNotExist) && !must {
			return nil
		}
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s isn't a regular file", src)
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		files[name] = b
		m.Files[name] = agentapi.FileEntry{SHA256: hex.EncodeToString(sum[:]), Mode: uint32(fi.Mode().Perm()), Size: int64(len(b))}
		return nil
	}
	walk := func(prefix, root string) error {
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && p == root {
					return fs.SkipDir
				}
				return err
			}
			if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			return add(prefix+filepath.ToSlash(rel), p, true)
		})
	}
	steps := []func() error{
		func() error { return add(bundleCompose, t.ComposePath(), true) },
		func() error { return add(bundleOverride, h.overridePath(id), false) },
		func() error { return add(bundleUserOverride, h.userOverridePath(id), false) },
		func() error { return add(bundleEnv, h.envPath(id), false) },
		func() error {
			return walk("templates/"+templateDir(&t)+"/", filepath.Join(h.templatesRoot(), templateDir(&t)))
		},
		func() error { return walk(bundleAppfiles, filepath.Join(h.cfg.AppFilesDir, id)) },
		func() error {
			return add(bundleCerts, filepath.Join(h.cfg.ProjectDir, "certs", "ca-bundle.crt"), false)
		},
	}
	for _, s := range steps {
		if err := s(); err != nil {
			return nil, m, statusErr(500, "the bundle of %s: %v", id, err)
		}
	}
	model, err := h.loadRuntime(ctx, &t)
	if err != nil {
		return nil, m, statusErr(500, "%s: compose can't load the project for its bundle", id)
	}
	if len(model.Volumes) > 0 {
		m.Volumes = map[string]string{}
		for k, vol := range model.Volumes {
			m.Volumes[k] = vol.Name
		}
	}
	return files, m, nil
}

// pushBundle sends instance id's bundle to its worker (before every
// create: the agent validates it and runs only its resolved model).
func (h *Hub) pushBundle(ctx context.Context, id string, rt runtime.Instances) error {
	b, ok := unwrapRT(rt).(bundlePusher)
	if !ok {
		return statusErr(500, "%s: the worker's runtime takes no bundles", id)
	}
	files, m, err := h.bundleOf(ctx, id)
	if err != nil {
		return err
	}
	if err := b.PushBundle(ctx, id, files, m); err != nil {
		return err
	}
	return nil
}
