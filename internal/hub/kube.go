package hub

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/templates"
)

// Kubernetes (contract §3.4): the kube backend can't read the Hub's
// disk, so an up's project carries the compose model and what binds
// would have brought in (template files, data files, per-person
// secrets) plus the facts the translation needs.

// kubeOn: the runtime is Kubernetes.
func (h *Hub) kubeOn() bool { return h.cfg.Runtime == runtime.KindKubernetes }

// maxTemplateFiles bounds what upProject reads of a template's support
// files (the ConfigMap's 1 MiB limit refuses more anyway).
const maxTemplateFiles = 2 << 20

// upProject is t's project for Create and Up: under Kubernetes with the
// interpolated model (the instance's profiles) and its inputs; elsewhere
// runtimeProject.
func (h *Hub) upProject(ctx context.Context, t *templates.Template) (runtime.Project, error) {
	p := h.runtimeProject(t)
	if !h.kubeOn() {
		return p, nil
	}
	m, err := h.loadRuntime(ctx, t)
	if err != nil {
		return p, statusErr(500, "%s: loading the project for Kubernetes: %v", t.ID, err)
	}
	p.Model = m
	in, err := h.kubeInputs(t)
	if err != nil {
		return p, err
	}
	p.Inputs = in
	return p, nil
}

// kubeInputs reads t's inputs from the Hub's disk and state.
func (h *Hub) kubeInputs(t *templates.Template) (*runtime.ProjectInputs, error) {
	in := &runtime.ProjectInputs{Template: templateDir(t), TemplateFiles: map[string][]byte{}, AppFiles: map[string]runtime.AppFileInput{},
		PersonSecrets: map[string]map[string][]byte{}, LanOnly: map[int]bool{}, Jobs: map[string]bool{}}
	// Template support files (<core>/templates/<template>/).
	root := filepath.Join(h.templatesRoot(), templateDir(t))
	total := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == root {
				return fs.SkipDir
			}
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if total += len(b); total > maxTemplateFiles {
			return fmt.Errorf("template files for %s exceed 1 MiB", templateDir(t))
		}
		rel, _ := filepath.Rel(root, p)
		in.TemplateFiles[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return nil, statusErr(409, "%s: %v", t.ID, err)
	}
	// Data files: keyed by the bind source the override renders.
	delivered := h.loadDelivered(t.ID).Hashes
	for _, f := range sortedFiles(t) {
		if f.Service == "" || f.Mount == "" {
			continue
		}
		af := runtime.AppFileInput{Name: f.Name, FileName: f.FileName(), Rev: delivered[fileUnit(f.Name)]}
		af.Data, _ = os.ReadFile(h.dataFilePathOf(t.ID, &f))
		if b, err := os.ReadFile(h.secretsFilePath(t.ID, f.Name)); err == nil {
			af.Secrets = b
		}
		in.AppFiles[path.Join(filepath.ToSlash(h.cfg.AppFilesHostDir), t.ID, f.Name)] = af
	}
	// Per-person secrets: each person_secret option's hash files.
	for _, o := range personSecretOptions(t) {
		files, err := h.personSecretFiles(t.ID, o.Key)
		if err != nil {
			return nil, statusErr(503, "%s was not started: %v", t.ID, err)
		}
		in.PersonSecrets[o.Key] = files
	}
	// lan_only ports at the instance's host ports.
	h.mu.RLock()
	s := h.st.Settings[t.ID]
	h.mu.RUnlock()
	for _, p := range t.Manifest.Ports {
		if !p.LanOnly {
			continue
		}
		port := p.Default
		if v, err := strconv.Atoi(strings.TrimSpace(s.Ports[p.Key])); err == nil {
			port = v
		}
		in.LanOnly[port] = true
	}
	for _, n := range h.LocalNetworks() {
		in.LocalNetworks = append(in.LocalNetworks, n.String())
	}
	maps.Copy(in.Jobs, t.Jobs)
	// A wired VPN provider: its slot and ingress service.
	h.mu.RLock()
	if p, wired := h.st.VPN.Providers[t.ID]; wired && t.Manifest.VPN != nil {
		slot := p.Slot
		in.VPNSlot, in.IngressService = &slot, t.Manifest.VPN.Ingress.Service
	}
	h.mu.RUnlock()
	return in, nil
}

// personSecretFiles are instance id's <user>.nt files of option key
// (none yet: empty).
func (h *Hub) personSecretFiles(id, key string) (map[string][]byte, error) {
	out := map[string][]byte{}
	if err := h.secretsBaseErr(); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(h.cfg.SecretsDir)
	if err != nil {
		return nil, fmt.Errorf("the secrets volume can't be opened: %v", err)
	}
	defer r.Close()
	dir, err := secretDirRel(id, key)
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(r.FS(), dir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the secrets of %s/%s can't be listed: %v", id, key, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".nt") || !e.Type().IsRegular() {
			continue
		}
		b, err := r.ReadFile(dir + "/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("a hash file of %s/%s can't be read: %v", id, key, err)
		}
		out[e.Name()] = b
	}
	return out, nil
}

// kubeDeliverer is the kube backend's delivery into a running instance
// (§13.7 "On Kubernetes"): the object updated with .rev, then the mounted
// copy waited for; nil only once it matches.
type kubeDeliverer interface {
	DeliverFile(ctx context.Context, instance string, f runtime.FileDelivery) error
	DeliverPersonSecret(ctx context.Context, instance string, s runtime.SecretDelivery) error
}

// kubeDeliverPersonSecret delivers option o's hash files of instance id
// as its *-pw Secret into the running instance (revision digest).
func (h *Hub) kubeDeliverPersonSecret(ctx context.Context, id string, o *templates.Option, digest string) error {
	if !h.kubeOn() || h.rt == nil {
		return nil
	}
	d, ok := h.rt.(kubeDeliverer)
	if !ok {
		return errors.New("the runtime can't deliver files")
	}
	files, err := h.personSecretFiles(id, o.Key)
	if err != nil {
		return err
	}
	svc, mount := "", ""
	if o.Mount != nil {
		svc, mount = o.Mount.Service, o.Mount.Path
	}
	return d.DeliverPersonSecret(ctx, id, runtime.SecretDelivery{Key: o.Key, Files: files, Service: svc, Mount: mount, Rev: digest})
}

// kubeDeliver delivers f into instance id when the runtime needs it
// (Kubernetes); elsewhere the bind mount already has it (nil).
func (h *Hub) kubeDeliver(ctx context.Context, id string, f runtime.FileDelivery) error {
	if !h.kubeOn() || h.rt == nil {
		return nil
	}
	d, ok := h.rt.(kubeDeliverer)
	if !ok {
		return errors.New("the runtime can't deliver files")
	}
	return d.DeliverFile(ctx, id, f)
}
