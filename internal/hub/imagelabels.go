package hub

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/templates"
)

// Image labels (contract §3): Docker merges an image's LABELs into its
// containers' labels, so an image can carry traefik.* routing the Hub never
// checked (compose's labels win only for keys they set). After every
// compose up the Hub compares each container's traefik.* keys with the
// keys compose was given (the template's labels and the Hub's override);
// any other key takes the project down (volumes kept) and fails the
// operation. The check runs first on the containers `up --no-start`
// created — before anything starts or Traefik could route it — and again
// after the real up. Reconcile reports the same as drift.

// expectedTraefikKeysLocked: per compose service, the traefik.* label keys
// compose sets for t — the template's (default instance; a non-default
// instance's override replaces them) plus the Hub override's. Caller holds mu.
func (h *Hub) expectedTraefikKeysLocked(t *templates.Template) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	add := func(svc, k string) {
		if !strings.HasPrefix(templates.FoldKey(k), "traefik") {
			return
		}
		if out[svc] == nil {
			out[svc] = map[string]bool{}
		}
		out[svc][k] = true
	}
	if t.IsDefault() {
		base, err := templates.ServiceLabels(t.ReadCompose())
		if err != nil {
			return nil, err
		}
		for svc, l := range base {
			for k := range l {
				add(svc, k)
			}
		}
	}
	ov, err := overrideLabelKeys(h.overridePath(t.ID))
	if err != nil {
		return nil, err
	}
	for svc, keys := range ov {
		for _, k := range keys {
			add(svc, k)
		}
	}
	return out, nil
}

// overrideLabelKeys reads the label keys per service of the Hub's override
// file (a yaml.Node walk: it carries compose's !override tag). A missing
// file has none.
func overrideLabelKeys(path string) (map[string][]string, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	get := func(n *yaml.Node, key string) *yaml.Node {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
		return nil
	}
	out := map[string][]string{}
	if len(root.Content) == 0 {
		return out, nil
	}
	svcs := get(root.Content[0], "services")
	if svcs == nil || svcs.Kind != yaml.MappingNode {
		return out, nil
	}
	for i := 0; i+1 < len(svcs.Content); i += 2 {
		name, labels := svcs.Content[i].Value, get(svcs.Content[i+1], "labels")
		if labels == nil {
			continue
		}
		switch labels.Kind {
		case yaml.MappingNode:
			for j := 0; j < len(labels.Content); j += 2 {
				out[name] = append(out[name], labels.Content[j].Value)
			}
		case yaml.SequenceNode:
			for _, it := range labels.Content {
				k, _, _ := strings.Cut(it.Value, "=")
				out[name] = append(out[name], k)
			}
		}
	}
	return out, nil
}

// extraTraefikKeys: the container's traefik.* label keys (folded like
// Traefik's decoder) that compose wasn't given, sorted.
func extraTraefikKeys(want map[string]bool, have map[string]string) []string {
	var out []string
	for k := range have {
		if strings.HasPrefix(templates.FoldKey(k), "traefik") && !want[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// imageLabelProblem: why t's containers (created or running) can't be
// trusted with routing ("" = fine): a traefik.* label key compose wasn't
// given (an image LABEL). Docker unreachable is a problem too (fail
// closed).
func (h *Hub) imageLabelProblem(t *templates.Template) string {
	if h.engine == nil {
		return ""
	}
	h.mu.RLock()
	want, err := h.expectedTraefikKeysLocked(t)
	h.mu.RUnlock()
	if err != nil {
		return "the expected labels can't be computed: " + err.Error()
	}
	cs, err := h.engine.ListContainers(context.Background(), docker.ProjectFilter(projectName(t.ID)))
	if err != nil {
		return "the containers' labels can't be checked: " + err.Error()
	}
	for _, c := range cs {
		if extra := extraTraefikKeys(want[c.Service()], c.Labels); len(extra) > 0 {
			return fmt.Sprintf("container %s (service %s) carries Traefik labels compose wasn't given — from its image's LABELs: %s", c.Name(), c.Service(), strings.Join(extra, ", "))
		}
	}
	return ""
}

// refuseImageLabels takes the project down (volumes kept) and returns the
// 409 for problem.
func (h *Hub) refuseImageLabels(t *templates.Template, problem, when string) error {
	if derr := h.compose.Down(context.Background(), h.project(t)); derr != nil {
		problem += fmt.Sprintf(" (taking the project down failed too: %v)", derr)
	}
	return statusErr(409, "instance %s %s: %s. Use an image without traefik.* labels (or one the template's labels fully override)", t.ID, when, problem)
}

// checkImageLabels is the post-up check (defence in depth: composeUp
// already checked the created, not yet started, containers).
func (h *Hub) checkImageLabels(t *templates.Template) error {
	if p := h.imageLabelProblem(t); p != "" {
		return h.refuseImageLabels(t, p, "was stopped")
	}
	return nil
}
