package hub

import (
	"context"
	"log"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/portcullis/hub/internal/doctor"
)

// The doctor's engine inputs (contract §14.5, rootless Podman): the
// guard's view of the engine and whether it labels with SELinux, plus the
// limits each instance's compose asks for (limits_not_enforced).

// engineSELinux reports whether the engine's SecurityOptions carry
// name=selinux, read once the guard has verified the engine and cached
// (the engine doesn't change under a running Hub). false while unknown.
// Never call it holding mu (an engine call).
func (h *Hub) engineSELinux(ctx context.Context) bool {
	on, _ := h.readEngineSELinux(ctx)
	return on
}

// readEngineSELinux is engineSELinux with the read's error (nil when
// cached, or nothing to read yet).
func (h *Hub) readEngineSELinux(ctx context.Context) (bool, error) {
	h.selinuxMu.Lock()
	known, on := h.selinuxKnown, h.selinuxOn
	h.selinuxMu.Unlock()
	if known || h.engine == nil || !h.engineVerifiedNow() || h.cfg.Guard == nil {
		return on, nil
	}
	opts, err := h.engine.SecurityOptions(ctx)
	if err != nil {
		log.Printf("engine: can't read the security options: %v", err)
		return false, err
	}
	on = securityOption(opts, "selinux")
	h.selinuxMu.Lock()
	h.selinuxKnown, h.selinuxOn = true, on
	h.selinuxMu.Unlock()
	return on, nil
}

// selinuxCached is engineSELinux's cached answer (false while unknown);
// safe under mu.
func (h *Hub) selinuxCached() bool {
	h.selinuxMu.Lock()
	defer h.selinuxMu.Unlock()
	return h.selinuxKnown && h.selinuxOn
}

// relabelBinds: the renderer re-declares the Hub's binds with
// bind.selinux z — only under podman on an SELinux engine (P10; Docker on
// SELinux is unchanged).
func (h *Hub) relabelBinds() bool { return h.rootlessOn() && h.selinuxCached() }

// doctorEngineIn is the doctor's engine input (nil without a guard: unit
// tests, P5). Never under mu.
func (h *Hub) doctorEngineIn(ctx context.Context) *doctor.EngineIn {
	g := h.cfg.Guard
	if g == nil {
		return nil
	}
	return &doctor.EngineIn{Runtime: string(h.cfg.Runtime), Mismatch: g.Info().Mismatch, SELinux: h.engineSELinux(ctx)}
}

// serviceLimits are the services of compose that set mem_limit and
// pids_limit (a non-zero value: what the running container must show).
func serviceLimits(compose []byte) map[string][2]bool {
	out := map[string][2]bool{}
	services, err := orderedServiceNodes(compose)
	if err != nil {
		return out
	}
	for name, s := range services {
		var w [2]bool
		for i, key := range []string{"mem_limit", "pids_limit"} {
			if n := mapField(s, key); n != nil && n.Kind == yaml.ScalarNode {
				v := strings.TrimSpace(n.Value)
				w[i] = v != "" && v != "0" && v != "-1" && n.Tag != "!!null"
			}
		}
		out[name] = w
	}
	return out
}

// orderedServiceNodes is compose's services by name (anchors and merge
// keys resolved).
func orderedServiceNodes(compose []byte) (map[string]*yaml.Node, error) {
	var doc struct {
		Services map[string]yaml.Node `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]*yaml.Node, len(doc.Services))
	for name, n := range doc.Services {
		var v map[string]any
		if err := n.Decode(&v); err != nil {
			continue
		}
		var re yaml.Node
		if err := re.Encode(v); err != nil {
			continue
		}
		out[name] = &re
	}
	return out, nil
}

// mapField is mapping n's value for key (nil when absent).
func mapField(n *yaml.Node, key string) *yaml.Node {
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

// ── SELinux relabels of the Hub's own binds (P10) ───────

// relabelBindEntry is one bind in long syntax with bind.selinux z (the
// shared label: every service of the instance may read it), as an
// override volumes entry.
func relabelBindEntry(source, target string, readOnly bool) string {
	return "type: bind\n" +
		"        source: " + yamlQuote(composeLiteral(source)) + "\n" +
		"        target: " + yamlQuote(composeLiteral(target)) + "\n" +
		"        read_only: " + strconv.FormatBool(readOnly) + "\n" +
		"        bind:\n" +
		"          selinux: z"
}

// templateBindPrefix: the template's own files (compose binds relative to
// core's checkout, the project directory).
const templateBindPrefix = "./templates/"

// docsBind: core's documentation tree (the docs template's ./docs bind):
// read-only, public, never secrets — labelled like the template's own
// files, since core's SELinux overlay covers only core's services.
const docsBind = "./docs"

// relabelSource: a bind source the Hub labels (P10, ruling I4): the
// template's own files and core's docs tree.
func relabelSource(src string) bool {
	return strings.HasPrefix(src, templateBindPrefix) || src == docsBind || strings.HasPrefix(src, docsBind+"/")
}

// selinuxRelabels are, per service of compose, its binds of the
// template's own files (literal sources under ./templates/) and of core's
// docs tree (./docs) re-declared
// with bind.selinux z (compose merges a service's volumes by target).
// Binds that already set a label (z / Z, bind.selinux) and anything else
// — shared folders, named volumes, other host paths — are left alone:
// user data is never relabelled.
func selinuxRelabels(compose []byte) map[string][]string {
	out := map[string][]string{}
	services, err := orderedServiceNodes(compose)
	if err != nil {
		return out
	}
	for name, s := range services {
		vols := mapField(s, "volumes")
		if vols == nil || vols.Kind != yaml.SequenceNode {
			continue
		}
		for _, v := range vols.Content {
			src, dst, ro, ok := templateBind(v)
			if !ok {
				continue
			}
			out[name] = append(out[name], relabelBindEntry(src, dst, ro))
		}
		sort.Strings(out[name])
	}
	for name := range out {
		if len(out[name]) == 0 {
			delete(out, name)
		}
	}
	return out
}

// templateBind reads one volumes entry: a bind of a literal source under
// ./templates/ with no label of its own.
func templateBind(v *yaml.Node) (src, dst string, ro, ok bool) {
	switch v.Kind {
	case yaml.ScalarNode:
		parts := strings.Split(v.Value, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return "", "", false, false
		}
		src, dst = parts[0], parts[1]
		if len(parts) == 3 {
			for _, o := range strings.Split(parts[2], ",") {
				switch o {
				case "ro":
					ro = true
				case "z", "Z":
					return "", "", false, false
				}
			}
		}
	case yaml.MappingNode:
		if t := mapField(v, "type"); t == nil || t.Value != "bind" {
			return "", "", false, false
		}
		// Only type / source / target / read_only are re-declared: a
		// bind with anything else (bind.*, consistency, volume.*) is left
		// as the template wrote it.
		for i := 0; i+1 < len(v.Content); i += 2 {
			switch v.Content[i].Value {
			case "type", "source", "target", "read_only":
			default:
				return "", "", false, false
			}
		}
		s, d := mapField(v, "source"), mapField(v, "target")
		if s == nil || d == nil {
			return "", "", false, false
		}
		src, dst = s.Value, d.Value
		if r := mapField(v, "read_only"); r != nil && (r.Value == "true" || r.Value == "True" || r.Value == "yes") {
			ro = true
		}
	default:
		return "", "", false, false
	}
	if !relabelSource(src) || strings.Contains(src, "$") || strings.Contains(dst, "$") ||
		strings.Contains(src, "..") || dst == "" {
		return "", "", false, false
	}
	return src, dst, ro, true
}
