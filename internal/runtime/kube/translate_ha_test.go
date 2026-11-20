package kube

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/portcullis/hub/internal/runtime"
)

// podSpecs are every pod spec of p (Deployments' and Jobs' templates).
func podSpecs(t *testing.T, p Plan) map[string]corev1.PodSpec {
	t.Helper()
	out := map[string]corev1.PodSpec{}
	for _, o := range p.Objects() {
		if o.GetKind() != "Deployment" && o.GetKind() != "Job" {
			continue
		}
		var w struct {
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := kruntime.DefaultUnstructuredConverter.FromUnstructured(o.Object, &w); err != nil {
			t.Fatal(err)
		}
		out[o.GetName()] = w.Spec.Template.Spec
	}
	if len(out) == 0 {
		t.Fatal("no pod in the plan")
	}
	return out
}

func translateOK(t *testing.T, in Input) Plan {
	t.Helper()
	p, err := Translate(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTranslateNoCPULimit: every container, the init ones too, requests
// 50m CPU and none has a CPU limit (compose cpus isn't carried).
func TestTranslateNoCPULimit(t *testing.T) {
	in := inputOf(t, `services:
  web:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
    cpus: 2
    cpu_shares: 512
    volumes: [data:/var/lib/web]
volumes:
  data: {}
`, "cpu")
	for name, spec := range podSpecs(t, translateOK(t, in)) {
		if len(spec.InitContainers) == 0 {
			t.Fatalf("%s: want the seed init container in this case", name)
		}
		for _, c := range slices.Concat(spec.InitContainers, spec.Containers) {
			if got := c.Resources.Requests.Cpu().String(); got != "50m" {
				t.Errorf("%s/%s: cpu request %s, want 50m", name, c.Name, got)
			}
			if _, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
				t.Errorf("%s/%s: has a CPU limit", name, c.Name)
			}
		}
	}
}

// TestTranslateDefaultMemory: no mem_limit → 512Mi request = limit;
// mem_limit (or deploy's) → request = limit = it; NoMemoryLimit names
// exactly the services without one.
func TestTranslateDefaultMemory(t *testing.T) {
	in := inputOf(t, `services:
  a:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
  b:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
    mem_limit: 256m
`, "mem")
	want := map[string]string{"mem--a": "512Mi", "mem--b": "256Mi"}
	for name, spec := range podSpecs(t, translateOK(t, in)) {
		c := spec.Containers[0]
		if r, l := c.Resources.Requests.Memory().String(), c.Resources.Limits.Memory().String(); r != want[name] || l != want[name] {
			t.Errorf("%s: memory request %s limit %s, want %s both", name, r, l, want[name])
		}
	}
	if got := NoMemoryLimit(in.Model); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("NoMemoryLimit = %v, want [a]", got)
	}
	if NoMemoryLimit(nil) != nil {
		t.Error("NoMemoryLimit(nil) isn't nil")
	}
}

const placementCompose = `services:
  web:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
`

func placementOf(t *testing.T, a *runtime.Availability, ha bool) corev1.PodSpec {
	t.Helper()
	in := inputOf(t, placementCompose, "pl")
	in.Availability, in.Settings.HA = a, ha
	return podSpecs(t, translateOK(t, in))["pl--web"]
}

func notSmallTerm(extra ...corev1.NodeSelectorRequirement) corev1.NodeSelectorTerm {
	return corev1.NodeSelectorTerm{MatchExpressions: append(extra, corev1.NodeSelectorRequirement{Key: "portcullis.io/class", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"small"}})}
}

// TestTranslatePlacement: each priority and Runs on choice renders the
// §20.6 terms, and only an only choice naming a small node tolerates the
// small taint.
func TestTranslatePlacement(t *testing.T) {
	smallTol := corev1.Toleration{Key: "portcullis.io/small", Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule}
	host := func(n ...string) corev1.NodeSelectorRequirement {
		return corev1.NodeSelectorRequirement{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: n}
	}
	for _, c := range []struct {
		name      string
		a         *runtime.Availability
		class     string
		required  []corev1.NodeSelectorTerm
		preferred []corev1.PreferredSchedulingTerm
		tol       []corev1.Toleration
	}{
		{"default", nil, "portcullis-normal", []corev1.NodeSelectorTerm{notSmallTerm()}, nil, nil},
		{"low anywhere", &runtime.Availability{Priority: "low", RunsOn: runtime.RunsOn{Mode: "anywhere"}}, "portcullis-low", []corev1.NodeSelectorTerm{notSmallTerm()}, nil, nil},
		{"critical", &runtime.Availability{Priority: "critical"}, "portcullis-critical", []corev1.NodeSelectorTerm{notSmallTerm()}, nil, nil},
		{"prefer class", &runtime.Availability{Priority: "high", RunsOn: runtime.RunsOn{Mode: "prefer", Class: "home"}}, "portcullis-high", []corev1.NodeSelectorTerm{notSmallTerm()},
			[]corev1.PreferredSchedulingTerm{{Weight: 100, Preference: corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "portcullis.io/class", Operator: corev1.NodeSelectorOpIn, Values: []string{"home"}}}}}}, nil},
		{"prefer site", &runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Site: "office"}}, "portcullis-normal", []corev1.NodeSelectorTerm{notSmallTerm()},
			[]corev1.PreferredSchedulingTerm{{Weight: 100, Preference: corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "portcullis.io/site", Operator: corev1.NodeSelectorOpIn, Values: []string{"office"}}}}}}, nil},
		{"prefer nodes", &runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Nodes: []string{"vm2", "vm1"}}}, "portcullis-normal", []corev1.NodeSelectorTerm{notSmallTerm()},
			[]corev1.PreferredSchedulingTerm{{Weight: 100, Preference: corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{host("vm1", "vm2")}}}}, nil},
		{"only big", &runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only", Nodes: []string{"vm2", "vm1"}}}, "portcullis-normal", []corev1.NodeSelectorTerm{notSmallTerm(host("vm1", "vm2"))}, nil, nil},
		{"only small", &runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only", Nodes: []string{"vm3"}, Small: []string{"vm3"}}}, "portcullis-normal",
			[]corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{host("vm3"), {Key: "portcullis.io/class", Operator: corev1.NodeSelectorOpIn, Values: []string{"small"}}}}}, nil, []corev1.Toleration{smallTol}},
		{"only mixed", &runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only", Nodes: []string{"vm3", "vm1"}, Small: []string{"vm3"}}}, "portcullis-normal",
			[]corev1.NodeSelectorTerm{notSmallTerm(host("vm1")), {MatchExpressions: []corev1.NodeSelectorRequirement{host("vm3"), {Key: "portcullis.io/class", Operator: corev1.NodeSelectorOpIn, Values: []string{"small"}}}}}, nil, []corev1.Toleration{smallTol}},
	} {
		t.Run(c.name, func(t *testing.T) {
			spec := placementOf(t, c.a, false)
			if spec.PriorityClassName != c.class {
				t.Errorf("class %q, want %q", spec.PriorityClassName, c.class)
			}
			na := spec.Affinity.NodeAffinity
			if !reflect.DeepEqual(na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms, c.required) {
				t.Errorf("required %+v, want %+v", na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms, c.required)
			}
			if !reflect.DeepEqual(na.PreferredDuringSchedulingIgnoredDuringExecution, c.preferred) {
				t.Errorf("preferred %+v, want %+v", na.PreferredDuringSchedulingIgnoredDuringExecution, c.preferred)
			}
			if !reflect.DeepEqual(spec.Tolerations, c.tol) {
				t.Errorf("tolerations %+v, want %+v", spec.Tolerations, c.tol)
			}
		})
	}
}

// TestTranslateHATolerations: in HA mode every app pod (Jobs too)
// tolerates not-ready and unreachable for 30 s; without it none.
func TestTranslateHATolerations(t *testing.T) {
	in := inputOf(t, `services:
  web:
    image: docker.io/library/nginx:1.29
    user: "1000:1000"
  init:
    image: docker.io/library/alpine:3.24
    user: "1000:1000"
    restart: "no"
`, "hat")
	for _, ha := range []bool{false, true} {
		in.Settings.HA = ha
		specs := podSpecs(t, translateOK(t, in))
		if len(specs) != 2 {
			t.Fatalf("%d pods", len(specs))
		}
		for name, spec := range specs {
			if !ha {
				if len(spec.Tolerations) != 0 {
					t.Errorf("%s: tolerations without HA: %+v", name, spec.Tolerations)
				}
				continue
			}
			if len(spec.Tolerations) != 2 {
				t.Fatalf("%s: tolerations %+v", name, spec.Tolerations)
			}
			for i, k := range []string{"node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"} {
				tol := spec.Tolerations[i]
				if tol.Key != k || tol.Operator != corev1.TolerationOpExists || tol.Effect != corev1.TaintEffectNoExecute || tol.TolerationSeconds == nil || *tol.TolerationSeconds != 30 || tol.Value != "" {
					t.Errorf("%s: toleration %d = %+v", name, i, tol)
				}
			}
		}
	}
}

// TestTranslateAvailabilityRefused: what §20.6 refuses (the API first)
// the translator refuses too, without echoing a value; portcullis-core
// is never an app's (ruling I5).
func TestTranslateAvailabilityRefused(t *testing.T) {
	long := strings.Repeat("n", 64)
	many := make([]string, 17)
	for i := range many {
		many[i] = "n" + strings.Repeat("x", i)
	}
	for _, c := range []struct {
		a    runtime.Availability
		want string
	}{
		{runtime.Availability{Priority: "core"}, "priority must be critical, high, normal or low"},
		{runtime.Availability{Priority: "urgent"}, "priority must be critical, high, normal or low"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "somewhere"}}, "runs_on mode must be anywhere, prefer or only"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Class: "home"}}, "runs_on anywhere takes no class, site or nodes"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "anywhere", Nodes: []string{"vm1"}}}, "runs_on anywhere takes no class, site or nodes"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer"}}, "runs_on prefer takes exactly one of class, site or nodes"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Class: "home", Site: "x"}}, "runs_on prefer takes exactly one of class, site or nodes"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Class: "small"}}, "small nodes take only instances pinned to them: use Only"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Nodes: []string{"vm3"}, Small: []string{"vm3"}}}, "small nodes take only instances pinned to them: use Only"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Class: "mars"}}, "runs_on prefer: class must be home or cloud"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Site: "a b"}}, "runs_on prefer names a site that isn't a site name"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Nodes: []string{long}}}, "runs_on names a node that isn't a node name"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Nodes: []string{"vm1", "vm1"}}}, "runs_on names a node twice"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "prefer", Nodes: many}}, "runs_on names 17 nodes (1–16)"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only"}}, "runs_on only takes nodes, and no class or site"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only", Nodes: []string{"vm1"}, Site: "x"}}, "runs_on only takes nodes, and no class or site"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only", Nodes: []string{"Bad_Node"}}}, "runs_on names a node that isn't a node name"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only", Nodes: []string{"vm1", "vm1"}}}, "runs_on names a node twice"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only", Nodes: many}}, "runs_on names 17 nodes (1–16)"},
		{runtime.Availability{RunsOn: runtime.RunsOn{Mode: "only", Nodes: []string{"vm1"}, Small: []string{"vm3"}}}, "runs_on only: a small node isn't one of the chosen nodes"},
	} {
		in := inputOf(t, placementCompose, "pl")
		in.Availability = &c.a
		_, err := Translate(in)
		var r *ErrRefused
		if !errors.As(err, &r) || r.Reason != c.want {
			t.Errorf("%+v: got %v, want refused %q", c.a, err, c.want)
		}
		if err != nil && (strings.Contains(err.Error(), long) || strings.Contains(err.Error(), "Bad_Node") || strings.Contains(err.Error(), "mars")) {
			t.Errorf("%+v: the refusal echoes a value: %v", c.a, err)
		}
	}
}

// TestPolicyPeersFollowHA: the routed ports admit Traefik from its own
// namespace (in HA portcullis-ingress by app.kubernetes.io/name, or the
// configured peer), the companion ports mcp-gate and the gateway wg
// from the core namespace, in both modes.
func TestPolicyPeersFollowHA(t *testing.T) {
	core := Peer{"portcullis", "portcullis.io/component", "traefik"}
	ha := Peer{"portcullis-ingress", "app.kubernetes.io/name", "traefik"}
	for _, c := range []struct {
		name    string
		ha      bool
		set     Peer
		coreNS  string
		traefik Peer
	}{
		{"non-HA", false, Peer{}, "", core},
		{"HA", true, Peer{}, "", ha},
		{"HA, own core namespace", true, Peer{}, "pc", ha},
		{"non-HA, own core namespace", false, Peer{}, "pc", Peer{"pc", "portcullis.io/component", "traefik"}},
		{"configured", true, Peer{"edge-in", "app", "tr"}, "", Peer{"edge-in", "app", "tr"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			slot := 2
			pols, err := InstancePolicies(PolicyInput{Instance: "app", Namespace: "portcullis-apps", CoreNamespace: c.coreNS,
				RoutedPorts: map[string][]int{"web": {80}}, CompanionPorts: map[string][]int{"mcp": {9000}}, VPNService: "gw", VPNSlot: &slot,
				Settings: Settings{HA: c.ha, TraefikPeer: c.set, NodeAddresses: []string{"192.0.2.10"}}})
			if err != nil {
				t.Fatal(err)
			}
			coreNS := c.coreNS
			if coreNS == "" {
				coreNS = "portcullis"
			}
			want := map[string]Peer{"app--routed-web": c.traefik, "app--companion-mcp": {coreNS, "portcullis.io/component", "mcp-gate"}, "app--vpn-edge": {coreNS, "portcullis.io/component", "wg"}}
			seen := 0
			for _, u := range pols {
				var np networkingv1.NetworkPolicy
				if err := kruntime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &np); err != nil {
					t.Fatal(err)
				}
				w, ok := want[np.Name]
				if !ok {
					continue
				}
				seen++
				var peer networkingv1.NetworkPolicyPeer
				if len(np.Spec.Ingress) == 1 {
					peer = np.Spec.Ingress[0].From[0]
				} else {
					peer = np.Spec.Egress[0].To[0]
				}
				got := Peer{peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"], "", ""}
				if len(peer.NamespaceSelector.MatchLabels) != 1 || len(peer.PodSelector.MatchLabels) != 1 {
					t.Fatalf("%s: peer %+v", np.Name, peer)
				}
				for k, v := range peer.PodSelector.MatchLabels {
					got.Key, got.Value = k, v
				}
				if got != w {
					t.Errorf("%s: peer %s, want %s", np.Name, got, w)
				}
			}
			if seen != 3 {
				t.Errorf("%d of the 3 peered policies", seen)
			}
		})
	}
}

// --- X5: the regenerated goldens differ from the pre-HA ones by the HA
// fields only.

// haDefaultAffinity is the default Runs on (anywhere) as JSON.
var haDefaultAffinity = map[string]any{"nodeAffinity": map[string]any{"requiredDuringSchedulingIgnoredDuringExecution": map[string]any{
	"nodeSelectorTerms": []any{map[string]any{"matchExpressions": []any{map[string]any{"key": "portcullis.io/class", "operator": "NotIn", "values": []any{"small"}}}}}}}}

// haTolerations are the HA mode's (as JSON).
var haTolerations = []any{
	map[string]any{"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": float64(30)},
	map[string]any{"key": "node.kubernetes.io/unreachable", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": float64(30)},
}

// goldenDocs splits a golden into its documents, each its step header
// and its object as JSON (a refused golden is one document, its text).
func goldenDocs(t *testing.T, b []byte) (heads []string, objs []map[string]any) {
	t.Helper()
	if bytes.HasPrefix(b, []byte("refused: ")) {
		return []string{string(b)}, []map[string]any{nil}
	}
	for _, d := range strings.Split(string(b), "---\n")[1:] {
		head, body, _ := strings.Cut(d, "\n")
		var o map[string]any
		if err := yaml.Unmarshal([]byte(body), &o); err != nil {
			t.Fatal(err)
		}
		heads, objs = append(heads, head), append(objs, o)
	}
	return heads, objs
}

// stripHA removes from new (a translated object) exactly the HA fields
// old (its pre-HA golden) lacks, and nothing else, recording what it
// removed; ha also allows the HA tolerations and the Traefik peer.
func stripHA(t *testing.T, new, old map[string]any, ha bool) (removed []string) {
	t.Helper()
	kind, _ := new["kind"].(string)
	if kind == "Deployment" || kind == "Job" {
		spec := dig(new, "spec", "template", "spec")
		oldSpec := dig(old, "spec", "template", "spec")
		if spec == nil {
			t.Fatalf("%s without a pod spec", kind)
		}
		if spec["priorityClassName"] == "portcullis-normal" && oldSpec["priorityClassName"] == nil {
			delete(spec, "priorityClassName")
			removed = append(removed, "priorityClassName")
		}
		if reflect.DeepEqual(spec["affinity"], haDefaultAffinity) && oldSpec["affinity"] == nil {
			delete(spec, "affinity")
			removed = append(removed, "affinity class NotIn [small]")
		}
		if ha && reflect.DeepEqual(spec["tolerations"], haTolerations) && oldSpec["tolerations"] == nil {
			delete(spec, "tolerations")
			removed = append(removed, "HA tolerations")
		}
		for _, key := range []string{"initContainers", "containers"} {
			cs, _ := spec[key].([]any)
			ocs, _ := oldSpec[key].([]any)
			for i, c := range cs {
				res, _ := c.(map[string]any)["resources"].(map[string]any)
				var ores map[string]any
				if i < len(ocs) {
					ores, _ = ocs[i].(map[string]any)["resources"].(map[string]any)
				}
				req, _ := res["requests"].(map[string]any)
				oreq, _ := ores["requests"].(map[string]any)
				if req["cpu"] != "50m" || res["limits"] != nil && res["limits"].(map[string]any)["cpu"] != nil {
					t.Errorf("%s %v: container %s: requests.cpu %v, want 50m and no CPU limit", kind, dig(new, "metadata")["name"], c.(map[string]any)["name"], req["cpu"])
				}
				if req["cpu"] == "50m" && oreq["cpu"] == nil {
					delete(req, "cpu")
					removed = append(removed, "requests.cpu")
				}
				// The 512Mi default, only where the old had no memory.
				lim, _ := res["limits"].(map[string]any)
				olim, _ := ores["limits"].(map[string]any)
				if key == "containers" && req["memory"] == DefaultMemory && lim["memory"] == DefaultMemory && oreq["memory"] == nil && olim["memory"] == nil {
					delete(req, "memory")
					delete(lim, "memory")
					removed = append(removed, "default memory")
				}
				for _, k := range []string{"requests", "limits"} {
					if m, ok := res[k].(map[string]any); ok && len(m) == 0 {
						delete(res, k)
					}
				}
				if res != nil && ores == nil {
					// the init containers had no resources key at all
					if len(res) == 0 {
						delete(c.(map[string]any), "resources")
					}
				}
			}
		}
	}
	if ha && kind == "NetworkPolicy" {
		for _, r := range asSlice(dig(new, "spec")["ingress"]) {
			for _, p := range asSlice(r.(map[string]any)["from"]) {
				pm := p.(map[string]any)
				if reflect.DeepEqual(pm["namespaceSelector"], map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": "portcullis-ingress"}}) &&
					reflect.DeepEqual(pm["podSelector"], map[string]any{"matchLabels": map[string]any{"app.kubernetes.io/name": "traefik"}}) {
					pm["namespaceSelector"] = map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": "portcullis"}}
					pm["podSelector"] = map[string]any{"matchLabels": map[string]any{"portcullis.io/component": "traefik"}}
					removed = append(removed, "Traefik peer")
				}
			}
		}
	}
	return removed
}

func dig(o map[string]any, path ...string) map[string]any {
	for _, p := range path {
		o, _ = o[p].(map[string]any)
	}
	return o
}

func asSlice(v any) []any { s, _ := v.([]any); return s }

// TestGoldenDiffOnlyHAFields (pre-flight X5): every golden of
// testdata/translate-pre-ha/ (the goldens before Task 13) equals its
// regenerated want.yaml once the HA fields are taken out — the class
// portcullis-normal, the default class NotIn [small] term, requests.cpu
// 50m and the 512Mi default where the old had no memory — so a
// regeneration can't hide another change. The same cases translated in
// HA mode may differ by those plus the HA tolerations and the Traefik
// peer (portcullis-ingress, app.kubernetes.io/name=traefik) only.
func TestGoldenDiffOnlyHAFields(t *testing.T) {
	// Every golden but the HA ones (new with Task 13) needs its pre-HA
	// copy: a later golden without one isn't silently skipped.
	cases, _ := filepath.Glob("testdata/translate/*")
	checked := 0
	for _, dir := range cases {
		c := filepath.Base(dir)
		if strings.HasPrefix(c, "ha-") {
			continue
		}
		ob, err := os.ReadFile(filepath.Join("testdata/translate-pre-ha", c+".yaml"))
		if err != nil {
			t.Errorf("%s: no pre-HA copy in testdata/translate-pre-ha/ (%v)", c, err)
			continue
		}
		checked++
		for _, ha := range []bool{false, true} {
			var nb []byte
			if !ha {
				if nb, err = os.ReadFile(filepath.Join(dir, "want.yaml")); err != nil {
					t.Fatal(err)
				}
			} else {
				in := baseInput(t, dir, c)
				in.Settings.HA = true
				p, err := Translate(in)
				if err != nil {
					nb = []byte("refused: " + err.Error() + "\n")
				} else if nb, err = PlanYAML(p); err != nil {
					t.Fatal(err)
				}
			}
			oh, oo := goldenDocs(t, ob)
			nh, no := goldenDocs(t, nb)
			if !slices.Equal(oh, nh) {
				t.Errorf("%s (ha %v): the documents changed: %q → %q", c, ha, oh, nh)
				continue
			}
			pods := 0
			for i := range oo {
				if oo[i] == nil {
					continue
				}
				removed := stripHA(t, no[i], oo[i], ha)
				if k := no[i]["kind"]; k == "Deployment" || k == "Job" {
					pods++
					if !slices.Contains(removed, "priorityClassName") || !slices.Contains(removed, "affinity class NotIn [small]") || !slices.Contains(removed, "requests.cpu") {
						t.Errorf("%s (ha %v) %s: an HA field is missing (removed %v)", c, ha, oh[i], removed)
					}
					if ha != slices.Contains(removed, "HA tolerations") {
						t.Errorf("%s (ha %v) %s: HA tolerations removed: %v", c, ha, oh[i], removed)
					}
				}
				a, _ := json.MarshalIndent(oo[i], "", " ")
				b, _ := json.MarshalIndent(no[i], "", " ")
				if !bytes.Equal(a, b) {
					t.Errorf("%s (ha %v) %s: differs beyond the HA fields:\nold %s\nnew (HA fields out) %s", c, ha, oh[i], a, b)
				}
			}
			if c != "refused-host" && pods == 0 {
				t.Errorf("%s: no pod compared", c)
			}
		}
	}
	if checked < 8 {
		t.Fatalf("%d goldens checked", checked)
	}
}

// TestHelperAndProbePodsLow (HA Task 13 ruling 3): every helper (volume,
// fixer) and NetworkPolicy probe pod runs at portcullis-low
// (preemptionPolicy Never): never portcullis-core (I5), never unset.
func TestHelperAndProbePodsLow(t *testing.T) {
	b := &Backend{cfg: Config{Namespace: "portcullis-apps", HubImage: hubImage}}
	pods := map[string]*corev1.Pod{
		"volume": b.helperPod(HelperVolume, "app", "app--data", true, nil),
		"fixer":  b.helperPod(HelperFixer, "", "", false, &runtime.FixerSpec{Image: hubImage, User: "0:0", Binds: []runtime.BindMount{{Source: "/srv/x", Target: "/root"}}}),
	}
	for _, role := range []string{"deny", "allow", "client"} {
		pods["probe-"+role] = probePod("portcullis-apps", hubImage, role, role != "client")
	}
	for name, p := range pods {
		if p.Spec.PriorityClassName != "portcullis-low" {
			t.Errorf("%s: priorityClassName %q, want portcullis-low", name, p.Spec.PriorityClassName)
		}
	}
}

func TestPeerString(t *testing.T) {
	if s := DefaultTraefikPeer(true, "x").String(); s != "portcullis-ingress:app.kubernetes.io/name=traefik" {
		t.Error(s)
	}
	if s := DefaultTraefikPeer(false, "").String(); s != "portcullis:portcullis.io/component=traefik" {
		t.Error(s)
	}
}
