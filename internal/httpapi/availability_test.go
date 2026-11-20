package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/hub"
	sdk "github.com/portcullis/hub/internal/mcpsdk"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/runtimetest"
	"github.com/portcullis/hub/internal/state"
)

// availNodeadm is nodeadm for the availability tests: a fixed snapshot.
type availNodeadm struct {
	clusterNodeadm
	mu   sync.Mutex
	snap nodeadm.Snapshot
	err  error
}

func (f *availNodeadm) Cluster(context.Context) (nodeadm.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snap, f.err
}

func availNode(name, class string) nodeadm.Node {
	n := nodeadm.Node{Name: name, Role: "server", Ready: true, Labels: map[string]string{nodeadm.LabelClass: class, nodeadm.LabelSite: "main"},
		Allocatable: nodeadm.Resources{CPUm: 1000, MemBytes: 1 << 30}}
	if class == "small" {
		n.Taints = []nodeadm.Taint{{Key: "portcullis.io/small", Value: "true", Effect: "NoSchedule"}}
	}
	return n
}

// fullSnapshot: n1 runs grafana's pod (normal), n2 is full of a core
// pod. Raising grafana to critical makes n1 red (a critical singleton
// with no room); at normal it is green.
func fullSnapshot() nodeadm.Snapshot {
	notSmall := [][]nodeadm.Expr{{{Key: "portcullis.io/class", Operator: "NotIn", Values: []string{"small"}}}}
	return nodeadm.Snapshot{V: 1, Nodes: []nodeadm.Node{availNode("n1", "home"), availNode("n2", "home"), availNode("pi", "small")},
		Pods: []nodeadm.Pod{
			{Name: "grafana--grafana-7c9d-x1", Namespace: "portcullis-apps", Node: "n1", Priority: 1000, PriorityClass: "portcullis-normal",
				PreemptionPolicy: "PreemptLowerPriority", Requests: nodeadm.Resources{CPUm: 500, MemBytes: 512 << 20}, RequiredAffinity: notSmall},
			{Name: "vault-0", Namespace: "portcullis", Node: "n2", Priority: 1000000, PriorityClass: "portcullis-core",
				PreemptionPolicy: "PreemptLowerPriority", Requests: nodeadm.Resources{CPUm: 1000, MemBytes: 1 << 30}},
		}}
}

type availEnv struct {
	*instEnv
	na   *availNodeadm
	rt   *runtimetest.Fake
	root string
}

func newAvailEnv(t *testing.T, kubeOn bool, seed func(*state.AppState)) *availEnv {
	t.Helper()
	o := instEnvOpts{seed: func(st *state.AppState) {
		st.Instances["grafana"] = state.Instance{ID: "grafana", Template: "grafana", State: state.InstanceCreated}
		if seed != nil {
			seed(st)
		}
	}}
	if kubeOn {
		o.cfg = func(c *hub.Config) {
			c.Runtime = runtime.KindKubernetes
			os.MkdirAll(c.ProjectDir, 0o755)
			os.WriteFile(filepath.Join(c.ProjectDir, ".env"), []byte("PORTCULLIS_KUBE_CONTEXT=default\n"), 0o644)
		}
		o.rt = &runtimetest.Fake{K: runtime.KindKubernetes, InfoVal: runtime.Info{Verified: true}}
	}
	fake, _ := o.rt.(*runtimetest.Fake)
	root := t.TempDir()
	e := newInstEnvOpts(t, root, o)
	na := &availNodeadm{snap: fullSnapshot()}
	e.s.Hub.SetNodeadm(na)
	return &availEnv{instEnv: e, na: na, rt: fake, root: root}
}

func (e *availEnv) stored(t *testing.T) *state.Availability {
	t.Helper()
	st, err := state.Load(filepath.Join(e.root, "data", "state.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return st.Instances["grafana"].Availability
}

const availPath = "/api/instances/grafana/availability"

// TestAvailabilityDefaults: an instance without a stored availability
// reads normal / anywhere, with the cluster's nodes and N−1 per node.
func TestAvailabilityDefaults(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	code, body := e.do(t, "root", "GET", availPath, "")
	if code != 200 {
		t.Fatalf("GET: %d %s", code, body)
	}
	var v struct {
		Priority string          `json:"priority"`
		RunsOn   json.RawMessage `json:"runs_on"`
		Nodes    []struct {
			Name, Class, Site string
			Small             bool
		} `json:"nodes"`
		NMinus1 []struct{ Node, Level string } `json:"n_minus_1"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	if v.Priority != "normal" || string(v.RunsOn) != `{"mode":"anywhere"}` {
		t.Errorf("defaults: %s", body)
	}
	if len(v.Nodes) != 3 || v.Nodes[2].Name != "pi" || !v.Nodes[2].Small || v.Nodes[0].Small || v.Nodes[0].Class != "home" || v.Nodes[0].Site != "main" {
		t.Errorf("nodes: %+v", v.Nodes)
	}
	if len(v.NMinus1) != 3 || v.NMinus1[0].Level != "green" {
		t.Errorf("n_minus_1: %+v", v.NMinus1)
	}
	// nil maps to the translator's nil (the defaults).
	if a := e.stored(t); a != nil {
		t.Errorf("stored %+v", a)
	}
	// A dirty snapshot: every node unknown, never green.
	e.na.mu.Lock()
	e.na.snap.Pods = append(e.na.snap.Pods, e.na.snap.Pods[0])
	e.na.mu.Unlock()
	_, body = e.do(t, "root", "GET", availPath, "")
	json.Unmarshal([]byte(body), &v)
	for _, r := range v.NMinus1 {
		if r.Level != "unknown" {
			t.Errorf("malformed snapshot: %s", body)
		}
	}
}

// TestRaiseToCriticalRunsNMinus1First: a raise N−1 judges red is 409
// with the exact sentence and the results, nothing saved, audited as
// refused; with confirm_n_minus_1 it is saved and audited.
func TestRaiseToCriticalRunsNMinus1First(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	code, body := e.do(t, "root", "PUT", availPath, `{"priority":"critical","runs_on":{"mode":"anywhere"}}`)
	if code != 409 {
		t.Fatalf("raise: %d %s", code, body)
	}
	var r struct {
		Error   string `json:"error"`
		NMinus1 []struct {
			Node, Level string
			Unplaced    []string
		} `json:"n_minus_1"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error != "if n1 fails, portcullis-apps/grafana--grafana-7c9d-x1 won't have room" {
		t.Errorf("error = %q", r.Error)
	}
	if len(r.NMinus1) != 3 || r.NMinus1[0].Level != "red" {
		t.Errorf("n_minus_1: %s", body)
	}
	if a := e.stored(t); a != nil {
		t.Errorf("saved %+v on a refusal", a)
	}
	if got := e.auditActions(t, "instance.availability"); len(got) != 1 || !strings.HasPrefix(got[0], "instance.availability:refused:root:grafana") {
		t.Errorf("audit: %v", got)
	}
	// Normal → low: no N−1, saved.
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"low","runs_on":{"mode":"anywhere"}}`); code != 200 {
		t.Fatalf("lower: %d %s", code, body)
	}
	// Confirmed: saved and audited ok.
	code, body = e.do(t, "root", "PUT", availPath, `{"priority":"critical","runs_on":{"mode":"only","nodes":["pi","n1"]},"confirm_n_minus_1":true}`)
	if code != 200 {
		t.Fatalf("confirmed: %d %s", code, body)
	}
	a := e.stored(t)
	if a == nil || a.Priority != "critical" || a.RunsOn.Mode != "only" || strings.Join(a.RunsOn.Nodes, ",") != "n1,pi" {
		t.Errorf("stored %+v", a)
	}
	got := e.auditActions(t, "instance.availability")
	if len(got) != 3 || !strings.HasPrefix(got[2], "instance.availability:ok:root:grafana") {
		t.Errorf("audit: %v", got)
	}
	// The same choice again: nothing changes, no N−1.
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"critical","runs_on":{"mode":"only","nodes":["n1","pi"]}}`); code != 200 {
		t.Errorf("unchanged: %d %s", code, body)
	}
	// The translator's input: the only choice's small node from the snapshot.
	ra, err := e.s.Hub.KubeAvailabilityForTest(context.Background(), "grafana")
	if err != nil || ra == nil || ra.Priority != "critical" || strings.Join(ra.RunsOn.Small, ",") != "pi" || len(ra.RunsOn.Nodes) != 2 {
		t.Errorf("runtime availability %+v %v", ra, err)
	}
}

// TestRaiseYellowNeedsConfirm: a yellow result refuses a raise too, and
// an unjudgeable (unknown) snapshot as red.
func TestRaiseYellowNeedsConfirm(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	e.na.mu.Lock()
	e.na.snap.Pods = append(e.na.snap.Pods, e.na.snap.Pods[1])
	e.na.mu.Unlock()
	code, body := e.do(t, "root", "PUT", availPath, `{"priority":"high","runs_on":{"mode":"anywhere"}}`)
	if code != 409 || !strings.Contains(body, "the N−1 check can't judge the cluster") || !strings.Contains(body, `"level":"unknown"`) {
		t.Errorf("unknown: %d %s", code, body)
	}
	// n2 is full of another app's normal pod: high grafana fits on n2 only
	// by evicting it (yellow).
	e.na.mu.Lock()
	e.na.snap = fullSnapshot()
	e.na.snap.Pods[1] = nodeadm.Pod{Name: "other--web-1", Namespace: "portcullis-apps", Node: "n2", Priority: 1000, PriorityClass: "portcullis-normal",
		PreemptionPolicy: "PreemptLowerPriority", Requests: nodeadm.Resources{CPUm: 1000, MemBytes: 1 << 30}}
	e.na.mu.Unlock()
	code, body = e.do(t, "root", "PUT", availPath, `{"priority":"high","runs_on":{"mode":"anywhere"}}`)
	// grafana's pod runs at high's value (10000): it evicts the normal pod.
	if code != 409 || !strings.Contains(body, `{"node":"n1","level":"yellow","unplaced":[],"evicted":["portcullis-apps/other--web-1"]}`) || !strings.Contains(body, "if n1 fails, portcullis-apps/grafana--grafana-7c9d-x1 won't have room") {
		t.Errorf("yellow: %d %s", code, body)
	}
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"high","runs_on":{"mode":"anywhere"},"confirm_n_minus_1":true}`); code != 200 {
		t.Errorf("confirmed: %d %s", code, body)
	}
}

// TestOnlySmallNodeNeedsSmallNode (amended by Task 1's finding 10: only
// takes any known node, small or not): an only choice of a non-small
// node is fine, of a small one too; an unknown node is 400 "unknown node
// <name>"; prefer naming a small node or class small is refused.
func TestOnlySmallNodeNeedsSmallNode(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	for body, want := range map[string]string{
		`{"priority":"normal","runs_on":{"mode":"only","nodes":["n2"]}}`:           "",
		`{"priority":"normal","runs_on":{"mode":"only","nodes":["pi"]}}`:           "",
		`{"priority":"normal","runs_on":{"mode":"only","nodes":["ghost"]}}`:        "unknown node ghost",
		`{"priority":"normal","runs_on":{"mode":"prefer","nodes":["pi","n1"]}}`:    "small nodes take only instances pinned to them: use Only",
		`{"priority":"normal","runs_on":{"mode":"prefer","class":"small"}}`:        "small nodes take only instances pinned to them: use Only",
		`{"priority":"normal","runs_on":{"mode":"prefer","nodes":["n1","ghost"]}}`: "unknown node ghost",
	} {
		code, got := e.do(t, "root", "PUT", availPath, body)
		if want == "" {
			if code != 200 {
				t.Errorf("%s: %d %s", body, code, got)
			}
			continue
		}
		if code != 400 || strings.TrimSpace(got) != want {
			t.Errorf("%s: %d %q, want 400 %q", body, code, got, want)
		}
	}
}

// TestAvailabilityRefusedOnDocker: off Kubernetes both routes are 409
// "availability needs Kubernetes" (before the body is read).
func TestAvailabilityRefusedOnDocker(t *testing.T) {
	e := newAvailEnv(t, false, nil)
	for _, c := range [][2]string{{"GET", ""}, {"PUT", `{"priority":"high","runs_on":{"mode":"anywhere"}}`}, {"PUT", `{"bogus":1}`}} {
		code, body := e.do(t, "root", c[0], availPath, c[1])
		if code != 409 || strings.TrimSpace(body) != "availability needs Kubernetes" {
			t.Errorf("%s %s: %d %s", c[0], c[1], code, body)
		}
	}
	if a := e.stored(t); a != nil {
		t.Errorf("stored %+v", a)
	}
}

// TestAvailabilityAPIStrict: unknown keys, priority core and an unknown
// mode are 400; a non-admin is refused; an unknown instance is 404.
func TestAvailabilityAPIStrict(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	for _, body := range []string{
		`{"priority":"normal","runs_on":{"mode":"anywhere"},"extra":1}`,
		`{"priority":"normal","runs_on":{"mode":"anywhere","weight":3}}`,
		`{"priority":"core","runs_on":{"mode":"anywhere"}}`,
		`{"priority":"urgent","runs_on":{"mode":"anywhere"}}`,
		`{"runs_on":{"mode":"anywhere"}}`,
		`{"priority":"normal","runs_on":{"mode":"everywhere"}}`,
		`{"priority":"normal"}`,
		`{"priority":"normal","runs_on":{"mode":"anywhere"}} {}`,
	} {
		if code, got := e.do(t, "root", "PUT", availPath, body); code != 400 {
			t.Errorf("%s: %d %s", body, code, got)
		}
	}
	if code, _ := e.do(t, "dana", "GET", availPath, ""); code != 403 {
		t.Errorf("non-admin GET: %d", code)
	}
	if code, _ := e.do(t, "dana", "PUT", availPath, `{"priority":"low","runs_on":{"mode":"anywhere"}}`); code != 403 {
		t.Errorf("non-admin PUT: %d", code)
	}
	if code, body := e.do(t, "root", "GET", "/api/instances/nosuch/availability", ""); code != 404 {
		t.Errorf("unknown instance: %d %s", code, body)
	}
}

// TestAvailabilityRefusals pins every text of §20.6.
func TestAvailabilityRefusals(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	for body, want := range map[string]string{
		`{"priority":"core","runs_on":{"mode":"anywhere"}}`:                              "priority must be critical, high, normal or low",
		`{"priority":"normal","runs_on":{"mode":"sometimes"}}`:                           "runs_on mode must be anywhere, prefer or only",
		`{"priority":"normal","runs_on":{"mode":"anywhere","site":"main"}}`:              "runs_on anywhere takes no class, site or nodes",
		`{"priority":"normal","runs_on":{"mode":"anywhere","nodes":[]}}`:                 "runs_on anywhere takes no class, site or nodes",
		`{"priority":"normal","runs_on":{"mode":"prefer"}}`:                              "runs_on prefer takes exactly one of class, site or nodes",
		`{"priority":"normal","runs_on":{"mode":"prefer","class":"home","site":"main"}}`: "runs_on prefer takes exactly one of class, site or nodes",
		`{"priority":"normal","runs_on":{"mode":"prefer","class":"moon"}}`:               "runs_on prefer takes exactly one of class, site or nodes",
		`{"priority":"normal","runs_on":{"mode":"prefer","nodes":["n1","n1"]}}`:          "runs_on prefer takes exactly one of class, site or nodes",
		`{"priority":"normal","runs_on":{"mode":"prefer","class":"small"}}`:              "small nodes take only instances pinned to them: use Only",
		`{"priority":"normal","runs_on":{"mode":"only"}}`:                                "runs_on only takes nodes, and no class or site",
		`{"priority":"normal","runs_on":{"mode":"only","nodes":["n1"],"site":"main"}}`:   "runs_on only takes nodes, and no class or site",
		`{"priority":"normal","runs_on":{"mode":"only","nodes":["N1!"]}}`:                "runs_on only takes nodes, and no class or site",
		`{"priority":"normal","runs_on":{"mode":"only","nodes":["n9"]}}`:                 "unknown node n9",
		`{"priority":"normal","runs_on":{"mode":"prefer","site":"nowhere"}}`:             "no node is at site nowhere",
		`{"priority":"normal","runs_on":{"mode":"only","nodes":["a..b"]}}`:               "runs_on only takes nodes, and no class or site",
	} {
		if code, got := e.do(t, "root", "PUT", availPath, body); code != 400 || strings.TrimSpace(got) != want {
			t.Errorf("%s: %d %q, want %q", body, code, got, want)
		}
	}
	nodes := `"n1","n2","n3","n4","n5","n6","n7","n8","n9","n10","n11","n12","n13","n14","n15","n16","n17"`
	if code, got := e.do(t, "root", "PUT", availPath, `{"priority":"normal","runs_on":{"mode":"only","nodes":[`+nodes+`]}}`); code != 400 ||
		strings.TrimSpace(got) != "runs_on only takes nodes, and no class or site" {
		t.Errorf("17 nodes: %d %s", code, got)
	}
	// Prefer class home and site are fine (no node check).
	for _, body := range []string{`{"priority":"normal","runs_on":{"mode":"prefer","class":"cloud"}}`, `{"priority":"normal","runs_on":{"mode":"prefer","site":"main"}}`} {
		if code, got := e.do(t, "root", "PUT", availPath, body); code != 200 {
			t.Errorf("%s: %d %s", body, code, got)
		}
	}
	// A stored availability state.Load refuses is a corrupt state file.
	if err := (state.Availability{Priority: "core", RunsOn: state.RunsOn{Mode: "anywhere"}}).Check(); err == nil {
		t.Error("state accepts priority core")
	}
}

func (e *availEnv) setSnap(s nodeadm.Snapshot) {
	e.na.mu.Lock()
	e.na.snap = s
	e.na.mu.Unlock()
}

var notSmallAffinity = [][]nodeadm.Expr{{{Key: "portcullis.io/class", Operator: "NotIn", Values: []string{"small"}}}}

func appPod(name, node string, cpu int64) nodeadm.Pod {
	return nodeadm.Pod{Name: name, Namespace: "portcullis-apps", Node: node, Priority: 1000, PriorityClass: "portcullis-normal",
		PreemptionPolicy: "PreemptLowerPriority", Requests: nodeadm.Resources{CPUm: cpu, MemBytes: 64 << 20}, RequiredAffinity: notSmallAffinity}
}

// dsFull: every node full of DaemonSet pods (they never move: green
// alone), so a new pod has no room anywhere.
func dsFull() nodeadm.Snapshot {
	s := nodeadm.Snapshot{V: 1, Nodes: []nodeadm.Node{availNode("n1", "home"), availNode("n2", "home"), availNode("pi", "small")}}
	for _, n := range s.Nodes {
		s.Pods = append(s.Pods, nodeadm.Pod{Name: "agent-" + n.Name, Namespace: "kube-system", Node: n.Name, Priority: 1000000, PriorityClass: "portcullis-core",
			PreemptionPolicy: "PreemptLowerPriority", DaemonSet: true, Requests: nodeadm.Resources{CPUm: 1000, MemBytes: 1 << 30}})
	}
	return s
}

// TestPlacementChangeAtCriticalRunsNMinus1 (fix I2): critical anywhere is
// green; moving it to only [n1] at the same priority is judged and red.
func TestPlacementChangeAtCriticalRunsNMinus1(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	e.setSnap(nodeadm.Snapshot{V: 1, Nodes: []nodeadm.Node{availNode("n1", "home"), availNode("n2", "home")},
		Pods: []nodeadm.Pod{appPod("grafana--grafana-1", "n1", 500)}})
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"critical","runs_on":{"mode":"anywhere"}}`); code != 200 {
		t.Fatalf("critical anywhere: %d %s", code, body)
	}
	code, body := e.do(t, "root", "PUT", availPath, `{"priority":"critical","runs_on":{"mode":"only","nodes":["n1"]}}`)
	if code != 409 || !strings.Contains(body, `"error":"if n1 fails, portcullis-apps/grafana--grafana-1 won't have room"`) {
		t.Fatalf("critical only [n1]: %d %s", code, body)
	}
	if a := e.stored(t); a == nil || a.RunsOn.Mode != "anywhere" {
		t.Errorf("stored %+v", a)
	}
	// A lower priority isn't gated (low only [n1] is saved).
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"low","runs_on":{"mode":"only","nodes":["n1"]}}`); code != 200 {
		t.Errorf("low: %d %s", code, body)
	}
}

// TestRaiseJudgesOtherInstances (fix I1): grafana was raised to critical
// (saved, its pod not restarted yet: the snapshot still says normal);
// raising home then is judged with grafana at critical: red.
func TestRaiseJudgesOtherInstances(t *testing.T) {
	e := newAvailEnv(t, true, func(st *state.AppState) {
		st.Instances["home"] = state.Instance{ID: "home", Template: "home", State: state.InstanceCreated}
	})
	e.setSnap(nodeadm.Snapshot{V: 1, Nodes: []nodeadm.Node{availNode("n1", "home"), availNode("n2", "home")},
		Pods: []nodeadm.Pod{appPod("grafana--grafana-1", "n1", 500), appPod("home--web-1", "n2", 600)}})
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"critical","runs_on":{"mode":"anywhere"}}`); code != 200 {
		t.Fatalf("grafana alone: %d %s", code, body)
	}
	code, body := e.do(t, "root", "PUT", "/api/instances/home/availability", `{"priority":"critical","runs_on":{"mode":"anywhere"}}`)
	if code != 409 || !strings.Contains(body, `{"node":"n1","level":"red"`) {
		t.Fatalf("home after grafana: %d %s", code, body)
	}
	// Alone (grafana back at normal), home's raise is green.
	e.do(t, "root", "PUT", availPath, `{"priority":"normal","runs_on":{"mode":"anywhere"}}`)
	if code, body := e.do(t, "root", "PUT", "/api/instances/home/availability", `{"priority":"critical","runs_on":{"mode":"anywhere"}}`); code != 200 {
		t.Errorf("home alone: %d %s", code, body)
	}
}

// TestRaisePodlessInstance (fix I3): an instance with no live pods is
// modelled from the translator's pods: on a cluster with no room the
// raise is red (the modelling node's result isn't shown); the model's
// failure is unknown; enabling a stored critical instance re-runs the
// gate and leaves it stopped.
func TestRaisePodlessInstance(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	e.setSnap(dsFull())
	var asked []string
	e.rt.PodShapesFn = func(p runtime.Project) ([]runtime.PodShape, error) {
		asked = append(asked, p.Instance)
		return []runtime.PodShape{{Workload: "grafana--grafana", Replicas: 1, CPUm: 50, MemBytes: 512 << 20}}, nil
	}
	code, body := e.do(t, "root", "PUT", availPath, `{"priority":"critical","runs_on":{"mode":"anywhere"}}`)
	if code != 409 || !strings.Contains(body, "if n1 fails, portcullis-apps/grafana--grafana-unstarted-0 won't have room") || strings.Contains(body, "portcullis-n1-unstarted") {
		t.Fatalf("pod-less raise: %d %s", code, body)
	}
	if strings.Join(asked, ",") != "grafana" {
		t.Errorf("rendered %v", asked)
	}
	e.rt.PodShapesFn = func(runtime.Project) ([]runtime.PodShape, error) { return nil, errors.New("no model") }
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"high","runs_on":{"mode":"anywhere"}}`); code != 409 || !strings.Contains(body, `"level":"unknown"`) {
		t.Errorf("no model: %d %s", code, body)
	}
	// Confirmed in the browser: saved; enabling then refuses (409, stays stopped).
	e.rt.PodShapesFn = func(runtime.Project) ([]runtime.PodShape, error) {
		return []runtime.PodShape{{Workload: "grafana--grafana", Replicas: 1, CPUm: 50, MemBytes: 512 << 20}}, nil
	}
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"critical","runs_on":{"mode":"anywhere"},"confirm_n_minus_1":true}`); code != 200 {
		t.Fatalf("confirmed: %d %s", code, body)
	}
	_, err := e.s.Hub.StartEnable("grafana", directory.Human("root"))
	if n1 := hub.ErrorsAsN1(err); n1 == nil || !strings.Contains(n1.Msg, "won't have room: grafana stays stopped") {
		t.Fatalf("enable: %v", err)
	}
	if e.s.Hub.IsEnabled("grafana") {
		t.Error("enabled past the gate")
	}
	// With room, it starts past the gate.
	e.setSnap(nodeadm.Snapshot{V: 1, Nodes: []nodeadm.Node{availNode("n1", "home"), availNode("n2", "home")}})
	if _, err := e.s.Hub.StartEnable("grafana", directory.Human("root")); hub.ErrorsAsN1(err) != nil {
		t.Errorf("enable with room: %v", err)
	}
	waitIdle(t, e.s.Hub, "grafana")
}

// TestAvailabilityToolAIRules (fix S1): set_instance_availability is W
// without confirm_n_minus_1, D with it; over MCP a red result is the 409
// {error, n_minus_1} even confirmed, nothing saved; a yellow one goes
// ahead confirmed.
func TestAvailabilityToolAIRules(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	e.s.registerMCPTools()
	var tool *Tool
	for _, tl := range e.s.tools(ScopeAdmin) {
		if tl.Name == "set_instance_availability" {
			tl := tl
			tool = &tl
		}
	}
	if tool == nil {
		t.Fatal("set_instance_availability isn't registered")
	}
	args := func(confirm bool) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"id": "grafana", "priority": "critical", "runs_on": map[string]any{"mode": "anywhere"}, "confirm_n_minus_1": confirm})
		return b
	}
	if tool.ClassFor(context.Background(), args(false)) != ClassWrite || tool.ClassFor(context.Background(), args(true)) != ClassDestructive {
		t.Error("ClassFor: want W without the confirmation, D with it")
	}
	ai := &directory.Caller{User: "root", Via: directory.ViaAI, Client: "portcullis-ai-claude"}
	for _, confirm := range []bool{false, true} {
		_, err := tool.Run(context.Background(), ai, args(confirm))
		txt := sdk.TextOf(toolError(err, func(s string) string { return s }))
		if !strings.HasPrefix(txt, `409: {"error":"if n1 fails, portcullis-apps/grafana--grafana-7c9d-x1 won't have room","n_minus_1":[`) {
			t.Errorf("AI red (confirm %v): %s", confirm, txt)
		}
	}
	if a := e.stored(t); a != nil {
		t.Errorf("saved %+v", a)
	}
	// Yellow (an evicted normal pod): confirmed over MCP, saved.
	s := fullSnapshot()
	s.Pods[1] = appPod("other--web-1", "n2", 1000)
	e.setSnap(s)
	hi := json.RawMessage(`{"id":"grafana","priority":"high","runs_on":{"mode":"anywhere"},"confirm_n_minus_1":true}`)
	if _, err := tool.Run(context.Background(), ai, hi); err != nil {
		t.Fatalf("AI yellow confirmed: %v", err)
	}
	if a := e.stored(t); a == nil || a.Priority != "high" {
		t.Errorf("stored %+v", a)
	}
}

// TestKubeAvailabilityStaleSnapshot (fix M3): with nodeadm down, an up
// uses the last snapshot only when it is at most 10 minutes old.
func TestKubeAvailabilityStaleSnapshot(t *testing.T) {
	e := newAvailEnv(t, true, nil)
	if code, body := e.do(t, "root", "PUT", availPath, `{"priority":"normal","runs_on":{"mode":"only","nodes":["n1","pi"]}}`); code != 200 {
		t.Fatalf("PUT: %d %s", code, body)
	}
	for _, c := range []struct {
		at string
		ok bool
	}{{"", false}, {time.Now().Add(-11 * time.Minute).UTC().Format(time.RFC3339), false}, {time.Now().UTC().Format(time.RFC3339), true}} {
		s := fullSnapshot()
		s.TakenAt = c.at
		e.setSnap(s)
		e.na.mu.Lock()
		e.na.err = nil
		e.na.mu.Unlock()
		e.do(t, "root", "GET", availPath, "") // the last snapshot read
		e.na.mu.Lock()
		e.na.err = errors.New("nodeadm down")
		e.na.mu.Unlock()
		ra, err := e.s.Hub.KubeAvailabilityForTest(context.Background(), "grafana")
		if c.ok != (err == nil) || c.ok && strings.Join(ra.RunsOn.Small, ",") != "pi" {
			t.Errorf("taken at %q: %+v %v", c.at, ra, err)
		}
	}
}

// TestDriftAdoptRunsNMinus1 (re-review N1): adopting a drifted critical
// instance starts it, so it passes the same N−1 gate as an enable: red
// on a full cluster is refused and it stays stopped.
func TestDriftAdoptRunsNMinus1(t *testing.T) {
	e := newAvailEnv(t, true, func(st *state.AppState) {
		in := st.Instances["grafana"]
		in.Availability = &state.Availability{Priority: "critical", RunsOn: state.RunsOn{Mode: "anywhere"}}
		st.Instances["grafana"] = in
	})
	e.setSnap(dsFull())
	e.rt.PodShapesFn = func(runtime.Project) ([]runtime.PodShape, error) {
		return []runtime.PodShape{{Workload: "grafana--grafana", Replicas: 1, CPUm: 50, MemBytes: 512 << 20}}, nil
	}
	err := e.s.Hub.ResolveDrift("grafana", hub.ActionAdopt)
	if n1 := hub.ErrorsAsN1(err); n1 == nil || !strings.Contains(n1.Msg, "grafana stays stopped") {
		t.Fatalf("adopt: %v", err)
	}
	if e.s.Hub.IsEnabled("grafana") {
		t.Error("adopted past the gate")
	}
	code, body := e.do(t, "root", "POST", "/api/drift/resolve", `{"id":"grafana","action":"adopt"}`)
	if code != 409 || !strings.Contains(body, "won't have room") {
		t.Errorf("route: %d %s", code, body)
	}
}
