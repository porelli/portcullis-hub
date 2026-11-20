package nminus1

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/jsonstrict"
	"github.com/portcullis/hub/internal/nodeadm"
)

type checkVector struct {
	Name     string           `json:"name"`
	Snapshot nodeadm.Snapshot `json:"snapshot"`
	Want     []struct {
		Node     string   `json:"node"`
		Level    string   `json:"level"`
		Unplaced []string `json:"unplaced"`
		Evicted  []string `json:"evicted"`
	} `json:"want"`
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// TestNMinus1Vectors: Check over nminus1_vectors.json (contract §20.7)
// gives each case's results: one per node in snapshot order, the level,
// and the unplaced and evicted pods (order-insensitive). A result that
// isn't green names what lacks room, and Explain says it (M7).
func TestNMinus1Vectors(t *testing.T) {
	b, err := os.ReadFile("testdata/nminus1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []checkVector
	if err := jsonstrict.Decode(b, &vs); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			got := check(t, v.Snapshot)
			if len(got) != len(v.Want) {
				t.Fatalf("%d results, want %d: %+v", len(got), len(v.Want), got)
			}
			for i, w := range v.Want {
				g := got[i]
				if g.Node != w.Node || string(g.Level) != w.Level || !sameSet(g.Unplaced, w.Unplaced) || !sameSet(g.Evicted, w.Evicted) {
					t.Errorf("node %s: got %s unplaced %v evicted %v; want %s %s unplaced %v evicted %v",
						g.Node, g.Level, g.Unplaced, g.Evicted, w.Node, w.Level, w.Unplaced, w.Evicted)
				}
				if g.Unplaced == nil || g.Evicted == nil {
					t.Errorf("node %s: nil list (the JSON must be [])", g.Node)
				}
				e := Explain(g)
				switch {
				case g.Level == Green && (e != "" || len(g.Lacking) != 0):
					t.Errorf("node %s: green with %q %v", g.Node, e, g.Lacking)
				case g.Level != Green && (len(g.Lacking) == 0 || e != "if "+g.Node+" fails, "+joinNames(g.Lacking)+" won't have room"):
					t.Errorf("node %s: %s with %q %v", g.Node, g.Level, e, g.Lacking)
				}
			}
		})
	}
}

func check(t testing.TB, s nodeadm.Snapshot) []Result {
	t.Helper()
	r, err := Check(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const apps = "portcullis-apps"

func pod(name, ns, node, class string, prio int, mem int64) nodeadm.Pod {
	p := nodeadm.Pod{Name: name, Namespace: ns, Node: node, Priority: prio, PriorityClass: class,
		PreemptionPolicy: "PreemptLowerPriority", Requests: nodeadm.Resources{CPUm: 100, MemBytes: mem}}
	if class == "portcullis-low" {
		p.PreemptionPolicy = "Never"
	}
	return p
}

func node(name string, mem int64) nodeadm.Node {
	return nodeadm.Node{Name: name, Ready: true, Allocatable: nodeadm.Resources{CPUm: 4000, MemBytes: mem},
		Labels: map[string]string{"kubernetes.io/hostname": name}}
}

func inSet(p nodeadm.Pod, set string, min int) nodeadm.Pod {
	p.Set = jsonstrict.Some(nodeadm.PodSet{Name: set, Min: min})
	return p
}

// TestValidate (I1): a malformed snapshot is an error, never a result.
func TestValidate(t *testing.T) {
	good := func() nodeadm.Snapshot {
		a := pod("a", "portcullis", "n1", "portcullis-core", 1000000, 500)
		a.Tolerations = []nodeadm.Toleration{{Key: "k", Operator: "Exists"}}
		a.RequiredAffinity = [][]nodeadm.Expr{{{Key: "n", Operator: "Gt", Values: []string{"1"}}}}
		return nodeadm.Snapshot{Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
			Pods: []nodeadm.Pod{inSet(a, "s", 1), pod("b", "portcullis", "n2", "portcullis-core", 1000000, 500)}}
	}
	if _, err := Check(good()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(s *nodeadm.Snapshot){
		"no nodes":              func(s *nodeadm.Snapshot) { s.Nodes, s.Pods = nil, nil },
		"node without a name":   func(s *nodeadm.Snapshot) { s.Nodes[1].Name = ""; s.Pods = s.Pods[:1] },
		"repeated node":         func(s *nodeadm.Snapshot) { s.Nodes[1].Name = "n1"; s.Pods[1].Node = "n1" },
		"negative allocatable":  func(s *nodeadm.Snapshot) { s.Nodes[0].Allocatable.MemBytes = -1 },
		"negative cpu":          func(s *nodeadm.Snapshot) { s.Nodes[0].Allocatable.CPUm = -1 },
		"unknown taint effect":  func(s *nodeadm.Snapshot) { s.Nodes[0].Taints = []nodeadm.Taint{{Key: "k", Effect: "Bogus"}} },
		"pod without a name":    func(s *nodeadm.Snapshot) { s.Pods[1].Name = "" },
		"pod without namespace": func(s *nodeadm.Snapshot) { s.Pods[1].Namespace = "" },
		"repeated pod":          func(s *nodeadm.Snapshot) { s.Pods[1].Name = "a" },
		"pod on unknown node":   func(s *nodeadm.Snapshot) { s.Pods[1].Node = "n9" },
		"negative request":      func(s *nodeadm.Snapshot) { s.Pods[1].Requests.MemBytes = -5000 },
		"negative cpu request":  func(s *nodeadm.Snapshot) { s.Pods[1].Requests.CPUm = -1 },
		"unknown preemption":    func(s *nodeadm.Snapshot) { s.Pods[1].PreemptionPolicy = "Bogus" },
		"empty preemption":      func(s *nodeadm.Snapshot) { s.Pods[1].PreemptionPolicy = "" },
		"set minimum 0":         func(s *nodeadm.Snapshot) { s.Pods[0].Set.V.Min = 0 },
		"set without a name":    func(s *nodeadm.Snapshot) { s.Pods[0].Set.V.Name = "" },
		"toleration operator":   func(s *nodeadm.Snapshot) { s.Pods[0].Tolerations[0].Operator = "Bogus" },
		"toleration effect":     func(s *nodeadm.Snapshot) { s.Pods[0].Tolerations[0].Effect = "Bogus" },
		"selector operator":     func(s *nodeadm.Snapshot) { s.Pods[0].RequiredAffinity[0][0].Operator = "Bogus" },
		"Gt not an integer":     func(s *nodeadm.Snapshot) { s.Pods[0].RequiredAffinity[0][0].Values = []string{"x"} },
		"Gt two values":         func(s *nodeadm.Snapshot) { s.Pods[0].RequiredAffinity[0][0].Values = []string{"1", "2"} },
		"In without values": func(s *nodeadm.Snapshot) {
			s.Pods[0].RequiredAffinity[0][0] = nodeadm.Expr{Key: "k", Operator: "In"}
		},
		"Exists with values": func(s *nodeadm.Snapshot) {
			s.Pods[0].RequiredAffinity[0][0] = nodeadm.Expr{Key: "k", Operator: "Exists", Values: []string{"x"}}
		},
	}
	for name, mutate := range cases {
		s := good()
		mutate(&s)
		r, err := Check(s)
		if err == nil || r != nil || !strings.HasPrefix(err.Error(), "nminus1: malformed snapshot: ") {
			t.Errorf("%s: %v %v", name, r, err)
		}
	}
	if _, err := CheckIn(good(), Namespaces{Apps: apps}); err == nil {
		t.Error("no core namespace accepted")
	}
	if _, err := CheckIn(good(), Namespaces{Core: "portcullis"}); err == nil {
		t.Error("no apps namespace accepted")
	}
}

// TestNeverEvictsOutsideApps (ruling I5): a normal pod outside the apps
// namespace is never a victim, even for a core pod; one inside is.
func TestNeverEvictsOutsideApps(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods: []nodeadm.Pod{
			pod("hub", "portcullis", "n1", "portcullis-core", 1000000, 2000),
			pod("odd", "portcullis", "n2", "portcullis-normal", 1000, 3000),
		},
	}
	r := check(t, s)
	if r[0].Level != Red || !slices.Equal(r[0].Unplaced, []string{"hub"}) || len(r[0].Evicted) != 0 {
		t.Errorf("outside apps: %+v", r[0])
	}
	s.Pods[1].Namespace = apps
	if r := check(t, s); r[0].Level != Green || !slices.Equal(r[0].Evicted, []string{"portcullis-apps/odd"}) {
		t.Errorf("inside apps: %+v", r[0])
	}
	r, err := CheckIn(s, Namespaces{Apps: "apps-elsewhere", Core: "portcullis"})
	if err != nil || r[0].Level != Red {
		t.Errorf("another apps namespace: %+v %v", r, err)
	}
}

// TestNames (M3): pods are named bare in the core namespace, else
// "<namespace>/<name>", so an apps vault-0 never reads as the core one.
func TestNames(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 1000)},
		Pods: []nodeadm.Pod{
			pod("vault-0", "portcullis", "n1", "portcullis-core", 1000000, 2000),
			pod("vault-0", apps, "n1", "portcullis-critical", 100000, 2000),
		},
	}
	r := check(t, s)[0]
	if !slices.Equal(r.Unplaced, []string{"portcullis-apps/vault-0", "vault-0"}) {
		t.Errorf("%+v", r)
	}
	rs, _ := CheckIn(s, Namespaces{Apps: apps, Core: "core"})
	if !slices.Equal(rs[0].Unplaced, []string{"portcullis-apps/vault-0", "portcullis/vault-0"}) {
		t.Errorf("another core namespace: %+v", rs)
	}
}

// TestTiers (I2, M6): outside the apps namespace a pod without a
// Portcullis class is core; an apps pod is at most critical (its set below
// the minimum is red, but an apps "core" class is no more than critical).
func TestTiers(t *testing.T) {
	ns := DefaultNamespaces
	cases := []struct {
		ns, class string
		want      tier
	}{
		{"kube-system", "system-cluster-critical", tierCore},
		{"portcullis", "", tierCore},
		{"portcullis", "portcullis-normal", tierNormal},
		{"portcullis", "portcullis-core", tierCore},
		{apps, "portcullis-core", tierCritical},
		{apps, "portcullis-critical", tierCritical},
		{apps, "portcullis-high", tierHigh},
		{apps, "portcullis-low", tierLow},
		{apps, "", tierOther},
		{apps, "system-node-critical", tierOther},
	}
	for _, c := range cases {
		p := nodeadm.Pod{Namespace: c.ns, PriorityClass: c.class}
		if got := tierOf(&p, ns); got != c.want {
			t.Errorf("%s %q: %v, want %v", c.ns, c.class, got, c.want)
		}
	}
	// An apps pod of no Portcullis class never raises the level and is
	// never a victim.
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods: []nodeadm.Pod{
			pod("x", apps, "n1", "", 0, 4000),
			pod("hub", "portcullis", "n1", "portcullis-core", 1000000, 0),
			pod("y", apps, "n2", "", 0, 3000),
			pod("big", "portcullis", "n1", "portcullis-core", 1000000, 1500),
		},
	}
	s.Nodes[0].Allocatable.MemBytes = 6000
	if r := check(t, s)[0]; r.Level != Red || !slices.Equal(r.Unplaced, []string{"big", "portcullis-apps/x"}) || len(r.Evicted) != 0 {
		t.Errorf("%+v", r)
	}
}

// TestHighSetMemberIsYellow: a high pod of a set below its minimum is
// still at most yellow (red is only for core and critical).
func TestHighSetMemberIsYellow(t *testing.T) {
	a := inSet(pod("a-0", apps, "n1", "portcullis-high", 10000, 3000), "a", 2)
	b := inSet(pod("a-1", apps, "n2", "portcullis-high", 10000, 3000), "a", 2)
	a.AntiAffinityHost, b.AntiAffinityHost = true, true
	r := check(t, nodeadm.Snapshot{Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)}, Pods: []nodeadm.Pod{a, b}})
	if r[0].Level != Yellow || !slices.Equal(r[0].Unplaced, []string{"portcullis-apps/a-0"}) {
		t.Errorf("%+v", r[0])
	}
}

// TestNormalSetBelowMinimumIsGreen: normal and low pods never raise the
// level, in a set or not.
func TestNormalSetBelowMinimumIsGreen(t *testing.T) {
	a := inSet(pod("a-0", apps, "n1", "portcullis-normal", 1000, 3000), "a", 2)
	b := inSet(pod("a-1", apps, "n2", "portcullis-normal", 1000, 3000), "a", 2)
	a.AntiAffinityHost, b.AntiAffinityHost = true, true
	r := check(t, nodeadm.Snapshot{Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)}, Pods: []nodeadm.Pod{a, b}})
	if r[0].Level != Green || !slices.Equal(r[0].Unplaced, []string{"portcullis-apps/a-0"}) {
		t.Errorf("%+v", r[0])
	}
}

// TestSetBelowMinimumEverywhere (M4): a core set already below its
// minimum is red for every node, the nodes without a member included, and
// named by Explain.
func TestSetBelowMinimumEverywhere(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000), node("n3", 4000)},
		Pods:  []nodeadm.Pod{inSet(pod("vault-0", "portcullis", "n1", "portcullis-core", 1000000, 300), "vault", 2)},
	}
	for _, r := range check(t, s) {
		if r.Level != Red || !slices.Equal(r.Lacking, []string{"vault"}) && !slices.Equal(r.Lacking, []string{"vault-0"}) {
			t.Errorf("%+v", r)
		}
	}
	if got := Explain(check(t, s)[1]); got != "if n2 fails, vault won't have room" {
		t.Errorf("%q", got)
	}
	// A high set below its minimum is no red.
	s.Pods[0].PriorityClass, s.Pods[0].Priority = "portcullis-high", 10000
	if r := check(t, s)[1]; r.Level != Green {
		t.Errorf("high set: %+v", r)
	}
}

// TestSpreadDomains (S1): the spread's domains are every node passing the
// affinity, whatever its taints or readiness, the lost node among them at
// its member count (0 once its pods move); a node the affinity rules out is
// no domain.
func TestSpreadDomains(t *testing.T) {
	mk := func(name, on string) nodeadm.Pod {
		p := inSet(pod(name, "portcullis", on, "portcullis-core", 1000000, 300), "k", 1)
		p.SpreadHost = true
		p.RequiredAffinity = [][]nodeadm.Expr{{{Key: "site", Operator: "In", Values: []string{"main"}}}}
		return p
	}
	snap := func(lost, third string) nodeadm.Snapshot {
		ns := []nodeadm.Node{node("n1", 4000), node("n2", 4000), node("n3", 4000)}
		ns[0].Labels["site"], ns[1].Labels["site"], ns[2].Labels["site"] = lost, "main", third
		return nodeadm.Snapshot{Nodes: ns, Pods: []nodeadm.Pod{mk("k-0", "n1"), mk("k-1", "n2")}}
	}
	// n1 is no longer at main (labels changed after scheduling), so it is no
	// domain: what n3 is decides whether k-0 may stack on n2.
	s := snap("old", "edge")
	if r := check(t, s)[0]; r.Level != Green {
		t.Errorf("n3 no domain: k-0 stacks on n2: %+v", r)
	}
	s = snap("old", "main")
	s.Nodes[2].Taints = []nodeadm.Taint{{Key: "t", Value: "v", Effect: "NoSchedule"}}
	if r := check(t, s)[0]; r.Level != Yellow || !slices.Equal(r.Unplaced, []string{"k-0"}) {
		t.Errorf("a tainted node is a domain: %+v", r)
	}
	s = snap("old", "main")
	s.Nodes[2].Ready = false
	if r := check(t, s)[0]; r.Level != Yellow {
		t.Errorf("a NotReady node is a domain: %+v", r)
	}
	s = snap("old", "main")
	s.Nodes[2].Unschedulable = true
	if r := check(t, s)[0]; r.Level != Yellow {
		t.Errorf("a cordoned node is a domain: %+v", r)
	}
	// The lost node at main is a domain at 0: k-0 can't stack on n2.
	s = snap("main", "edge")
	if r := check(t, s)[0]; r.Level != Yellow {
		t.Errorf("the lost node is a domain: %+v", r)
	}
	// Room on a third main node: the member moves there.
	if r := check(t, snap("main", "main"))[0]; r.Level != Green {
		t.Errorf("room on n3: %+v", r)
	}
}

// TestBaseline (I3): the pods of a NotReady node are placed first; a pod
// placed there by the baseline moves again when its new node is lost.
func TestBaseline(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000), node("n3", 4000)},
		Pods: []nodeadm.Pod{
			pod("x", "portcullis", "n3", "portcullis-core", 1000000, 2500),
			pod("app", apps, "n1", "portcullis-normal", 1000, 3000),
			pod("ds", "portcullis", "n3", "portcullis-core", 1000000, 3999),
		},
	}
	s.Pods[2].DaemonSet = true
	s.Nodes[2].Ready = false
	r := check(t, s)
	// Baseline: x onto n2 (DaemonSet pods of n3 go nowhere). n1 lost: app
	// fits nowhere but n2 (1500 free): unplaced, green.
	if r[0].Level != Green || !slices.Equal(r[0].Unplaced, []string{"portcullis-apps/app"}) {
		t.Errorf("n1: %+v", r[0])
	}
	// n2 lost: x moves again, evicting app on n1.
	if r[1].Level != Green || !slices.Equal(r[1].Evicted, []string{"portcullis-apps/app"}) || len(r[1].Unplaced) != 0 {
		t.Errorf("n2: %+v", r[1])
	}
	if r[2].Level != Green || len(r[2].Unplaced) != 0 {
		t.Errorf("n3: %+v", r[2])
	}
}

// TestSelectorOperators: the node-selector operators.
func TestSelectorOperators(t *testing.T) {
	n := map[string]string{"a": "x", "n": "5"}
	cases := []struct {
		e    nodeadm.Expr
		want bool
	}{
		{nodeadm.Expr{Key: "a", Operator: "In", Values: []string{"x"}}, true},
		{nodeadm.Expr{Key: "a", Operator: "NotIn", Values: []string{"x"}}, false},
		{nodeadm.Expr{Key: "a", Operator: "NotIn", Values: []string{"y"}}, true},
		{nodeadm.Expr{Key: "b", Operator: "NotIn", Values: []string{"x"}}, true},
		{nodeadm.Expr{Key: "a", Operator: "Exists"}, true},
		{nodeadm.Expr{Key: "b", Operator: "DoesNotExist"}, true},
		{nodeadm.Expr{Key: "n", Operator: "Gt", Values: []string{"4"}}, true},
		{nodeadm.Expr{Key: "n", Operator: "Lt", Values: []string{"4"}}, false},
		{nodeadm.Expr{Key: "a", Operator: "Gt", Values: []string{"4"}}, false},
		{nodeadm.Expr{Key: "a", Operator: "Bogus"}, false},
	}
	for _, c := range cases {
		if got := exprMatches(c.e, n); got != c.want {
			t.Errorf("%+v: %v", c.e, got)
		}
	}
}

// TestExplain: the sentence of §20.6's 409, naming the pods behind the
// level ("if <node> fails, <x> won't have room").
func TestExplain(t *testing.T) {
	cases := []struct {
		r    Result
		want string
	}{
		{Result{Node: "n1", Level: Green}, ""},
		{Result{Node: "n1", Level: Red, Unplaced: []string{"hub", "low"}, Lacking: []string{"hub"}}, "if n1 fails, hub won't have room"},
		{Result{Node: "n2", Level: Yellow, Lacking: []string{"a", "b"}}, "if n2 fails, a and b won't have room"},
		{Result{Node: "n3", Level: Red, Lacking: []string{"a", "b", "c"}}, "if n3 fails, a, b and c won't have room"},
		{Result{Node: "n4", Level: Yellow, Unplaced: []string{"x"}}, "if n4 fails, x won't have room"},
	}
	for _, c := range cases {
		if got := Explain(c.r); got != c.want {
			t.Errorf("%+v: %q, want %q", c.r, got, c.want)
		}
	}
	// From Check: the eviction case names the high pod.
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods: []nodeadm.Pod{
			pod("app-high", apps, "n1", "portcullis-high", 10000, 2000),
			pod("app-norm", apps, "n2", "portcullis-normal", 1000, 3000),
		},
	}
	if got := Explain(check(t, s)[0]); got != "if n1 fails, portcullis-apps/app-high won't have room" {
		t.Errorf("%q", got)
	}
}

// TestPriorityOrder: the lost node's pods are placed highest priority
// first, so a core pod takes the only room before a high one.
func TestPriorityOrder(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods: []nodeadm.Pod{
			pod("app-high", apps, "n1", "portcullis-high", 10000, 2000),
			pod("hub", "portcullis", "n1", "portcullis-core", 1000000, 1500),
			pod("fill", "portcullis", "n2", "portcullis-core", 1000000, 2000),
		},
	}
	if r := check(t, s)[0]; r.Level != Yellow || !slices.Equal(r.Unplaced, []string{"portcullis-apps/app-high"}) {
		t.Errorf("%+v", r)
	}
}

// TestPreemptionRules: who may evict whom (contract §20.7 step 3; I2:
// by numeric priority, whatever the class).
func TestPreemptionRules(t *testing.T) {
	run := func(mover, victim nodeadm.Pod) Result {
		return check(t, nodeadm.Snapshot{
			Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
			Pods:  []nodeadm.Pod{mover, victim},
		})[0]
	}
	norm := pod("norm", apps, "n1", "portcullis-normal", 1000, 2000)
	normNever := norm
	normNever.PreemptionPolicy = "Never"
	lowPreempting := pod("low", apps, "n1", "portcullis-low", 100, 2000)
	lowPreempting.PreemptionPolicy = "PreemptLowerPriority"
	lowerLow := pod("lower", apps, "n2", "portcullis-low", 50, 3000)
	equalNorm := pod("peer", apps, "n2", "portcullis-normal", 1000, 3000)
	system := pod("coredns", "kube-system", "n1", "system-cluster-critical", 2000000000, 2000)
	appNoClass := pod("odd", apps, "n1", "", 5000, 2000)
	for name, c := range map[string]struct {
		mover, victim nodeadm.Pod
		evicts        bool
	}{
		"normal evicts a lower low":                   {norm, lowerLow, true},
		"preemptionPolicy Never never evicts":         {normNever, lowerLow, false},
		"a low pod never evicts, whatever its policy": {lowPreempting, lowerLow, false},
		"never a victim at the pod's own priority":    {norm, equalNorm, false},
		"a system pod evicts by its priority":         {system, equalNorm, true},
		"an apps pod without a class, by priority":    {appNoClass, equalNorm, true},
	} {
		r := run(c.mover, c.victim)
		if got := len(r.Evicted) == 1; got != c.evicts {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// TestLowestVictimFirst: the lowest priority victim goes first, and only
// as many as make room.
func TestLowestVictimFirst(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods: []nodeadm.Pod{
			pod("hub", "portcullis", "n1", "portcullis-core", 1000000, 1500),
			pod("norm", apps, "n2", "portcullis-normal", 1000, 2000),
			pod("low", apps, "n2", "portcullis-low", 100, 1500),
		},
	}
	if r := check(t, s)[0]; r.Level != Green || !slices.Equal(r.Evicted, []string{"portcullis-apps/low"}) {
		t.Errorf("%+v", r)
	}
}

// TestTolerations: Kubernetes' toleration matching; every effect but
// PreferNoSchedule keeps out (M2).
func TestTolerations(t *testing.T) {
	taint := nodeadm.Taint{Key: "k", Value: "v", Effect: "NoSchedule"}
	cases := []struct {
		tol  nodeadm.Toleration
		want bool
	}{
		{nodeadm.Toleration{Key: "k", Operator: "Equal", Value: "v", Effect: "NoSchedule"}, true},
		{nodeadm.Toleration{Key: "k", Operator: "", Value: "v"}, true},
		{nodeadm.Toleration{Key: "k", Operator: "Equal", Value: "w", Effect: "NoSchedule"}, false},
		{nodeadm.Toleration{Key: "k", Operator: "Exists", Effect: "NoExecute"}, false},
		{nodeadm.Toleration{Key: "other", Operator: "Exists"}, false},
		{nodeadm.Toleration{Operator: "Exists"}, true},
		{nodeadm.Toleration{Key: "k", Operator: "Bogus", Value: "v"}, false},
	}
	for _, c := range cases {
		if got := toleratesTaint(c.tol, taint); got != c.want {
			t.Errorf("%+v: %v", c.tol, got)
		}
	}
	for effect, want := range map[string]bool{"NoSchedule": false, "NoExecute": false, "PreferNoSchedule": true, "Bogus": false} {
		if got := tolerates(nil, []nodeadm.Taint{{Key: "k", Effect: effect}}); got != want {
			t.Errorf("effect %s: %v", effect, got)
		}
	}
}

// TestHostnameWithoutLabel: a hostname term matches the node's name when
// the snapshot carries no hostname label.
func TestHostnameWithoutLabel(t *testing.T) {
	a := pod("a", "portcullis", "n1", "portcullis-core", 1000000, 500)
	a.RequiredAffinity = [][]nodeadm.Expr{{{Key: "kubernetes.io/hostname", Operator: "In", Values: []string{"n2"}}}}
	s := nodeadm.Snapshot{Nodes: []nodeadm.Node{node("n1", 4000), {Name: "n2", Ready: true, Allocatable: nodeadm.Resources{CPUm: 4000, MemBytes: 4000}}},
		Pods: []nodeadm.Pod{a}}
	if r := check(t, s)[0]; r.Level != Green {
		t.Errorf("%+v", r)
	}
}

// TestExplainNamesRedOnly: a red result names the core and critical pods,
// not the yellow ones.
func TestExplainNamesRedOnly(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods: []nodeadm.Pod{
			pod("hub", "portcullis", "n1", "portcullis-core", 1000000, 3000),
			pod("app-high", apps, "n1", "portcullis-high", 10000, 3000),
			pod("fill", "portcullis", "n2", "portcullis-core", 1000000, 2000),
		},
	}
	if got := Explain(check(t, s)[0]); got != "if n1 fails, hub won't have room" {
		t.Errorf("%q", got)
	}
}

// bigSnapshot: nodes nodes of 4 CPU / 4 GB, and pods apps pods in
// hostname-spread (and every other set anti-affine) sets of nodes members,
// filling the nodes to ~95 %, plus a core pod per node; with full, the
// CPU is full too, so every move tries preemption.
func bigSnapshot(nodes, pods int, full bool) nodeadm.Snapshot {
	var s nodeadm.Snapshot
	for i := range nodes {
		n := node(fmt.Sprintf("n%d", i), 4_000_000_000)
		n.Labels["portcullis.io/class"] = "home"
		s.Nodes = append(s.Nodes, n)
	}
	per := max(pods/nodes, 1)
	mem := int64(3_800_000_000 / per)
	cpu := int64(3900 / per)
	if full {
		cpu = 4000 / int64(per)
	}
	for i := range pods {
		class, prio := "portcullis-normal", 1000
		switch i % 4 {
		case 1:
			class, prio = "portcullis-high", 10000
		case 2:
			class, prio = "portcullis-low", 100
		}
		p := pod(fmt.Sprintf("app-%d", i), apps, s.Nodes[i%nodes].Name, class, prio, mem)
		p.Requests.CPUm = cpu
		p.Set = jsonstrict.Some(nodeadm.PodSet{Name: fmt.Sprintf("set-%d", i/nodes), Min: nodes / 2})
		p.SpreadHost = true
		p.AntiAffinityHost = (i/nodes)%2 == 1
		p.RequiredAffinity = [][]nodeadm.Expr{{{Key: "portcullis.io/class", Operator: "NotIn", Values: []string{"small"}}}}
		s.Pods = append(s.Pods, p)
	}
	for i := range nodes {
		s.Pods = append(s.Pods, pod(fmt.Sprintf("core-%d", i), "portcullis", s.Nodes[i].Name, "portcullis-core", 1000000, 100_000_000))
	}
	return s
}

// BenchmarkCheck50x2000 (C1): 50 nodes, 2,000 apps pods in spread sets,
// nodes full (every move tries preemption). Target: well under 1 s.
func BenchmarkCheck50x2000(b *testing.B) {
	s := bigSnapshot(50, 2000, true)
	b.ResetTimer()
	for b.Loop() {
		if _, err := Check(s); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCheckBounded (C1): the 50 × 2,000 check stays far below a second
// (the guard is generous for the race detector and slow machines).
func TestCheckBounded(t *testing.T) {
	for _, full := range []bool{false, true} {
		s := bigSnapshot(50, 2000, full)
		start := time.Now()
		r := check(t, s)
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("full %v: %s", full, d)
		}
		if len(r) != 50 {
			t.Fatalf("%d results", len(r))
		}
	}
}

// TestSetBelowMinimumCritical (M4): an apps critical set below its minimum
// is red too; members disagreeing on the minimum take the strictest.
func TestSetBelowMinimumCritical(t *testing.T) {
	a := inSet(pod("db-0", apps, "n1", "portcullis-critical", 100000, 300), "db", 1)
	b := inSet(pod("db-1", apps, "n2", "portcullis-critical", 100000, 300), "db", 2)
	s := nodeadm.Snapshot{Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000), node("n3", 4000)}, Pods: []nodeadm.Pod{a, b}}
	if r := check(t, s)[2]; r.Level != Green {
		t.Errorf("two of two: %+v", r)
	}
	s.Pods[0].Set.V.Min = 3
	if r := check(t, s)[2]; r.Level != Red || !slices.Equal(r.Lacking, []string{"portcullis-apps/db"}) {
		t.Errorf("below the strictest minimum: %+v", r)
	}
}

// TestLackingOnce: a pod and a set of one name are named once.
func TestLackingOnce(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 1000)},
		Pods: []nodeadm.Pod{
			pod("vault", "portcullis", "n1", "portcullis-core", 1000000, 2000),
			inSet(pod("vault-0", "portcullis", "n2", "portcullis-core", 1000000, 300), "vault", 2),
		},
	}
	if got := Explain(check(t, s)[0]); got != "if n1 fails, vault won't have room" {
		t.Errorf("%q", got)
	}
}

// TestDaemonSetNeverVictim: an apps DaemonSet pod is never evicted.
func TestDaemonSetNeverVictim(t *testing.T) {
	ds := pod("agent", apps, "n2", "portcullis-normal", 1000, 3000)
	ds.DaemonSet = true
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods:  []nodeadm.Pod{pod("hub", "portcullis", "n1", "portcullis-core", 1000000, 2000), ds},
	}
	if r := check(t, s)[0]; r.Level != Red || len(r.Evicted) != 0 {
		t.Errorf("%+v", r)
	}
}

// TestLargestFirst: at one priority, the largest request is placed first.
func TestLargestFirst(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 2000), node("n3", 1000)},
		Pods: []nodeadm.Pod{
			pod("small", "portcullis", "n1", "portcullis-core", 1000000, 1000),
			pod("large", "portcullis", "n1", "portcullis-core", 1000000, 2000),
		},
	}
	if r := check(t, s)[0]; r.Level != Green {
		t.Errorf("%+v", r)
	}
}
