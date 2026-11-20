package nminus1

import (
	"os"
	"slices"
	"testing"

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
// and the unplaced and evicted pods (order-insensitive).
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
			got := Check(v.Snapshot)
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
			}
		})
	}
}

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
	r := Check(s)
	if r[0].Level != Red || !slices.Equal(r[0].Unplaced, []string{"hub"}) || len(r[0].Evicted) != 0 {
		t.Errorf("outside apps: %+v", r[0])
	}
	s.Pods[1].Namespace = DefaultAppsNamespace
	if r := Check(s); r[0].Level != Green || !slices.Equal(r[0].Evicted, []string{"odd"}) {
		t.Errorf("inside apps: %+v", r[0])
	}
	if r := CheckApps(s, "apps-elsewhere"); r[0].Level != Red {
		t.Errorf("another apps namespace: %+v", r[0])
	}
}

// TestHighSetMemberIsYellow: a high pod of a set below its minimum is
// still at most yellow (red is only for core and critical).
func TestHighSetMemberIsYellow(t *testing.T) {
	a := pod("a-0", DefaultAppsNamespace, "n1", "portcullis-high", 10000, 3000)
	b := pod("a-1", DefaultAppsNamespace, "n2", "portcullis-high", 10000, 3000)
	for _, p := range []*nodeadm.Pod{&a, &b} {
		p.AntiAffinityHost = true
		p.Set = jsonstrict.Some(nodeadm.PodSet{Name: "a", Min: 2})
	}
	r := Check(nodeadm.Snapshot{Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)}, Pods: []nodeadm.Pod{a, b}})
	if r[0].Level != Yellow || !slices.Equal(r[0].Unplaced, []string{"a-0"}) {
		t.Errorf("%+v", r[0])
	}
}

// TestNormalSetBelowMinimumIsGreen: normal and low pods never raise the
// level, in a set or not.
func TestNormalSetBelowMinimumIsGreen(t *testing.T) {
	a := pod("a-0", DefaultAppsNamespace, "n1", "portcullis-normal", 1000, 3000)
	b := pod("a-1", DefaultAppsNamespace, "n2", "portcullis-normal", 1000, 3000)
	for _, p := range []*nodeadm.Pod{&a, &b} {
		p.AntiAffinityHost = true
		p.Set = jsonstrict.Some(nodeadm.PodSet{Name: "a", Min: 2})
	}
	r := Check(nodeadm.Snapshot{Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)}, Pods: []nodeadm.Pod{a, b}})
	if r[0].Level != Green || !slices.Equal(r[0].Unplaced, []string{"a-0"}) {
		t.Errorf("%+v", r[0])
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
			pod("app-high", DefaultAppsNamespace, "n1", "portcullis-high", 10000, 2000),
			pod("app-norm", DefaultAppsNamespace, "n2", "portcullis-normal", 1000, 3000),
		},
	}
	if got := Explain(Check(s)[0]); got != "if n1 fails, app-high won't have room" {
		t.Errorf("%q", got)
	}
}

// TestPriorityOrder: the failed node's pods are placed highest priority
// first, so a core pod takes the only room before a high one.
func TestPriorityOrder(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods: []nodeadm.Pod{
			pod("app-high", DefaultAppsNamespace, "n1", "portcullis-high", 10000, 2000),
			pod("hub", "portcullis", "n1", "portcullis-core", 1000000, 1500),
			pod("fill", "portcullis", "n2", "portcullis-core", 1000000, 2000),
		},
	}
	if r := Check(s)[0]; r.Level != Yellow || !slices.Equal(r.Unplaced, []string{"app-high"}) {
		t.Errorf("%+v", r)
	}
}

// TestPreemptionRules: who may evict whom (contract §20.7 step 3).
func TestPreemptionRules(t *testing.T) {
	run := func(mover, victim nodeadm.Pod) Result {
		return Check(nodeadm.Snapshot{
			Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
			Pods:  []nodeadm.Pod{mover, victim},
		})[0]
	}
	norm := pod("norm", DefaultAppsNamespace, "n1", "portcullis-normal", 1000, 2000)
	normNever := norm
	normNever.PreemptionPolicy = "Never"
	lowPreempting := pod("low", DefaultAppsNamespace, "n1", "portcullis-low", 100, 2000)
	lowPreempting.PreemptionPolicy = "PreemptLowerPriority"
	lowerLow := pod("lower", DefaultAppsNamespace, "n2", "portcullis-low", 50, 3000)
	equalNorm := pod("peer", DefaultAppsNamespace, "n2", "portcullis-normal", 1000, 3000)
	for name, c := range map[string]struct {
		mover, victim nodeadm.Pod
		evicts        bool
	}{
		"normal evicts a lower low":                   {norm, lowerLow, true},
		"preemptionPolicy Never never evicts":         {normNever, lowerLow, false},
		"a low pod never evicts, whatever its policy": {lowPreempting, lowerLow, false},
		"never a victim at the pod's own priority":    {norm, equalNorm, false},
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
			pod("norm", DefaultAppsNamespace, "n2", "portcullis-normal", 1000, 2000),
			pod("low", DefaultAppsNamespace, "n2", "portcullis-low", 100, 1500),
		},
	}
	if r := Check(s)[0]; r.Level != Green || !slices.Equal(r.Evicted, []string{"low"}) {
		t.Errorf("%+v", r)
	}
}

// TestTolerations: Kubernetes' toleration matching.
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
}

// TestHostnameWithoutLabel: a hostname term matches the node's name when
// the snapshot carries no hostname label.
func TestHostnameWithoutLabel(t *testing.T) {
	n := nodeadm.Node{Name: "n3", Labels: map[string]string{}}
	terms := [][]nodeadm.Expr{{{Key: "kubernetes.io/hostname", Operator: "In", Values: []string{"n3"}}}}
	if !affinityMatches(terms, &n) {
		t.Error("no match")
	}
}

// TestExplainNamesRedOnly: a red result names the core and critical pods,
// not the yellow ones.
func TestExplainNamesRedOnly(t *testing.T) {
	s := nodeadm.Snapshot{
		Nodes: []nodeadm.Node{node("n1", 4000), node("n2", 4000)},
		Pods: []nodeadm.Pod{
			pod("hub", "portcullis", "n1", "portcullis-core", 1000000, 3000),
			pod("app-high", DefaultAppsNamespace, "n1", "portcullis-high", 10000, 3000),
			pod("fill", "portcullis", "n2", "portcullis-core", 1000000, 2000),
		},
	}
	if got := Explain(Check(s)[0]); got != "if n1 fails, hub won't have room" {
		t.Errorf("%q", got)
	}
}
