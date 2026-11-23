// Package nminus1 is the N−1 check (contract §20.7): for each node of a
// cluster snapshot (nodeadm GET /v1/cluster, §20.2), would that node's
// core, critical and high pods still find room on the remaining nodes,
// once normal and low pods are evicted for them?
//
// It is a pure function of the snapshot, and a documented approximation
// of the Kubernetes scheduler, not a scheduler. It honours exactly these
// rules, and nothing else:
//
//   - requests, CPU and memory (core pods request their measured peak plus
//     a margin, below their limits; app pods request = limit, §20.1, §3.4);
//     DaemonSet pods count where they run and are never moved;
//   - only Ready, schedulable nodes take a pod. The pods of nodes that are
//     already NotReady are placed first, onto the Ready nodes (the
//     baseline); each node's loss is then simulated on top of it;
//   - taints against the pod's tolerations: every effect but
//     PreferNoSchedule keeps out a pod that doesn't tolerate it (the small
//     taint among them);
//   - required node affinity (terms ORed, expressions ANDed; In, NotIn,
//     Exists, DoesNotExist, Gt, Lt);
//   - a set's hostname anti-affinity (no two members on one node) and its
//     hostname DoNotSchedule spread, taken as maxSkew 1. The spread's
//     domains are every node that passes the pod's required affinity,
//     whatever its taints, readiness or cordon (Kubernetes' defaults
//     nodeAffinityPolicy Honor, nodeTaintsPolicy Ignore), the lost node and
//     NotReady nodes among them at their current member count;
//   - preemption by numeric priority: a pod with preemptionPolicy
//     PreemptLowerPriority (never a portcullis-low pod) may evict normal and
//     low pods of the apps namespace only (ruling I5), with a priority below
//     its own, lowest priority first.
//
// Tiers (what an unplaced pod means) come from the priority class. Outside
// the apps namespace a pod without a Portcullis class (k3s's system-*
// pods, a pod with no class) counts as core (fail closed); an apps pod is
// at most critical (§20.6: an instance never takes core).
//
// Simplifications, on purpose: first fit in snapshot node order (no
// scoring); a pod is placed without eviction anywhere it can before any
// eviction is tried; victims are chosen greedily on the first node where
// they make room (no reprieve, no minimal-victims node choice, no
// PodDisruptionBudgets); evicted pods are not re-placed; filters are judged
// before the eviction; pods nodeadm doesn't list (Pending, unbound) are not
// seen. The builder's chaos test (ha_n_minus_1) compares it with the real
// scheduler.
package nminus1

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/nodeadm"
)

// Level is a node's N−1 level.
type Level string

const (
	// Green: everything that matters fits.
	Green Level = "green"
	// Yellow: a high pod fits only by evicting a normal pod, a high pod
	// can't be placed, or a set member can't be placed while its set keeps
	// its minimum (it runs degraded).
	Yellow Level = "yellow"
	// Red: a core or critical singleton can't be placed, or a core or
	// critical set is below its minimum.
	Red Level = "red"
	// Unknown is the callers' level when Check refuses the snapshot (a
	// malformed one): never a pass. Gates treat it as red, the doctor
	// raises its Problem. Check itself never returns it.
	Unknown Level = "unknown"
)

// Namespaces are the apps namespace (the only one whose pods are ever
// evicted; HUB_APPS_NAMESPACE) and the core namespace (whose pods the
// results name bare; every other pod is "<namespace>/<name>").
type Namespaces struct{ Apps, Core string }

// DefaultNamespaces are the chart's defaults.
var DefaultNamespaces = Namespaces{Apps: "portcullis-apps", Core: "portcullis"}

// Result is one node's outcome (the §20.7 JSON). Unplaced are the pods
// (any priority) that found no room: the lost node's and the baseline's
// (pods of nodes already NotReady); Evicted the pods evicted to make room.
// Pods are named bare in the core namespace, else "<namespace>/<name>".
// Lacking are the pods (or, for a set below its minimum with no pod
// unplaced, the set) behind the level, Explain's <x>; not in the JSON.
type Result struct {
	Node     string   `json:"node"`
	Level    Level    `json:"level"`
	Unplaced []string `json:"unplaced"`
	Evicted  []string `json:"evicted"`
	Lacking  []string `json:"-"`
	// QuorumHeld: a yellow result whose every reason is P7's: a core or
	// critical set member with no room while its set keeps its minimum
	// (Vault, Postgres and the Sentinels on three main servers: a working
	// majority, the member re-placed only when its node is back). Never set
	// on another yellow (a high pod unplaced, or placed only by evicting a
	// normal one), nor on green or red. Not in the JSON (§20.7's shape).
	QuorumHeld bool `json:"-"`
}

// Explain is the sentence of §20.6's 409 and the dialog: "if <node>
// fails, <x> won't have room" ("" for a green result).
func Explain(r Result) string {
	if r.Level == Green || r.Level == "" {
		return ""
	}
	x := r.Lacking
	if len(x) == 0 {
		x = r.Unplaced
	}
	if len(x) == 0 {
		x = r.Evicted
	}
	return "if " + r.Node + " fails, " + joinNames(x) + " won't have room"
}

func joinNames(x []string) string {
	switch len(x) {
	case 0:
		return "some pods"
	case 1:
		return x[0]
	}
	return strings.Join(x[:len(x)-1], ", ") + " and " + x[len(x)-1]
}

// Check runs the N−1 check with the default namespaces: one result per
// snapshot node, in snapshot order, or Validate's error.
func Check(s nodeadm.Snapshot) ([]Result, error) {
	return CheckIn(s, DefaultNamespaces)
}

// CheckIn is Check with the namespaces given.
func CheckIn(s nodeadm.Snapshot, ns Namespaces) ([]Result, error) {
	if ns.Apps == "" || ns.Core == "" {
		return nil, errors.New("nminus1: the apps and core namespaces are required")
	}
	if err := Validate(s); err != nil {
		return nil, err
	}
	m := newModel(&s, ns)
	base := m.baseline()
	out := make([]Result, 0, len(s.Nodes))
	for ni := range s.Nodes {
		st := base
		if m.ready[ni] {
			st = base.clone()
			m.lose(st, ni)
		}
		out = append(out, m.result(st, s.Nodes[ni].Name))
	}
	return out, nil
}

// Validate refuses a snapshot the check can't judge: no nodes, a repeated
// node or pod, a pod on an unknown node, a negative request or allocatable,
// an unknown taint effect, toleration, node-selector operator or
// preemption policy, a set without a name or with a minimum below 1.
func Validate(s nodeadm.Snapshot) error {
	bad := func(f string, a ...any) error {
		return fmt.Errorf("nminus1: malformed snapshot: "+f, a...)
	}
	if len(s.Nodes) == 0 {
		return bad("no nodes")
	}
	nodes := map[string]bool{}
	for _, n := range s.Nodes {
		switch {
		case n.Name == "":
			return bad("a node without a name")
		case nodes[n.Name]:
			return bad("node %s listed twice", n.Name)
		case n.Allocatable.CPUm < 0 || n.Allocatable.MemBytes < 0:
			return bad("node %s has a negative allocatable", n.Name)
		}
		nodes[n.Name] = true
		for _, t := range n.Taints {
			if !knownEffect(t.Effect) {
				return bad("node %s has a taint with effect %q", n.Name, t.Effect)
			}
		}
	}
	pods := map[[2]string]bool{}
	for _, p := range s.Pods {
		k := [2]string{p.Namespace, p.Name}
		switch {
		case p.Name == "" || p.Namespace == "":
			return bad("a pod without a name or namespace")
		case pods[k]:
			return bad("pod %s/%s listed twice", p.Namespace, p.Name)
		case !nodes[p.Node]:
			return bad("pod %s/%s is on unknown node %q", p.Namespace, p.Name, p.Node)
		case p.Requests.CPUm < 0 || p.Requests.MemBytes < 0:
			return bad("pod %s/%s has a negative request", p.Namespace, p.Name)
		case p.PreemptionPolicy != "PreemptLowerPriority" && p.PreemptionPolicy != "Never":
			return bad("pod %s/%s has preemption policy %q", p.Namespace, p.Name, p.PreemptionPolicy)
		case p.Set.Valid && (p.Set.V.Name == "" || p.Set.V.Min < 1):
			return bad("pod %s/%s has a set without a name or with a minimum below 1", p.Namespace, p.Name)
		}
		pods[k] = true
		for _, t := range p.Tolerations {
			if (t.Operator != "" && t.Operator != "Equal" && t.Operator != "Exists") || (t.Effect != "" && !knownEffect(t.Effect)) {
				return bad("pod %s/%s has a toleration %q %q", p.Namespace, p.Name, t.Operator, t.Effect)
			}
		}
		for _, term := range p.RequiredAffinity {
			for _, e := range term {
				if !validExpr(e) {
					return bad("pod %s/%s has a node-selector expression %q on %q", p.Namespace, p.Name, e.Operator, e.Key)
				}
			}
		}
	}
	return nil
}

func knownEffect(e string) bool {
	return e == "NoSchedule" || e == "PreferNoSchedule" || e == "NoExecute"
}

func validExpr(e nodeadm.Expr) bool {
	switch e.Operator {
	case "In", "NotIn":
		return len(e.Values) > 0
	case "Exists", "DoesNotExist":
		return len(e.Values) == 0
	case "Gt", "Lt":
		if len(e.Values) != 1 {
			return false
		}
		_, err := strconv.ParseInt(e.Values[0], 10, 64)
		return err == nil
	}
	return false
}

type tier int

const (
	tierOther tier = iota // an apps pod without a Portcullis class: never matters, never a victim
	tierLow
	tierNormal
	tierHigh
	tierCritical
	tierCore
)

func classTier(class string) tier {
	switch class {
	case "portcullis-core":
		return tierCore
	case "portcullis-critical":
		return tierCritical
	case "portcullis-high":
		return tierHigh
	case "portcullis-normal":
		return tierNormal
	case "portcullis-low":
		return tierLow
	}
	return tierOther
}

func tierOf(p *nodeadm.Pod, ns Namespaces) tier {
	t := classTier(p.PriorityClass)
	if p.Namespace == ns.Apps {
		return min(t, tierCritical) // never core (M6)
	}
	if t == tierOther {
		return tierCore // fail closed (I2)
	}
	return t
}

// model is what doesn't change between the losses: the snapshot, each
// pod's tier, set and display name, and which node each pod may use.
type model struct {
	s       *nodeadm.Snapshot
	ns      Namespaces
	nn      int
	ready   []bool
	tier    []tier
	set     []int // set index, -1: none
	display []string
	setName []string // display
	setMin  []int
	setTier []tier
	takes   []bool // [pod*nn+node]: schedulable, taints tolerated, affinity
	affine  []bool // [pod*nn+node]: affinity only (the spread domains)
}

// setKey names a set: its namespace and its name. A set named like a core
// set in the apps namespace is another set, and never changes the core
// set's members, anti-affinity, spread or minimum (Kubernetes' own
// selectors are namespace-scoped too). The snapshot carries no controller
// kind, so two controllers of one name in one namespace would be one set;
// only the chart creates the core namespace's controllers.
type setKey struct{ ns, name string }

func newModel(s *nodeadm.Snapshot, ns Namespaces) *model {
	nn, np := len(s.Nodes), len(s.Pods)
	m := &model{s: s, ns: ns, nn: nn, ready: make([]bool, nn), tier: make([]tier, np), set: make([]int, np),
		display: make([]string, np), takes: make([]bool, np*nn), affine: make([]bool, np*nn)}
	labels := make([]map[string]string, nn)
	for ni := range s.Nodes {
		n := &s.Nodes[ni]
		m.ready[ni] = n.Ready
		labels[ni] = n.Labels
		if _, ok := n.Labels["kubernetes.io/hostname"]; !ok {
			l := make(map[string]string, len(n.Labels)+1)
			for k, v := range n.Labels {
				l[k] = v
			}
			l["kubernetes.io/hostname"] = n.Name
			labels[ni] = l
		}
	}
	sets := map[setKey]int{}
	for pi := range s.Pods {
		p := &s.Pods[pi]
		m.tier[pi] = tierOf(p, ns)
		m.display[pi] = m.name(p.Namespace, p.Name)
		m.set[pi] = -1
		if p.Set.Valid {
			k := setKey{p.Namespace, p.Set.V.Name}
			si, ok := sets[k]
			if !ok {
				si = len(m.setName)
				sets[k] = si
				m.setName = append(m.setName, m.name(k.ns, k.name))
				m.setMin = append(m.setMin, 0)
				m.setTier = append(m.setTier, tierOther)
			}
			m.set[pi] = si
			m.setMin[si] = max(m.setMin[si], p.Set.V.Min) // members disagreeing: the strictest
			m.setTier[si] = max(m.setTier[si], m.tier[pi])
		}
		if p.DaemonSet {
			continue // never moved
		}
		for ni := range s.Nodes {
			aff := affinityMatches(p.RequiredAffinity, labels[ni])
			m.affine[pi*nn+ni] = aff
			m.takes[pi*nn+ni] = aff && !s.Nodes[ni].Unschedulable && tolerates(p.Tolerations, s.Nodes[ni].Taints)
		}
	}
	return m
}

func (m *model) name(ns, name string) string {
	if ns == m.ns.Core {
		return name
	}
	return ns + "/" + name
}

// state is where every pod runs in one scenario.
type state struct {
	at       []int   // pod → node, -1: not running
	perNode  [][]int // node → its running pods
	used     []nodeadm.Resources
	count    [][]int // set → node → running members
	total    []int   // set → running members
	alive    []bool  // nodes that take pods
	unplaced []int
	evicted  []int
	yellow   []int // high pods placed only by evicting a normal pod
}

func (st *state) clone() *state {
	c := &state{at: slices.Clone(st.at), perNode: make([][]int, len(st.perNode)), used: slices.Clone(st.used),
		count: make([][]int, len(st.count)), total: slices.Clone(st.total), alive: slices.Clone(st.alive),
		unplaced: slices.Clone(st.unplaced), evicted: slices.Clone(st.evicted), yellow: slices.Clone(st.yellow)}
	for i := range st.perNode {
		c.perNode[i] = slices.Clone(st.perNode[i])
	}
	for i := range st.count {
		c.count[i] = slices.Clone(st.count[i])
	}
	return c
}

func (m *model) put(st *state, pi, ni int) {
	st.at[pi] = ni
	st.perNode[ni] = append(st.perNode[ni], pi)
	q := m.s.Pods[pi].Requests
	st.used[ni].CPUm += q.CPUm
	st.used[ni].MemBytes += q.MemBytes
	if si := m.set[pi]; si >= 0 {
		st.count[si][ni]++
		st.total[si]++
	}
}

func (m *model) remove(st *state, pi int) {
	ni := st.at[pi]
	st.at[pi] = -1
	l := st.perNode[ni]
	i := slices.Index(l, pi)
	l[i] = l[len(l)-1]
	st.perNode[ni] = l[:len(l)-1]
	q := m.s.Pods[pi].Requests
	st.used[ni].CPUm -= q.CPUm
	st.used[ni].MemBytes -= q.MemBytes
	if si := m.set[pi]; si >= 0 {
		st.count[si][ni]--
		st.total[si]--
	}
}

// baseline: every pod of a Ready node runs where it is; the pods of
// NotReady nodes (but DaemonSet pods) are placed onto the Ready nodes.
func (m *model) baseline() *state {
	st := &state{at: make([]int, len(m.s.Pods)), perNode: make([][]int, m.nn), used: make([]nodeadm.Resources, m.nn),
		count: make([][]int, len(m.setName)), total: make([]int, len(m.setName)), alive: slices.Clone(m.ready)}
	for si := range st.count {
		st.count[si] = make([]int, m.nn)
	}
	idx := make(map[string]int, m.nn)
	for ni := range m.s.Nodes {
		idx[m.s.Nodes[ni].Name] = ni
	}
	var moving []int
	for pi := range m.s.Pods {
		st.at[pi] = -1
		p := &m.s.Pods[pi]
		switch ni := idx[p.Node]; {
		case m.ready[ni]:
			m.put(st, pi, ni)
		case !p.DaemonSet:
			moving = append(moving, pi)
		}
	}
	m.placeAll(st, moving)
	return st
}

// lose simulates node ni's loss on st: its pods (DaemonSet pods go with
// it) are placed elsewhere.
func (m *model) lose(st *state, ni int) {
	st.alive[ni] = false
	pods := slices.Clone(st.perNode[ni])
	var moving []int
	for _, pi := range pods {
		m.remove(st, pi)
		if !m.s.Pods[pi].DaemonSet {
			moving = append(moving, pi)
		}
	}
	m.placeAll(st, moving)
}

func (m *model) placeAll(st *state, moving []int) {
	slices.SortFunc(moving, func(a, b int) int {
		pa, pb := &m.s.Pods[a], &m.s.Pods[b]
		return cmp.Or(cmp.Compare(pb.Priority, pa.Priority),
			cmp.Compare(pb.Requests.MemBytes, pa.Requests.MemBytes),
			cmp.Compare(pb.Requests.CPUm, pa.Requests.CPUm),
			cmp.Compare(pa.Namespace, pb.Namespace),
			cmp.Compare(pa.Name, pb.Name))
	})
	for _, pi := range moving {
		placed, normalEvicted := m.place(st, pi)
		switch {
		case !placed:
			st.unplaced = append(st.unplaced, pi)
		case normalEvicted && m.tier[pi] == tierHigh:
			st.yellow = append(st.yellow, pi)
		}
	}
}

func (m *model) fits(st *state, pi, ni int, freed nodeadm.Resources) bool {
	a, u, q := m.s.Nodes[ni].Allocatable, st.used[ni], m.s.Pods[pi].Requests
	return u.CPUm-freed.CPUm+q.CPUm <= a.CPUm && u.MemBytes-freed.MemBytes+q.MemBytes <= a.MemBytes
}

// place puts pod pi on the first candidate node with room, else (if it
// may preempt) on the first candidate where evicting victims makes room.
// normalEvicted: a normal pod was evicted for it.
func (m *model) place(st *state, pi int) (placed, normalEvicted bool) {
	p := &m.s.Pods[pi]
	si := m.set[pi]
	anti := si >= 0 && p.AntiAffinityHost
	spread := si >= 0 && p.SpreadHost
	lowest := 0
	if spread {
		// The spread's global minimum, once per pod: every node passing the
		// affinity is a domain (S1).
		lowest = -1
		for ni := 0; ni < m.nn; ni++ {
			if m.affine[pi*m.nn+ni] {
				if c := st.count[si][ni]; lowest < 0 || c < lowest {
					lowest = c
				}
			}
		}
	}
	var cands []int
	for ni := 0; ni < m.nn; ni++ {
		if !st.alive[ni] || !m.takes[pi*m.nn+ni] {
			continue
		}
		if anti && st.count[si][ni] > 0 {
			continue
		}
		if spread && st.count[si][ni]+1-lowest > 1 {
			continue
		}
		if m.fits(st, pi, ni, nodeadm.Resources{}) {
			m.put(st, pi, ni)
			return true, false
		}
		cands = append(cands, ni)
	}
	if p.PreemptionPolicy != "PreemptLowerPriority" || p.PriorityClass == "portcullis-low" {
		return false, false
	}
	for _, ni := range cands {
		victims := m.victims(st, pi, ni)
		if victims == nil {
			continue
		}
		for _, v := range victims {
			normalEvicted = normalEvicted || m.tier[v] == tierNormal
			m.remove(st, v)
			st.evicted = append(st.evicted, v)
		}
		m.put(st, pi, ni)
		return true, normalEvicted
	}
	return false, false
}

// victims are the pods to evict on node ni for pod pi, lowest priority
// first (then the largest first), or nil when evicting every allowed
// victim still leaves no room.
func (m *model) victims(st *state, pi, ni int) []int {
	prio := m.s.Pods[pi].Priority
	var allowed []int
	for _, vi := range st.perNode[ni] {
		v := &m.s.Pods[vi]
		t := m.tier[vi]
		if !v.DaemonSet && v.Namespace == m.ns.Apps && (t == tierNormal || t == tierLow) && v.Priority < prio {
			allowed = append(allowed, vi)
		}
	}
	slices.SortFunc(allowed, func(a, b int) int {
		va, vb := &m.s.Pods[a], &m.s.Pods[b]
		return cmp.Or(cmp.Compare(va.Priority, vb.Priority),
			cmp.Compare(vb.Requests.MemBytes, va.Requests.MemBytes),
			cmp.Compare(vb.Requests.CPUm, va.Requests.CPUm),
			cmp.Compare(va.Name, vb.Name))
	})
	var freed nodeadm.Resources
	for i, vi := range allowed {
		q := m.s.Pods[vi].Requests
		freed.CPUm += q.CPUm
		freed.MemBytes += q.MemBytes
		if m.fits(st, pi, ni, freed) {
			return allowed[:i+1]
		}
	}
	return nil
}

// result judges a scenario's end state.
func (m *model) result(st *state, node string) Result {
	r := Result{Node: node, Level: Green, Unplaced: []string{}, Evicted: []string{}}
	var red, yellow []string
	other := false // a yellow reason that isn't P7's
	redSet := make([]bool, len(m.setName))
	for _, pi := range st.unplaced {
		r.Unplaced = append(r.Unplaced, m.display[pi])
		si := m.set[pi]
		switch m.tier[pi] {
		case tierCore, tierCritical:
			if si >= 0 && st.total[si] >= m.setMin[si] {
				yellow = append(yellow, m.display[pi]) // runs degraded (P7)
			} else {
				red = append(red, m.display[pi])
				if si >= 0 {
					redSet[si] = true
				}
			}
		case tierHigh:
			yellow = append(yellow, m.display[pi]) // an unplaceable high pod (Task 2 ruling)
			other = true
		}
	}
	for _, pi := range st.yellow {
		yellow = append(yellow, m.display[pi])
		other = true
	}
	// Every core or critical set below its minimum, unplaced members or
	// not (M4).
	for si := range m.setName {
		if m.setTier[si] >= tierCritical && st.total[si] < m.setMin[si] && !redSet[si] {
			red = append(red, m.setName[si])
		}
	}
	for _, pi := range st.evicted {
		r.Evicted = append(r.Evicted, m.display[pi])
	}
	switch {
	case len(red) > 0:
		r.Level, r.Lacking = Red, red
	case len(yellow) > 0:
		r.Level, r.Lacking, r.QuorumHeld = Yellow, yellow, !other
	}
	slices.Sort(r.Unplaced)
	slices.Sort(r.Evicted)
	slices.Sort(r.Lacking)
	r.Lacking = slices.Compact(r.Lacking)
	return r
}

// tolerates: every taint but PreferNoSchedule is tolerated.
func tolerates(tols []nodeadm.Toleration, taints []nodeadm.Taint) bool {
	for _, t := range taints {
		if t.Effect == "PreferNoSchedule" {
			continue
		}
		if !slices.ContainsFunc(tols, func(tol nodeadm.Toleration) bool { return toleratesTaint(tol, t) }) {
			return false
		}
	}
	return true
}

// toleratesTaint is Kubernetes' Toleration.ToleratesTaint.
func toleratesTaint(tol nodeadm.Toleration, t nodeadm.Taint) bool {
	if tol.Effect != "" && tol.Effect != t.Effect {
		return false
	}
	if tol.Key != "" && tol.Key != t.Key {
		return false
	}
	switch tol.Operator {
	case "Exists":
		return true
	case "", "Equal":
		return tol.Value == t.Value
	}
	return false
}

// affinityMatches: no terms, or one term whose expressions all match.
func affinityMatches(terms [][]nodeadm.Expr, labels map[string]string) bool {
	if len(terms) == 0 {
		return true
	}
	for _, term := range terms {
		if len(term) > 0 && !slices.ContainsFunc(term, func(e nodeadm.Expr) bool { return !exprMatches(e, labels) }) {
			return true
		}
	}
	return false
}

// exprMatches is one node-selector requirement.
func exprMatches(e nodeadm.Expr, labels map[string]string) bool {
	v, has := labels[e.Key]
	switch e.Operator {
	case "In":
		return has && slices.Contains(e.Values, v)
	case "NotIn":
		return !has || !slices.Contains(e.Values, v)
	case "Exists":
		return has
	case "DoesNotExist":
		return !has
	case "Gt", "Lt":
		if !has || len(e.Values) != 1 {
			return false
		}
		a, err1 := strconv.ParseInt(v, 10, 64)
		b, err2 := strconv.ParseInt(e.Values[0], 10, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		if e.Operator == "Gt" {
			return a > b
		}
		return a < b
	}
	return false
}
