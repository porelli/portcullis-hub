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
//   - only Ready, schedulable nodes take a pod (a node that is already
//     NotReady takes nothing, and its pods are not counted as running);
//   - taints NoSchedule and NoExecute against the pod's tolerations
//     (PreferNoSchedule is ignored), the small taint among them;
//   - required node affinity (terms ORed, expressions ANDed; In, NotIn,
//     Exists, DoesNotExist, Gt, Lt);
//   - a set's hostname anti-affinity (no two members on one node) and its
//     hostname DoNotSchedule spread, taken as maxSkew 1 over the Ready
//     nodes that pass the pod's required affinity (taints don't narrow
//     those domains: Kubernetes' default nodeTaintsPolicy Ignore);
//   - preemption: a pod that may preempt (not preemptionPolicy Never, not
//     low) may evict normal and low pods of the apps namespace only
//     (ruling I5), with a priority below its own, lowest priority first.
//
// Simplifications, on purpose: first fit in snapshot node order (no
// scoring); a pod is placed without eviction anywhere it can before any
// eviction is tried; victims are chosen greedily on the first node where
// they make room (no reprieve, no minimal-victims node choice, no
// PodDisruptionBudgets); evicted pods are not re-placed; filters are judged
// before the eviction. The builder's chaos test (ha_n_minus_1) compares it
// with the real scheduler.
package nminus1

import (
	"cmp"
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
	// critical set drops below its minimum.
	Red Level = "red"
)

// DefaultAppsNamespace is the apps namespace's default name
// (PORTCULLIS_APPS_NAMESPACE, contract §3.4).
const DefaultAppsNamespace = "portcullis-apps"

// Result is one node's outcome (the §20.7 JSON). Unplaced are the node's
// pods (any priority) that found no room; Evicted the pods elsewhere
// evicted to make room. Lacking are the pods behind the level (Explain's
// <x>); it isn't part of the JSON.
type Result struct {
	Node     string   `json:"node"`
	Level    Level    `json:"level"`
	Unplaced []string `json:"unplaced"`
	Evicted  []string `json:"evicted"`
	Lacking  []string `json:"-"`
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

// Check runs the N−1 check with the default apps namespace: one result per
// snapshot node, in snapshot order.
func Check(s nodeadm.Snapshot) []Result {
	return CheckApps(s, DefaultAppsNamespace)
}

// CheckApps is Check with the apps namespace given (the only namespace
// whose pods are ever evicted).
func CheckApps(s nodeadm.Snapshot, appsNamespace string) []Result {
	out := make([]Result, 0, len(s.Nodes))
	for i := range s.Nodes {
		out = append(out, simulate(&s, i, appsNamespace))
	}
	return out
}

type tier int

const (
	tierOther tier = iota // no Portcullis class: never matters, never a victim
	tierLow
	tierNormal
	tierHigh
	tierCritical
	tierCore
)

func tierOf(p *nodeadm.Pod) tier {
	switch p.PriorityClass {
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

// sim is one node's loss: where every pod runs afterwards.
type sim struct {
	s       *nodeadm.Snapshot
	apps    string
	alive   []int        // the remaining Ready nodes (indexes into s.Nodes)
	isAlive map[int]bool // the same, as a set
	byName  map[string]int
	at      map[int]int // pod index → node index, for pods running after the loss
	used    map[int]nodeadm.Resources
	evicted map[int]bool
}

func simulate(s *nodeadm.Snapshot, failed int, apps string) Result {
	m := &sim{s: s, apps: apps, isAlive: map[int]bool{}, byName: map[string]int{},
		at: map[int]int{}, used: map[int]nodeadm.Resources{}, evicted: map[int]bool{}}
	for i := range s.Nodes {
		m.byName[s.Nodes[i].Name] = i
		if i != failed && s.Nodes[i].Ready {
			m.alive = append(m.alive, i)
			m.isAlive[i] = true
		}
	}
	var moving []int
	for pi := range s.Pods {
		p := &s.Pods[pi]
		ni, ok := m.byName[p.Node]
		switch {
		case !ok:
		case ni == failed:
			if !p.DaemonSet {
				moving = append(moving, pi)
			}
		case m.isAlive[ni]:
			m.put(pi, ni)
		}
	}
	slices.SortStableFunc(moving, func(a, b int) int {
		pa, pb := &s.Pods[a], &s.Pods[b]
		return cmp.Or(cmp.Compare(pb.Priority, pa.Priority),
			cmp.Compare(pb.Requests.MemBytes, pa.Requests.MemBytes),
			cmp.Compare(pb.Requests.CPUm, pa.Requests.CPUm),
			cmp.Compare(pa.Name, pb.Name))
	})

	r := Result{Node: s.Nodes[failed].Name, Level: Green, Unplaced: []string{}, Evicted: []string{}}
	var red, yellow, unplaced []int
	for _, pi := range moving {
		placed, normalEvicted := m.place(pi)
		switch {
		case !placed:
			unplaced = append(unplaced, pi)
			r.Unplaced = append(r.Unplaced, s.Pods[pi].Name)
		case normalEvicted && tierOf(&s.Pods[pi]) == tierHigh:
			yellow = append(yellow, pi)
		}
	}
	for _, pi := range unplaced {
		p := &s.Pods[pi]
		switch tierOf(p) {
		case tierCore, tierCritical:
			if set := setOf(p); set != (setKey{}) && m.members(set) >= p.Set.V.Min {
				yellow = append(yellow, pi) // runs degraded (P7)
			} else {
				red = append(red, pi)
			}
		case tierHigh:
			yellow = append(yellow, pi) // an unplaceable high pod (Task 2 ruling)
		}
	}
	for pi := range m.evicted {
		r.Evicted = append(r.Evicted, s.Pods[pi].Name)
	}
	lacking := yellow
	switch {
	case len(red) > 0:
		r.Level, lacking = Red, red
	case len(yellow) > 0:
		r.Level = Yellow
	}
	for _, pi := range lacking {
		r.Lacking = append(r.Lacking, s.Pods[pi].Name)
	}
	slices.Sort(r.Unplaced)
	slices.Sort(r.Evicted)
	slices.Sort(r.Lacking)
	return r
}

func (m *sim) put(pi, ni int) {
	m.at[pi] = ni
	u, q := m.used[ni], m.s.Pods[pi].Requests
	m.used[ni] = nodeadm.Resources{CPUm: u.CPUm + q.CPUm, MemBytes: u.MemBytes + q.MemBytes}
}

func (m *sim) evict(pi int) {
	ni := m.at[pi]
	delete(m.at, pi)
	m.evicted[pi] = true
	u, q := m.used[ni], m.s.Pods[pi].Requests
	m.used[ni] = nodeadm.Resources{CPUm: u.CPUm - q.CPUm, MemBytes: u.MemBytes - q.MemBytes}
}

// fits: the pod's requests fit node ni with extra freed on top.
func (m *sim) fits(pi, ni int, freed nodeadm.Resources) bool {
	a, u, q := m.s.Nodes[ni].Allocatable, m.used[ni], m.s.Pods[pi].Requests
	return u.CPUm-freed.CPUm+q.CPUm <= a.CPUm && u.MemBytes-freed.MemBytes+q.MemBytes <= a.MemBytes
}

// place puts pod pi on the first candidate node with room, else (if it
// may preempt) on the first candidate where evicting victims makes room.
// normalEvicted: a normal pod was evicted for it.
func (m *sim) place(pi int) (placed, normalEvicted bool) {
	var cands []int
	for _, ni := range m.alive {
		if m.passes(pi, ni) {
			cands = append(cands, ni)
		}
	}
	for _, ni := range cands {
		if m.fits(pi, ni, nodeadm.Resources{}) {
			m.put(pi, ni)
			return true, false
		}
	}
	p := &m.s.Pods[pi]
	if p.PreemptionPolicy == "Never" || tierOf(p) <= tierLow {
		return false, false
	}
	for _, ni := range cands {
		victims, ok := m.victims(pi, ni)
		if !ok {
			continue
		}
		for _, v := range victims {
			normalEvicted = normalEvicted || tierOf(&m.s.Pods[v]) == tierNormal
			m.evict(v)
		}
		m.put(pi, ni)
		return true, normalEvicted
	}
	return false, false
}

// victims are the pods to evict on node ni for pod pi, lowest priority
// first (then the largest first), or false when evicting every allowed
// victim still leaves no room.
func (m *sim) victims(pi, ni int) ([]int, bool) {
	p := &m.s.Pods[pi]
	var allowed []int
	for vi, at := range m.at {
		v := &m.s.Pods[vi]
		t := tierOf(v)
		if at == ni && !v.DaemonSet && v.Namespace == m.apps && (t == tierNormal || t == tierLow) && v.Priority < p.Priority {
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
		freed = nodeadm.Resources{CPUm: freed.CPUm + q.CPUm, MemBytes: freed.MemBytes + q.MemBytes}
		if m.fits(pi, ni, freed) {
			return allowed[:i+1], true
		}
	}
	return nil, false
}

// passes: node ni takes pod pi by everything but room.
func (m *sim) passes(pi, ni int) bool {
	p, n := &m.s.Pods[pi], &m.s.Nodes[ni]
	if n.Unschedulable || !tolerates(p.Tolerations, n.Taints) || !affinityMatches(p.RequiredAffinity, n) {
		return false
	}
	if !p.Set.Valid {
		return true
	}
	set := setOf(p)
	if p.AntiAffinityHost && m.membersOn(set, ni) > 0 {
		return false
	}
	if p.SpreadHost {
		lowest := -1
		for _, d := range m.alive {
			if affinityMatches(p.RequiredAffinity, &m.s.Nodes[d]) {
				if c := m.membersOn(set, d); lowest < 0 || c < lowest {
					lowest = c
				}
			}
		}
		if m.membersOn(set, ni)+1-lowest > 1 {
			return false
		}
	}
	return true
}

// setKey names a set: its namespace and its name. A set named like a core
// set in the apps namespace is another set, and never changes the core
// set's members, anti-affinity, spread or minimum (Kubernetes' own
// selectors are namespace-scoped too). The snapshot carries no controller
// kind, so two controllers of one name in one namespace would be one set;
// only the chart creates the core namespace's controllers.
type setKey struct{ ns, name string }

// setOf is the pod's set (the zero key: none; no set has an empty name).
func setOf(p *nodeadm.Pod) setKey {
	if !p.Set.Valid || p.Set.V.Name == "" {
		return setKey{}
	}
	return setKey{p.Namespace, p.Set.V.Name}
}

func (m *sim) membersOn(set setKey, ni int) int {
	c := 0
	for pi, at := range m.at {
		if at == ni && setOf(&m.s.Pods[pi]) == set {
			c++
		}
	}
	return c
}

// members counts the set's pods running after the loss (on the remaining
// Ready nodes, placed ones included).
func (m *sim) members(set setKey) int {
	c := 0
	for pi := range m.at {
		if setOf(&m.s.Pods[pi]) == set {
			c++
		}
	}
	return c
}

// tolerates: every NoSchedule and NoExecute taint is tolerated.
func tolerates(tols []nodeadm.Toleration, taints []nodeadm.Taint) bool {
	for _, t := range taints {
		if t.Effect != "NoSchedule" && t.Effect != "NoExecute" {
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
func affinityMatches(terms [][]nodeadm.Expr, n *nodeadm.Node) bool {
	if len(terms) == 0 {
		return true
	}
	labels := n.Labels
	if _, ok := labels["kubernetes.io/hostname"]; !ok {
		labels = make(map[string]string, len(n.Labels)+1)
		for k, v := range n.Labels {
			labels[k] = v
		}
		labels["kubernetes.io/hostname"] = n.Name
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
