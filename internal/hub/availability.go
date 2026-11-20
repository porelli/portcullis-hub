package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/nminus1"
	"github.com/portcullis/hub/internal/nodeadm"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/runtime/kube"
	"github.com/portcullis/hub/internal/settings"
	"github.com/portcullis/hub/internal/state"
)

// Instance availability (contract §20.6): an instance's priority and
// Runs on choice, Kubernetes only. A raise to critical or high runs the
// N−1 check (§20.7) first; a yellow, red or unknown node refuses it
// (409) unless the admin confirms.

// AvailabilityNode is one node of the GET's node list.
type AvailabilityNode struct {
	Name  string `json:"name"`
	Class string `json:"class"`
	Site  string `json:"site"`
	Small bool   `json:"small"`
}

// AvailabilityView is GET /api/instances/{id}/availability.
type AvailabilityView struct {
	Priority string             `json:"priority"`
	RunsOn   state.RunsOn       `json:"runs_on"`
	Nodes    []AvailabilityNode `json:"nodes"`
	NMinus1  []nminus1.Result   `json:"n_minus_1"`
}

// NMinus1Refusal is the 409 of a raise N−1 judges yellow, red or
// unknown: its sentence and the per-node results.
type NMinus1Refusal struct {
	Msg     string
	Results []nminus1.Result
}

func (e *NMinus1Refusal) Error() string { return e.Msg }

// Unwrap is the refusal as a 409 (the audit's "refused", the routes'
// status).
func (e *NMinus1Refusal) Unwrap() error { return &StatusError{Status: 409, Err: errors.New(e.Msg)} }

// priorityValues are the PriorityClass values (contract §20.1).
var priorityValues = map[string]int{
	runtime.PriorityCritical: 100000, runtime.PriorityHigh: 10000, runtime.PriorityNormal: 1000, runtime.PriorityLow: 100,
}

// AvailabilityOn refuses (409) availability off Kubernetes.
func (h *Hub) AvailabilityOn() error {
	if !h.kubeOn() {
		return statusErr(409, "%s", state.ErrTextNeedsKube)
	}
	return nil
}

// nminusNamespaces are the N−1 check's namespaces (the chart's defaults
// when unset).
func (h *Hub) nminusNamespaces() nminus1.Namespaces {
	ns := nminus1.DefaultNamespaces
	if h.cfg.AppsNamespace != "" {
		ns.Apps = h.cfg.AppsNamespace
	}
	if h.cfg.CoreNamespace != "" {
		ns.Core = h.cfg.CoreNamespace
	}
	return ns
}

// availabilitySnapshot reads nodeadm's snapshot (the node list, the
// small nodes and the N−1 input).
func (h *Hub) availabilitySnapshot(ctx context.Context) (nodeadm.Snapshot, error) {
	api, err := h.nodeadmAPI(ctx)
	if err != nil {
		return nodeadm.Snapshot{}, err
	}
	snap, err := h.clusterSnapshot(ctx, api)
	if err != nil {
		return snap, nodeadmErr(err)
	}
	return snap, nil
}

func isSmall(n *nodeadm.Node) bool { return n.Labels[nodeadm.LabelClass] == kube.ClassSmall }

// checkN1 is the N−1 check as callers gate it: an error is one result
// per node at the level unknown, with the error's text.
func (h *Hub) checkN1(s nodeadm.Snapshot) ([]nminus1.Result, string) {
	res, err := nminus1.CheckIn(s, h.nminusNamespaces())
	if err != nil {
		return unknownResults(s), "the N−1 check can't judge the cluster: " + clipRunes(err.Error(), 300)
	}
	return wireResults(res), ""
}

// wireResults gives every result non-nil lists (JSON [] rather than null).
func wireResults(res []nminus1.Result) []nminus1.Result {
	if res == nil {
		return []nminus1.Result{}
	}
	for i := range res {
		if res[i].Unplaced == nil {
			res[i].Unplaced = []string{}
		}
		if res[i].Evicted == nil {
			res[i].Evicted = []string{}
		}
	}
	return res
}

// availabilityOf is id's stored availability (nil = the defaults) and
// whether the instance exists.
func (h *Hub) availabilityOf(id string) (*state.Availability, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.findLocked(id) == nil {
		return nil, false
	}
	e, ok := h.st.Instances[id]
	if !ok || e.Availability == nil {
		return nil, true
	}
	a := *e.Availability
	a.RunsOn.Nodes = slices.Clone(a.RunsOn.Nodes)
	return &a, true
}

// view is the GET's answer for a over snap.
func (h *Hub) availabilityView(a *state.Availability, snap nodeadm.Snapshot, n1 []nminus1.Result) *AvailabilityView {
	v := &AvailabilityView{Priority: a.PriorityOrDefault(), RunsOn: state.RunsOn{Mode: a.ModeOrDefault()}, Nodes: []AvailabilityNode{}, NMinus1: n1}
	if a != nil {
		v.RunsOn.Class, v.RunsOn.Site, v.RunsOn.Nodes = a.RunsOn.Class, a.RunsOn.Site, a.RunsOn.Nodes
	}
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		v.Nodes = append(v.Nodes, AvailabilityNode{Name: n.Name, Class: n.Labels[nodeadm.LabelClass], Site: n.Labels[nodeadm.LabelSite], Small: isSmall(n)})
	}
	return v
}

// InstanceAvailability is GET /api/instances/{id}/availability: the
// choice, the cluster's nodes and the current N−1 result.
func (h *Hub) InstanceAvailability(ctx context.Context, id string) (*AvailabilityView, error) {
	if err := h.AvailabilityOn(); err != nil {
		return nil, err
	}
	a, ok := h.availabilityOf(id)
	if !ok {
		return nil, statusErr(404, "instance not found: %s", id)
	}
	snap, err := h.availabilitySnapshot(ctx)
	if err != nil {
		return nil, err
	}
	n1, _ := h.checkN1(snap)
	return h.availabilityView(a, snap, n1), nil
}

// SetAvailability is PUT /api/instances/{id}/availability: a checked,
// N−1-gated (a raise to critical or high) change, saved, audited
// instance.availability, and an enabled instance restarts.
func (h *Hub) SetAvailability(ctx context.Context, id string, want state.Availability, confirm bool, actor directory.Actor) (v *AvailabilityView, err error) {
	if err := h.AvailabilityOn(); err != nil {
		return nil, err
	}
	detail := "refused"
	defer func() {
		var se *StatusError
		if detail == "" || errors.As(err, &se) && se.Status == 404 {
			return
		}
		h.auditOp(actor, "instance.availability", id, detail, err)
	}()
	if strings.TrimSpace(actor.User) == "" {
		return nil, statusErr(400, "no signed-in user to audit the change as")
	}
	if err := want.Check(); err != nil {
		return nil, statusErr(400, "%v", err)
	}
	if want.RunsOn.Nodes != nil {
		want.RunsOn.Nodes = slices.Sorted(slices.Values(want.RunsOn.Nodes))
	}
	if _, ok := h.availabilityOf(id); !ok {
		return nil, statusErr(404, "instance not found: %s", id)
	}
	unlock, err := h.lockApp(id)
	if err != nil {
		return nil, h.busyErr(id, err)
	}
	defer unlock()
	// One Hub-wide lock around the check and the save (after the
	// instance's: lockApp is always taken first): two raises are never
	// judged without each other.
	h.avail.Lock()
	defer h.avail.Unlock()
	old, ok := h.availabilityOf(id)
	if !ok {
		return nil, statusErr(404, "instance not found: %s", id)
	}
	snap, err := h.availabilitySnapshot(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := runsOnSmall(want.RunsOn, snap); err != nil {
		return nil, err
	}
	// The gate: the result is critical or high and the priority or the
	// placement changes. N−1 runs first, on the snapshot with every
	// instance's pods as state says they run, this one as want.
	n1Note := ""
	var n1 []nminus1.Result
	if n1Gated(old, want) {
		sim, serr := h.simulateCluster(ctx, snap, id, want)
		var why string
		if serr != nil {
			n1, why = unknownResults(snap), "the N−1 check can't model the cluster: "+clipRunes(serr.Error(), 300)
		} else {
			n1, why = h.checkN1(sim)
			n1 = dropUnstarted(n1)
		}
		if msg, level := n1Verdict(n1, why); msg != "" {
			// An AI never overrides a red or unknown result; a yellow
			// one only with confirm_n_minus_1 (the tool asks the person
			// in the browser then).
			overridable := confirm && (actor.Via == "" || level == string(nminus1.Yellow))
			if !overridable {
				detail = "priority=" + want.Priority + " n_minus_1=" + level
				return nil, &NMinus1Refusal{Msg: msg, Results: n1}
			}
			n1Note = " n_minus_1=" + level + " confirmed"
		}
	}
	h.mu.Lock()
	live := h.findLocked(id)
	if live == nil {
		h.mu.Unlock()
		return nil, statusErr(404, "instance not found: %s", id)
	}
	if err := h.pendingLocked(id); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	e, had := h.st.Instances[id]
	if _, serr := os.Stat(h.envPath(id)); !had && !h.st.IsEnabled(id) && serr != nil {
		h.mu.Unlock()
		return nil, statusErr(404, "instance %s doesn't exist yet: create the instance first", id)
	}
	var next *state.Availability
	if !want.IsDefault() {
		w := want
		next = &w
	}
	if availabilityEqual(e.Availability, next) {
		h.mu.Unlock()
		detail = ""
		return h.availabilityView(next, snap, n1OrCurrent(h, n1, snap)), nil
	}
	prev := e
	if !had {
		e = state.Instance{ID: id, Template: live.TemplateID}
	}
	e.Availability = next
	if next == nil && entryHoldsNothing(e) {
		delete(h.st.Instances, id)
	} else {
		h.st.Instances[id] = e
	}
	if serr := h.st.Save(h.statePath()); serr != nil {
		if had {
			h.st.Instances[id] = prev
		} else {
			delete(h.st.Instances, id)
		}
		h.mu.Unlock()
		return nil, statusErr(500, "saving the availability failed: %v", serr)
	}
	enabled := h.st.IsEnabled(id) && !h.instanceBusyLocked(id)
	h.mu.Unlock()
	detail = availabilityDetail(want) + n1Note
	if enabled {
		// The pods take the new class and affinity at the restart.
		h.queueDelivery(id, TriggerSave, settings.EffectRestart, 0)
	}
	return h.availabilityView(next, snap, n1OrCurrent(h, n1, snap)), nil
}

// n1OrCurrent is the raise's result, else the current check's.
func n1OrCurrent(h *Hub, n1 []nminus1.Result, snap nodeadm.Snapshot) []nminus1.Result {
	if n1 != nil {
		return n1
	}
	r, _ := h.checkN1(snap)
	return r
}

// n1Verdict is the 409's sentence and the worst level ("" = green): the
// first unknown, else red, else yellow node's explanation.
func n1Verdict(res []nminus1.Result, why string) (string, string) {
	if why != "" {
		return why, string(nminus1.Unknown)
	}
	for _, lv := range []nminus1.Level{nminus1.Unknown, nminus1.Red, nminus1.Yellow} {
		for _, r := range res {
			if r.Level == lv {
				return nminus1.Explain(r), string(lv)
			}
		}
	}
	return "", ""
}

func availabilityEqual(a, b *state.Availability) bool {
	if a.IsDefault() || b.IsDefault() {
		return a.IsDefault() && b.IsDefault()
	}
	return a.Priority == b.Priority && a.RunsOn.Mode == b.RunsOn.Mode && a.RunsOn.Class == b.RunsOn.Class &&
		a.RunsOn.Site == b.RunsOn.Site && slices.Equal(a.RunsOn.Nodes, b.RunsOn.Nodes)
}

// availabilityDetail is the audit detail of a saved choice.
func availabilityDetail(a state.Availability) string {
	d := "priority=" + a.Priority + " runs_on=" + a.RunsOn.Mode
	switch {
	case a.RunsOn.Class != "":
		d += " class=" + a.RunsOn.Class
	case a.RunsOn.Site != "":
		d += " site=" + a.RunsOn.Site
	case len(a.RunsOn.Nodes) > 0:
		d += " nodes=" + strings.Join(a.RunsOn.Nodes, ",")
	}
	return d
}

// runsOnSmall checks r's nodes against snap: every node known (400
// unknown node <name>), no small node in a prefer choice; it answers the
// small nodes an only choice names.
func runsOnSmall(r state.RunsOn, snap nodeadm.Snapshot) ([]string, error) {
	if r.Mode == runtime.RunsOnPrefer && r.Site != "" && !slices.ContainsFunc(snap.Nodes, func(n nodeadm.Node) bool { return n.Labels[nodeadm.LabelSite] == r.Site }) {
		return nil, statusErr(400, state.ErrTextUnknownSiteF, r.Site)
	}
	var small []string
	for _, name := range r.Nodes {
		n := snap.Node(name)
		if n == nil {
			return nil, statusErr(400, state.ErrTextUnknownNodeF, name)
		}
		if isSmall(n) {
			if r.Mode == runtime.RunsOnPrefer {
				return nil, statusErr(400, "%s", state.ErrTextSmallPrefer)
			}
			small = append(small, name)
		}
	}
	return small, nil
}

// instancePod: pod p of the snapshot is one of instance id's (the
// translator names its objects "<instance>--<service>"; another
// instance whose id extends id's with "--" keeps its own pods).
func instancePod(p *nodeadm.Pod, apps, id string, ids []string) bool {
	if p.Namespace != apps || !strings.HasPrefix(p.Name, id+"--") {
		return false
	}
	for _, o := range ids {
		if o != id && strings.HasPrefix(o, id+"--") && strings.HasPrefix(p.Name, o+"--") {
			return false
		}
	}
	return true
}

// unstartedNode holds the modelled pods of instances that have no live
// pods (a NotReady node: the check's baseline places them first, so a
// pod with no room even now is unplaced in every node's result). Its own
// result is dropped.
const unstartedNode = "portcullis-n1-unstarted"

// n1Gated: the change is judged by N−1 — the resulting priority is
// critical or high and the priority or the placement changes.
func n1Gated(old *state.Availability, want state.Availability) bool {
	if want.Priority != runtime.PriorityCritical && want.Priority != runtime.PriorityHigh {
		return false
	}
	if old.PriorityOrDefault() != want.Priority || old.ModeOrDefault() != want.RunsOn.Mode {
		return true
	}
	if old == nil {
		return want.RunsOn.Class != "" || want.RunsOn.Site != "" || len(want.RunsOn.Nodes) > 0
	}
	return old.RunsOn.Class != want.RunsOn.Class || old.RunsOn.Site != want.RunsOn.Site || !slices.Equal(old.RunsOn.Nodes, want.RunsOn.Nodes)
}

// unknownResults: every node at the level unknown.
func unknownResults(s nodeadm.Snapshot) []nminus1.Result {
	res := make([]nminus1.Result, 0, len(s.Nodes))
	for _, n := range s.Nodes {
		if n.Name != unstartedNode {
			res = append(res, nminus1.Result{Node: n.Name, Level: nminus1.Unknown})
		}
	}
	return wireResults(res)
}

// dropUnstarted removes the modelling node's own result.
func dropUnstarted(res []nminus1.Result) []nminus1.Result {
	return slices.DeleteFunc(res, func(r nminus1.Result) bool { return r.Node == unstartedNode })
}

// placement is an availability's required node affinity and whether its
// pods tolerate the small taint (§20.6, as the translator renders it).
func placementOf(a *state.Availability, snap nodeadm.Snapshot) ([][]nodeadm.Expr, bool) {
	notSmall := nodeadm.Expr{Key: kube.LabelNodeClass, Operator: "NotIn", Values: []string{kube.ClassSmall}}
	if a.ModeOrDefault() != runtime.RunsOnOnly {
		return [][]nodeadm.Expr{{notSmall}}, false
	}
	var big, small []string
	for _, name := range a.RunsOn.Nodes {
		if n := snap.Node(name); n != nil && isSmall(n) {
			small = append(small, name)
		} else {
			big = append(big, name)
		}
	}
	var terms [][]nodeadm.Expr
	if len(big) > 0 {
		terms = append(terms, []nodeadm.Expr{{Key: kube.LabelHostname, Operator: "In", Values: big}, notSmall})
	}
	if len(small) > 0 {
		terms = append(terms, []nodeadm.Expr{{Key: kube.LabelHostname, Operator: "In", Values: small},
			{Key: kube.LabelNodeClass, Operator: "In", Values: []string{kube.ClassSmall}}})
	}
	return terms, len(small) > 0
}

// simInstance is one instance as the model runs it.
type simInstance struct {
	id      string
	a       *state.Availability
	enabled bool
}

// simulateCluster is snap as state says the apps run, with id at want:
// every instance's live pods re-classed to its stored availability (its
// priority class, value, preemption, Runs on affinity and the small
// toleration); id's pods, and those of an enabled critical or high
// instance, modelled from the translator's output when none is live
// (on unstartedNode).
func (h *Hub) simulateCluster(ctx context.Context, snap nodeadm.Snapshot, id string, want state.Availability) (nodeadm.Snapshot, error) {
	h.mu.RLock()
	insts := map[string]*simInstance{}
	for k, e := range h.st.Instances {
		insts[k] = &simInstance{id: k, a: e.Availability, enabled: h.st.IsEnabled(k)}
	}
	for _, k := range h.st.Enabled {
		if insts[k] == nil {
			insts[k] = &simInstance{id: k, enabled: true}
		}
	}
	h.mu.RUnlock()
	w := want
	if insts[id] == nil {
		insts[id] = &simInstance{id: id}
	}
	insts[id].a = &w
	ids := slices.Sorted(maps.Keys(insts))
	apps := h.nminusNamespaces().Apps
	out := snap
	out.Nodes = slices.Clone(snap.Nodes)
	out.Pods = slices.Clone(snap.Pods)
	// Instances without a live pod: the translator's pods.
	var modelled []nodeadm.Pod
	for _, k := range ids {
		in := insts[k]
		pr := in.a.PriorityOrDefault()
		if k != id && !(in.enabled && (pr == runtime.PriorityCritical || pr == runtime.PriorityHigh)) {
			continue
		}
		if slices.ContainsFunc(snap.Pods, func(p nodeadm.Pod) bool { return instancePod(&p, apps, k, ids) }) {
			continue
		}
		shapes, err := h.instancePodShapes(ctx, k)
		if err != nil {
			return out, fmt.Errorf("%s's pods: %w", k, err)
		}
		for _, sh := range shapes {
			for i := range sh.Replicas {
				modelled = append(modelled, nodeadm.Pod{Name: fmt.Sprintf("%s-unstarted-%d", sh.Workload, i), Namespace: apps, Node: unstartedNode,
					Requests: nodeadm.Resources{CPUm: sh.CPUm, MemBytes: sh.MemBytes}})
			}
		}
	}
	if len(modelled) > 0 {
		out.Nodes = append(out.Nodes, nodeadm.Node{Name: unstartedNode, Ready: false, Labels: map[string]string{}})
		out.Pods = append(out.Pods, modelled...)
	}
	for i := range out.Pods {
		p := &out.Pods[i]
		if p.DaemonSet || p.Namespace != apps {
			continue
		}
		var in *simInstance
		for _, k := range ids {
			if instancePod(p, apps, k, ids) {
				in = insts[k]
				break
			}
		}
		if in == nil {
			continue
		}
		pr := in.a.PriorityOrDefault()
		p.PriorityClass = kube.PriorityClassName(pr)
		p.Priority = priorityValues[pr]
		p.PreemptionPolicy = "PreemptLowerPriority"
		if pr == runtime.PriorityLow {
			p.PreemptionPolicy = "Never"
		}
		terms, tolerate := placementOf(in.a, snap)
		p.RequiredAffinity = terms
		var tol []nodeadm.Toleration
		for _, t := range p.Tolerations {
			if t.Key != kube.TaintSmall {
				tol = append(tol, t)
			}
		}
		if tolerate {
			tol = append(tol, nodeadm.Toleration{Key: kube.TaintSmall, Operator: "Equal", Value: "true", Effect: "NoSchedule"})
		}
		p.Tolerations = tol
	}
	return out, nil
}

// instancePodShapes are id's pods as the translator renders them.
func (h *Hub) instancePodShapes(ctx context.Context, id string) ([]runtime.PodShape, error) {
	ps, ok := h.rt.(runtime.PodShaper)
	if !ok {
		return nil, errors.New("this runtime can't render an instance's pods")
	}
	t := h.Template(id)
	if t == nil {
		return nil, fmt.Errorf("instance %s not found", id)
	}
	p, err := h.upProject(ctx, t)
	if err != nil {
		return nil, err
	}
	return ps.PodShapes(ctx, p)
}

// enableN1Gate is the N−1 gate at enable (I3): a critical or high
// instance starts only if the cluster keeps room for it when any one node
// fails; otherwise the 409 of the PUT, and it stays stopped. Caller holds
// id's lock.
func (h *Hub) enableN1Gate(ctx context.Context, id string) error {
	if !h.kubeOn() {
		return nil
	}
	a, _ := h.availabilityOf(id)
	if pr := a.PriorityOrDefault(); pr != runtime.PriorityCritical && pr != runtime.PriorityHigh {
		return nil
	}
	h.avail.Lock()
	defer h.avail.Unlock()
	var n1 []nminus1.Result
	var why string
	snap, err := h.availabilitySnapshot(ctx)
	if err == nil {
		var sim nodeadm.Snapshot
		if sim, err = h.simulateCluster(ctx, snap, id, *a); err == nil {
			n1, why = h.checkN1(sim)
			n1 = dropUnstarted(n1)
		}
	}
	if err != nil {
		n1, why = unknownResults(snap), "the N−1 check can't model the cluster: "+clipRunes(err.Error(), 300)
	}
	if msg, _ := n1Verdict(n1, why); msg != "" {
		return &NMinus1Refusal{Msg: msg + ": " + id + " stays stopped (lower its priority under Availability)", Results: n1}
	}
	return nil
}

// maxSnapshotAge bounds the last snapshot an up may use for *Only*'s
// small nodes when nodeadm doesn't answer.
const maxSnapshotAge = 10 * time.Minute

// kubeAvailability is id's availability as the translator takes it
// (nil = the defaults), its only choice's small nodes from the cluster
// snapshot (the last one read when nodeadm doesn't answer now).
func (h *Hub) kubeAvailability(ctx context.Context, id string) (*runtime.Availability, error) {
	a, _ := h.availabilityOf(id)
	if a == nil {
		return nil, nil
	}
	ra := &runtime.Availability{Priority: a.Priority, RunsOn: runtime.RunsOn{Mode: a.RunsOn.Mode, Class: a.RunsOn.Class, Site: a.RunsOn.Site,
		Nodes: slices.Clone(a.RunsOn.Nodes)}}
	if a.RunsOn.Mode != runtime.RunsOnOnly {
		return ra, nil
	}
	snap, err := h.availabilitySnapshot(ctx)
	if err != nil {
		last := h.lastSnapshot()
		if last != nil {
			if at, perr := time.Parse(time.RFC3339, last.TakenAt); perr != nil || h.now().Sub(at) > maxSnapshotAge {
				last = nil
			}
		}
		if last == nil {
			return nil, statusErr(503, "%s was not started: its Runs on needs the cluster's nodes, and nodeadm doesn't answer: %v", id, err)
		}
		log.Printf("availability: %s: nodeadm doesn't answer (%v): the small nodes come from the last snapshot", id, err)
		snap = *last
	}
	for _, name := range ra.RunsOn.Nodes {
		if n := snap.Node(name); n != nil && isSmall(n) {
			ra.RunsOn.Small = append(ra.RunsOn.Small, name)
		}
	}
	return ra, nil
}

// ErrorsAsN1 is the N−1 refusal in err (nil: none).
func ErrorsAsN1(err error) *NMinus1Refusal {
	var r *NMinus1Refusal
	if errors.As(err, &r) {
		return r
	}
	return nil
}

// KubeAvailabilityForTest is kubeAvailability (tests of other packages).
func (h *Hub) KubeAvailabilityForTest(ctx context.Context, id string) (*runtime.Availability, error) {
	return h.kubeAvailability(ctx, id)
}
