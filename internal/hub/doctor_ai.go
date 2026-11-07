package hub

import (
	"context"
	"log"
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/policy"
	"github.com/portcullis/hub/internal/templates"
)

// The doctor's AI inputs (plan 4 Task 20, contract §14.5 "AI support"):
// doctorInputs calls aiDoctorInputs before it takes mu — the revocation
// problems (AIRevokeProblems takes mu itself) and the companions' state
// are read under short read locks, the containers outside any lock.

// aiCompanionIn is one switched-on companion to look up in Docker.
type aiCompanionIn struct {
	in      doctor.AIIn
	tmpl    *templates.Template
	service string
	sidecar bool // kind companion: its own image, judged against the pin
}

// aiDoctorInputs are the AI checks' inputs: every companion with AI
// support on now (master on, instance enabled and not busy, switched on,
// no owed revoke_all) with its service's container state and image, its
// instance's effective policy and the template's pinned digest, merged
// with AIRevokeProblems (any instance state: a revocation owed by a
// disabled instance is still owed).
func (h *Hub) aiDoctorInputs(ctx context.Context) []doctor.AIIn {
	problems := h.AIRevokeProblems()
	var on []aiCompanionIn
	labels := map[string][2]string{} // "<inst>/<comp>" → app label, companion label
	h.mu.RLock()
	for id, a := range h.st.AIInstances {
		t := h.findLocked(id)
		if t == nil || t.Manifest.AI == nil {
			continue
		}
		app := appName(t)
		eff := h.effectivePolicyLocked(t)
		images := templates.ServiceImages(t.ReadCompose())
		live := h.st.AI.Enabled && h.st.IsEnabled(id) && h.pendingLocked(id) == nil && t.HasAIMCP()
		for i := range t.Manifest.AI.MCP {
			c := &t.Manifest.AI.MCP[i]
			labels[id+"/"+c.Name] = [2]string{app, c.Label}
			sw, ok := a.Companions[c.Name]
			if !ok || !live || !sw.Enabled || sw.RevokePending || sw.Pruned {
				continue
			}
			ai := doctor.AIIn{Instance: id, Companion: c.Name, Label: app, CompanionLabel: c.Label, On: true,
				Policy: policyWords(eff), LoA: policy.LoA(eff)}
			sidecar := c.Kind == templates.CompanionKind
			if sidecar {
				ai.ImagePinned = templates.ImageDigest(images[c.Service])
			}
			cp := *t
			on = append(on, aiCompanionIn{in: ai, tmpl: &cp, service: c.Service, sidecar: sidecar})
		}
	}
	h.mu.RUnlock()

	// Docker, outside every lock: one listing per instance.
	listed := map[string][]docker.Container{}
	failed := map[string]bool{}
	for i := range on {
		x := &on[i]
		id := x.in.Instance
		if _, done := listed[id]; !done && !failed[id] {
			cs, _, err := h.appContainers(ctx, x.tmpl)
			if err != nil {
				log.Printf("doctor: %s: listing containers for the AI checks: %v", id, err)
				failed[id] = true
			} else {
				listed[id] = cs
			}
		}
		if failed[id] {
			continue // Status "": not judged
		}
		x.in.Status = "missing"
		for _, c := range listed[id] {
			if c.Service() != x.service {
				continue
			}
			st := c.State
			if st == "running" && strings.Contains(c.Status, "(unhealthy)") {
				st = "unhealthy"
			}
			// A running container wins over a stopped replica.
			if x.in.Status == "missing" || (st == "running" && x.in.Status != "running") {
				x.in.Status = st
				x.in.ImageRunning = ""
				if c.State == "running" && x.sidecar {
					if d := templates.ImageDigest(c.Image); d != "" {
						x.in.ImageRunning = d
					} else {
						x.in.ImageRunning = c.Image
					}
				}
			}
		}
	}

	byKey := map[string]*doctor.AIIn{}
	var keys []string
	for i := range on {
		k := on[i].in.Instance + "/" + on[i].in.Companion
		in := on[i].in
		byKey[k] = &in
		keys = append(keys, k)
	}
	for _, p := range problems {
		k := p.Instance + "/" + p.Companion
		in := byKey[k]
		if in == nil {
			l := labels[k]
			in = &doctor.AIIn{Instance: p.Instance, Companion: p.Companion, Label: l[0], CompanionLabel: l[1]}
			byKey[k] = in
			keys = append(keys, k)
		}
		in.Revoking, in.Pruned, in.NoHook, in.Recorded, in.Reason = p.Revoking, p.Pruned, p.NoHook, p.Recorded, p.Reason
		in.Unmatched = slices.Clone(p.Unmatched)
	}
	sort.Strings(keys)
	out := make([]doctor.AIIn, 0, len(keys))
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	return out
}

// policyWords is a policy as the doctor's text shows it ("mtls and
// webauthn", "password or webauthn", "none").
func policyWords(p policy.AuthPolicy) string {
	if len(p.Factors) == 0 {
		return "none"
	}
	sep := " or "
	if p.Op == "all" {
		sep = " and "
	}
	return strings.Join(p.Factors, sep)
}
