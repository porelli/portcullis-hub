package hub

import (
	"context"
	"slices"

	"github.com/portcullis/hub/internal/doctor"
)

// doctorKubeIn is the doctor's Kubernetes input (nil unless the runtime
// is Kubernetes): the cluster guard's state through Info and the
// instances whose last reload restarted the pod. Never under mu.
func (h *Hub) doctorKubeIn(ctx context.Context) *doctor.KubeIn {
	if !h.kubeOn() {
		return nil
	}
	in := &doctor.KubeIn{Admission: "unknown", Netpol: "unproven", Why: "no runtime"}
	if h.rt != nil {
		if i, err := h.rt.Info(ctx); err == nil {
			in.Verified, in.Why = i.Verified, i.Why
			if i.Admission != "" {
				in.Admission = i.Admission
			}
			if i.Netpol != "" {
				in.Netpol = i.Netpol
			}
		} else {
			in.Why = err.Error()
		}
	}
	h.reloadDegraded.Range(func(k, _ any) bool {
		in.ReloadDegraded = append(in.ReloadDegraded, k.(string))
		return true
	})
	slices.Sort(in.ReloadDegraded)
	for id, g := range h.KubeGateways() {
		in.Gateways = append(in.Gateways, id+" "+g.IP+" "+g.UID)
	}
	slices.Sort(in.Gateways)
	return in
}

// doctorMeshIn is the doctor's mesh input (nil unless cluster nodes are
// managed: a Kubernetes primary with nodeadm).
func (h *Hub) doctorMeshIn() *doctor.MeshIn {
	if h.clusterNodesOn() != nil {
		return nil
	}
	st := h.MeshStatus()
	return &doctor.MeshIn{Stale: st.Stale, NoGateway: st.NoGateway}
}
