package doctor

import "testing"

func runKube(in *KubeIn) map[string]int {
	out := map[string]int{}
	for _, k := range KubeKinds {
		for _, f := range (kubeCheck{kind: k}).Run(&Inputs{Kube: in}) {
			out[f.Kind]++
		}
	}
	return out
}

// The Kubernetes kinds fire only under Kubernetes, each for its own
// cause (contract §14.5).
func TestKubeKinds(t *testing.T) {
	if got := runKube(nil); len(got) != 0 {
		t.Errorf("not kubernetes: %v", got)
	}
	if got := runKube(&KubeIn{Verified: true, Admission: "ok", Netpol: "proven"}); len(got) != 0 {
		t.Errorf("all good: %v", got)
	}
	if got := runKube(&KubeIn{Admission: "missing", Netpol: "proven", Why: "admission self-test: the guard is missing"}); got[KindAdmissionGuardMissing] != 1 || got[KindClusterUnverified] != 0 {
		t.Errorf("guard missing: %v", got)
	}
	if got := runKube(&KubeIn{Admission: "ok", Netpol: "unproven", Why: "NetworkPolicy probe: a connection the policy denies succeeded"}); got[KindNetpolNotEnforced] != 1 || got[KindClusterUnverified] != 0 {
		t.Errorf("netpol: %v", got)
	}
	if got := runKube(&KubeIn{Admission: "ok", Netpol: "proven", Why: "the cluster check is missing"}); got[KindClusterUnverified] != 1 {
		t.Errorf("unverified: %v", got)
	}
	if got := runKube(&KubeIn{Verified: true, Admission: "ok", Netpol: "proven", ReloadDegraded: []string{"b", "a"}, APIPublic: "203.0.113.7:6443"}); got[KindReloadDegraded] != 2 || got[KindKubeAPIPublic] != 1 {
		t.Errorf("info/warning: %v", got)
	}
}
