package doctor

import (
	"sort"
	"strings"
)

// Kubernetes (contract §14.5): five kinds that run only under
// HUB_CONTAINER_RUNTIME=kubernetes (Inputs.Kube set); all explain-only.
const (
	KindNetpolNotEnforced     = "netpol_not_enforced"
	KindAdmissionGuardMissing = "admission_guard_missing"
	KindClusterUnverified     = "cluster_unverified"
	KindReloadDegraded        = "reload_degraded"
	KindKubeAPIPublic         = "kube_api_public"
)

// KubeKinds are the Kubernetes kinds.
var KubeKinds = []string{KindNetpolNotEnforced, KindAdmissionGuardMissing, KindClusterUnverified, KindReloadDegraded, KindKubeAPIPublic}

// KubeIn is the cluster guard's state (contract §6 "On Kubernetes"):
// verified and its why, the admission self-test (ok|missing|unknown),
// the NetworkPolicy probe (proven|unproven), the instances whose last
// reload had to restart the pod (no kill in the image) and the API or
// kubelet answering on the node's external address ("" = not seen).
type KubeIn struct {
	Verified       bool
	Why            string
	Admission      string
	Netpol         string
	ReloadDegraded []string
	APIPublic      string
}

func init() {
	for _, k := range KubeKinds {
		Register(kubeCheck{kind: k})
	}
}

type kubeCheck struct{ kind string }

func (c kubeCheck) Kind() string { return c.kind }

func (c kubeCheck) Run(in *Inputs) []Finding {
	k := in.Kube
	if k == nil {
		return nil
	}
	switch c.kind {
	case KindNetpolNotEnforced:
		if k.Netpol == "proven" {
			return nil
		}
		return []Finding{{FP: Fingerprint(c.kind), Kind: c.kind, Severity: Problem,
			Title:  "The cluster's NetworkPolicies aren't proven to be enforced.",
			Why:    "The Hub's own probe (a denied and an allowed connection between probe pods) hasn't passed: without enforcement an app could reach any other pod, so every instance deploy is refused.",
			Class:  FixExplain,
			Steps:  []string{"Check that k3s runs its network policy controller (no --disable-network-policy) and that ./portcullis status shows the probe proven.", "The Hub retries every minute; restart it once the cluster is fixed."},
			Inputs: Digest(k.Netpol + " " + k.Why)}}
	case KindAdmissionGuardMissing:
		if k.Admission != "missing" {
			return nil
		}
		return []Finding{{FP: Fingerprint(c.kind), Kind: c.kind, Severity: Problem,
			Title:  "The admission guard behind the Hub's Role is missing.",
			Why:    "A forbidden object the Hub dry-ran wasn't rejected by its portcullis-apps-guard binding: nothing would stop a pod spec the Role allows. Every runtime operation answers 503.",
			Class:  FixExplain,
			Steps:  []string{"Run ./portcullis upgrade: it installs the five ValidatingAdmissionPolicies and their bindings again.", "Check ./portcullis status for the cluster check."},
			Inputs: Digest(k.Admission + " " + k.Why)}}
	case KindClusterUnverified:
		if k.Verified || k.Admission == "missing" || (k.Netpol != "proven" && strings.Contains(k.Why, "NetworkPolicy probe")) {
			return nil // reported by its own kind
		}
		return []Finding{{FP: Fingerprint(c.kind), Kind: c.kind, Severity: Problem,
			Title:  "The cluster isn't verified.",
			Why:    k.Why + ". Every runtime operation of the Hub answers 503 until it is.",
			Class:  FixExplain,
			Steps:  []string{"Run ./portcullis up (it writes the cluster check the Hub reads) and ./portcullis status.", "Check that the Hub's Role equals the chart's (no extra rules bound to its ServiceAccount)."},
			Inputs: Digest(k.Why)}}
	case KindReloadDegraded:
		ids := append([]string(nil), k.ReloadDegraded...)
		sort.Strings(ids)
		var out []Finding
		for _, id := range ids {
			out = append(out, Finding{FP: Fingerprint(c.kind, id), Kind: c.kind, Severity: Info, Instances: []string{id},
				Title: id + " is restarted instead of reloaded.",
				Why:   "Its image has no kill: a settings reload signal can't be sent by exec, so the Hub restarts its pod through the Deployment (the app is briefly unavailable on each reload).",
				Class: FixExplain,
				Steps: []string{"Nothing to do; a template whose image ships kill (busybox, coreutils) reloads in place."}})
		}
		return out
	case KindKubeAPIPublic:
		if k.APIPublic == "" {
			return nil
		}
		return []Finding{{FP: Fingerprint(c.kind), Kind: c.kind, Severity: Warning,
			Title:  "The Kubernetes API or the kubelet answers on the node's public address.",
			Why:    k.APIPublic + " answers from outside: restrict it in the firewall (Portcullis never changes a firewall).",
			Class:  FixExplain,
			Steps:  []string{"Allow :6443 and :10250 only from the addresses that administer the cluster."},
			Inputs: Digest(k.APIPublic)}}
	}
	return nil
}
