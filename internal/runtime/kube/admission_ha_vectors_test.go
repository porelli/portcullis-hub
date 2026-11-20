package kube

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The exact refusal texts of the HA admission rules (contract §6 "On
// Kubernetes"), each carried by at least one case tagged "ha".
var haAdmissionTexts = []string{
	"app pods may use only portcullis-critical|high|normal|low",
	"the portcullis.io/small toleration needs a required node affinity on portcullis.io/class In [small]",
	"nodeName is refused",
	"topologySpreadConstraints and affinity may use only portcullis.io/* and kubernetes.io/hostname keys",
	"the Hub may exec only hub rev <dir> <doc> in a reader pod of the core namespace",
	"nodeadm may create only bootstrap token Secrets in kube-system",
	"bootstrap tokens must expire within 15 minutes",
	"bootstrap tokens may be used for authentication only",
	"bootstrap tokens may carry only the group system:bootstrappers:k3s:default-node-token",
	"only the CLI may attach to or port-forward a pod of the core namespace",
	"nodeadm may delete only bootstrap token Secrets (bootstrap-token-<6 [a-z0-9]>) in kube-system",
	"nodes can't set Portcullis placement labels or taints; nodeadm sets them",
	"only the Traefik DaemonSet's pod shape may run in portcullis-ingress",
}

// TestAdmissionHAVectorsShape (no envtest): admission_vectors.json holds
// ≥ 24 cases tagged "ha", every HA text has a denial and the accepted
// forms are there; an HA case runs as hub, intruder, nodeadm, cli (the
// CLI's own identity: portcullis-ingress-pods judges every identity) or
// daemonset-controller, an exec / attach / portforward case is the
// matching Pod*Options naming its pod, no case is an admission object
// (ruling R-ADM: the API server applies no policy to them), and a
// bootstrap token's expiration may be ${NOW+<n>m}, which the envtest
// harness replaces with now + n minutes (RFC 3339) before the request.
func TestAdmissionHAVectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/admission_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name           string            `json:"name"`
		Object         map[string]any    `json:"object"`
		As             string            `json:"as"`
		Want           string            `json:"want"`
		ReasonContains string            `json:"reason_contains"`
		Existing       map[string]any    `json:"existing,omitempty"`
		Op             string            `json:"op,omitempty"`
		Subresource    string            `json:"subresource,omitempty"`
		HA             bool              `json:"ha,omitempty"`
		Params         map[string]string `json:"params,omitempty"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	ha, allow := 0, 0
	denied := map[string]bool{}
	for _, v := range vs {
		if names[v.Name] {
			t.Errorf("repeated vector name %q", v.Name)
		}
		names[v.Name] = true
		if !v.HA {
			continue
		}
		ha++
		switch v.As {
		case "hub", "intruder", "nodeadm", "cli", "daemonset-controller", "node":
		default:
			t.Errorf("%s: as %q", v.Name, v.As)
		}
		switch v.Want {
		case "allow":
			allow++
			if v.ReasonContains != "" {
				t.Errorf("%s: an allow with a reason", v.Name)
			}
		case "deny":
			denied[v.ReasonContains] = true
		default:
			t.Errorf("%s: want %q", v.Name, v.Want)
		}
		want := map[string]string{"exec": "PodExecOptions", "attach": "PodAttachOptions", "portforward": "PodPortForwardOptions"}[v.Op]
		if want != "" && v.Object["kind"] != want {
			t.Errorf("%s: an %s case is a %s", v.Name, v.Op, want)
		}
		if strings.Contains(string(mustJSON(v.Object)), "ValidatingAdmissionPolicy") {
			t.Errorf("%s: no admission policy judges admission objects (ruling R-ADM)", v.Name)
		}
	}
	if ha < 24 || allow < 6 {
		t.Errorf("%d ha cases (%d allowed), want ≥ 24 (≥ 6 allowed)", ha, allow)
	}
	for _, text := range haAdmissionTexts {
		if !denied[text] {
			t.Errorf("no ha denial carries %q", text)
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
