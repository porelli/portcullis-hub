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
	"nodeadm may create only a binding in its canonical form on a params generation",
	"nodeadm may never change or delete a Portcullis admission policy or binding",
	"nodeadm may create only portcullis-admission-params-<16 hex> ConfigMaps",
}

// TestAdmissionHAVectorsShape (no envtest): admission_vectors.json holds
// ≥ 24 cases tagged "ha", every HA text has a denial and the accepted
// forms are there; an HA case runs as hub, intruder or nodeadm, and an
// exec case (op "exec") is a PodExecOptions naming its pod.
func TestAdmissionHAVectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/admission_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name           string         `json:"name"`
		Object         map[string]any `json:"object"`
		As             string         `json:"as"`
		Want           string         `json:"want"`
		ReasonContains string         `json:"reason_contains"`
		Existing       map[string]any `json:"existing,omitempty"`
		Op             string         `json:"op,omitempty"`
		HA             bool           `json:"ha,omitempty"`
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
		case "hub", "intruder", "nodeadm":
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
		if v.Op == "exec" && v.Object["kind"] != "PodExecOptions" {
			t.Errorf("%s: an exec case is a PodExecOptions", v.Name)
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
