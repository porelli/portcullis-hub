package kube

import (
	"encoding/json"

	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// defaultConverter converts a typed k8s.io/api object to its unstructured
// form (the API server's JSON; never a hand-rolled wire format).
func defaultConverter(o any) (map[string]any, error) {
	m, err := k8sruntime.DefaultUnstructuredConverter.ToUnstructured(o)
	if err != nil {
		return nil, err
	}
	// creationTimestamp: null is noise in goldens and applies.
	if md, ok := m["metadata"].(map[string]any); ok {
		delete(md, "creationTimestamp")
	}
	stripNulls(m)
	return m, nil
}

// stripNulls drops the empty "creationTimestamp" and "status" stubs of
// nested templates (Deployment/Job pod templates).
func stripNulls(m map[string]any) {
	if st, ok := m["status"].(map[string]any); ok && len(st) == 0 {
		delete(m, "status")
	}
	if spec, ok := m["spec"].(map[string]any); ok {
		if tmpl, ok := spec["template"].(map[string]any); ok {
			if md, ok := tmpl["metadata"].(map[string]any); ok {
				delete(md, "creationTimestamp")
			}
		}
	}
}

// PlanYAML renders p's objects as one YAML stream, in apply order, with
// "# step <n> wait <kind>" separators (the translator's goldens).
func PlanYAML(p Plan) ([]byte, error) {
	var out []byte
	for i, s := range p.Steps {
		for _, o := range s.Objects {
			b, err := json.Marshal(o.Object)
			if err != nil {
				return nil, err
			}
			y, err := yaml.JSONToYAML(b)
			if err != nil {
				return nil, err
			}
			out = append(out, []byte("---\n# step "+itoa(i)+" wait "+s.Wait.String()+"\n")...)
			out = append(out, y...)
		}
	}
	return out, nil
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func (w WaitKind) String() string {
	switch w {
	case WaitReady:
		return "ready"
	case WaitComplete:
		return "complete"
	}
	return "none"
}
