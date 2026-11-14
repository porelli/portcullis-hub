package kube

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/version"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/cel/environment"
)

// TestAdmissionCELCompiles compiles every expression of the admission
// policies with the API server's CEL environment at the floor
// (Kubernetes 1.32): a broken expression or a function 1.32 lacks fails
// here, before it reaches a cluster (core applies these files byte for
// byte).
func TestAdmissionCELCompiles(t *testing.T) {
	b, err := os.ReadFile("testdata/admission/policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	base := environment.MustBaseEnvSet(version.MajorMinor(1, 32))
	set, err := base.Extend(environment.VersionedOptions{IntroducedVersion: version.MajorMinor(1, 0), EnvOptions: []cel.EnvOption{
		cel.Variable("object", cel.DynType), cel.Variable("oldObject", cel.DynType), cel.Variable("params", cel.DynType),
		cel.Variable("request", cel.DynType), cel.Variable("namespaceObject", cel.DynType),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	env, err := set.Env(environment.NewExpressions)
	if err != nil {
		t.Fatal(err)
	}
	// The check would catch what broke before: a function newer than the
	// floor, and a quote that isn't CEL.
	for _, bad := range []string{"[[1]].flatten()", "'isn''t'"} {
		if _, iss := env.Compile(bad); iss == nil || iss.Err() == nil {
			t.Errorf("%s compiled at 1.32", bad)
		}
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(b), 4096)
	n, policies := 0, 0
	for {
		var p admissionv1.ValidatingAdmissionPolicy
		if err := dec.Decode(&p); err != nil {
			break
		}
		if p.Name == "" {
			continue
		}
		policies++
		compile := func(where, expr string) {
			if strings.TrimSpace(expr) == "" {
				return
			}
			n++
			if _, iss := env.Compile(expr); iss != nil && iss.Err() != nil {
				t.Errorf("%s %s: %v", p.Name, where, iss.Err())
			}
		}
		for _, v := range p.Spec.Variables {
			compile("variable "+v.Name, v.Expression)
		}
		for i, v := range p.Spec.Validations {
			compile("validation "+string(rune('0'+i)), v.Expression)
			compile("messageExpression", v.MessageExpression)
		}
		for _, m := range p.Spec.MatchConditions {
			compile("matchCondition "+m.Name, m.Expression)
		}
	}
	if policies != 6 || n < 100 {
		t.Fatalf("%d policies, %d expressions", policies, n)
	}
}
