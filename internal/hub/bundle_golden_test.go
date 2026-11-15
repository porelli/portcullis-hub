package hub

import (
	"testing"

	"github.com/portcullis/hub/internal/agentapi"
)

// TestGoldenRendersPassBundleRules: the golden grafana and disks renders
// (template + Hub override, v2) pass the agent's bundle re-validation
// unchanged (multi-server pre-flight P4: the model-level rules and the
// Hub's renders can't drift apart).
func TestGoldenRendersPassBundleRules(t *testing.T) {
	f, _ := goldenRun(t, true)
	for _, id := range []string{"grafana", "disks"} {
		tpl := f.h.Template(id)
		proj, err := f.h.loadRendered(t.Context(), tpl)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		mf := agentapi.BundleManifest{Instance: id, Template: tpl.TemplateID, Volumes: tpl.NamesFor(id).Volumes}
		if err := agentapi.ValidateBundle(proj, mf, nil, DefaultOverrideBindRoots, "/host/project"); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}
