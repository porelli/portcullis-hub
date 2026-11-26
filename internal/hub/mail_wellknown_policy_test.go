package hub

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/portcullis/hub/internal/policy"
)

// TestPolicyKeepsMailWellknownHosts (issue 5, test server 2026-11-26):
// the wired mail provider's project routes the Hub's own
// portcullis-mail-wellknown hosts (mta-sts / autoconfig / autodiscover
// of every mail domain, contract §5): the policy file publishes no deny
// entry for them (they are known config, no group-gate) and logs no
// "DENYING ALL ACCESS". Any other host the provider's project routes
// outside its config is still denied, and another project routing a
// well-known host is still denied too.
func TestPolicyKeepsMailWellknownHosts(t *testing.T) {
	f := mailOverrideFixture(t)
	f.h.driftMu.Lock()
	f.h.runtimeHosts = map[string][]string{
		mailProviderID: {"mta-sts.example.org", "Autoconfig.example.org", "autodiscover.example.org", "rogue.example.org"},
		"other":        {"mta-sts.example.org"},
	}
	f.h.driftMu.Unlock()
	if err := f.h.WritePolicy(); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups map[string]string `json:"groups"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(f.data, "group-gate-policy.json"))), &doc); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"autoconfig.example.org", "autodiscover.example.org"} {
		if doc.Groups[h] == policy.DenyGroup {
			t.Errorf("%s is denied: the Hub's own well-known router counted as unknown config", h)
		}
	}
	if doc.Groups["rogue.example.org"] != policy.DenyGroup {
		t.Errorf("rogue.example.org = %q, want denied", doc.Groups["rogue.example.org"])
	}
	// Routed by a project that isn't the wired provider: still unknown.
	if doc.Groups["mta-sts.example.org"] != policy.DenyGroup {
		t.Errorf("mta-sts.example.org routed by another project = %q, want denied", doc.Groups["mta-sts.example.org"])
	}
}
