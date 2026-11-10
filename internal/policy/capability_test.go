package policy

import "testing"

func TestCapabilityMatrix(t *testing.T) {
	for _, c := range []struct {
		method    string
		templates bool
		enforce   string
	}{
		{"forward-auth", true, EnforcePerRequest},
		{"header-auth", true, EnforcePerRequest},
		{"native-oidc", true, EnforceAtLogin},
		{"mtls", false, EnforceTLS},
		{"custom", false, EnforceNone},
		{"public", false, EnforceNone},
		{"bogus", false, EnforceNone},
	} {
		got := CapabilityFor(c.method)
		if got.Templates != c.templates || got.Enforcement != c.enforce {
			t.Errorf("CapabilityFor(%q) = %+v", c.method, got)
		}
	}
}
