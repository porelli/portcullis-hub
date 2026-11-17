package servers

import (
	"testing"
)

func TestCompatible(t *testing.T) {
	for _, c := range []struct {
		hub, agent string
		want       bool
	}{
		{"1.4", "1.4", true}, {"1.4", "1.3", true}, {"1.4", "1.2", false}, {"1.4", "1.5", false}, {"2.0", "1.9", false},
		{"v1.4.2", "1.3.9", true}, {"1.4.0", "v1.4.7", true}, {"1.0", "0.9", false}, {"1.0", "1.0", true},
		{"0.4", "0.3", true}, {"", "1.4", false}, {"1.4", "", false}, {"edge", "edge", false}, {"1.4", "1.3-dirty", false},
		{"1.4", "1.3.0-rc.1", true}, {"1.4", "01.3", false}, {"1.4", "1.3.0+build", true}, {"1", "1", false},
	} {
		if got := Compatible(c.hub, c.agent); got != c.want {
			t.Errorf("Compatible(%q, %q) = %v", c.hub, c.agent, got)
		}
	}
}
