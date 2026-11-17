package hub

import (
	"testing"
	"time"

	"github.com/portcullis/hub/internal/e2etest"
)

// TestClockOffsetOnlyInE2E: the clock offset moves h.now() in an
// e2etest build only; a default build ignores the field (and main
// refuses the variable).
func TestClockOffsetOnlyInE2E(t *testing.T) {
	h := &Hub{cfg: Config{ClockOffset: func() time.Duration { return 3 * time.Hour }}}
	moved := h.now().Sub(time.Now()) > 2*time.Hour
	if moved != e2etest.Enabled {
		t.Errorf("e2etest %v: now %v", e2etest.Enabled, h.now())
	}
}
