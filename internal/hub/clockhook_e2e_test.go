//go:build e2etest

package hub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/hub/internal/e2etest"
)

// TestClockOffsetFileE2E (core's e2e): changing the offset file shifts
// h.now() within about a second, with no restart, and a join code
// expires by it.
func TestClockOffsetFileE2E(t *testing.T) {
	sf := newServersFixture(t)
	sf.h.srvT.now = nil // the Hub's own clock, with the offset
	p := filepath.Join(t.TempDir(), "offset")
	sf.h.cfg.ClockOffset = e2etest.OffsetReader(p, time.Now)
	if d := sf.h.now().Sub(time.Now()); d > time.Minute || d < -time.Minute {
		t.Fatalf("no file: offset %v", d)
	}
	if _, _, err := sf.h.AddServer(context.Background(), admin, "nas", "NAS"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, []byte("16m\n"), 0o600)
	deadline := time.Now().Add(3 * time.Second)
	for sf.h.now().Sub(time.Now()) < 15*time.Minute {
		if time.Now().After(deadline) {
			t.Fatal("the offset didn't apply within a second or so")
		}
		time.Sleep(50 * time.Millisecond)
	}
	rec := waitServerOp(t, sf.h, serverOpKey("nas"))
	if rec.OK || !strings.Contains(rec.Error, "join code expired") {
		t.Errorf("op %+v", rec)
	}
}
