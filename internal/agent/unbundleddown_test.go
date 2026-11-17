package agent

import (
	"context"
	"testing"

	"github.com/portcullis/hub/internal/runtime"
)

// stoppingFake: DownByName removes the project's containers (stops) or
// leaves them running (stuck).
type stoppingFake struct {
	*eventsFake
	stops bool
}

func (s *stoppingFake) DownByName(ctx context.Context, name string) error {
	if err := s.eventsFake.DownByName(ctx, name); err != nil {
		return err
	}
	if s.stops {
		s.Lock()
		kept := s.Units[:0]
		for _, u := range s.Units {
			if u.Project != name {
				kept = append(kept, u)
			}
		}
		s.Units = kept
		s.Unlock()
	}
	return nil
}

// TestUnbundledDown (security review of the "404 = down" change): a Down
// of a project the agent holds no bundle of takes every container
// labelled with it down by name, and is 204 only when none is left — a
// leftover stopped → 204; one that stays → 409; nothing there → 204.
func TestUnbundledDown(t *testing.T) {
	for name, c := range map[string]struct {
		units []runtime.Unit
		stops bool
		want  int
	}{
		"a leftover stopped": {[]runtime.Unit{{ID: "c1", Project: "portcullis-ghost", Instance: "ghost", State: "running"}}, true, 204},
		"a leftover stays":   {[]runtime.Unit{{ID: "c1", Project: "portcullis-ghost", Instance: "ghost", State: "running"}}, false, 409},
		"nothing there":      {nil, false, 204},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAPI(t)
			f.rt.Units = c.units
			sf := &stoppingFake{eventsFake: f.rt, stops: c.stops}
			f.api.cfg.Runtime = sf
			if got := f.code(t, "POST", "/v1/projects/ghost/down", nil); got != c.want {
				t.Fatalf("down: %d, want %d", got, c.want)
			}
			calls := f.rt.Calls()
			if len(calls) == 0 || calls[0] != "down-by-name portcullis-ghost" {
				t.Errorf("the engine got %v", calls)
			}
		})
	}
}
