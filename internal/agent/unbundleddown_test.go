package agent

import (
	"context"
	"slices"
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

// TestUnbundledDown (security reviews of the "404 = down" change and of
// b23c457): a Down of a project the agent holds no bundle of is served
// only for an id it once held (a tombstone) or quarantined — 404 otherwise
// —, never for its own project (400), never touching its own containers;
// it takes the project's labelled containers down by name and is 204
// only when none is left.
func TestUnbundledDown(t *testing.T) {
	ghost := func(f *apiFixture) { // held once, then removed: a tombstone
		f.bundle(t, "ghost")
		if c := f.code(t, "DELETE", "/v1/projects/ghost", nil); c != 204 {
			t.Fatalf("removing ghost's bundle: %d", c)
		}
	}
	leftover := []runtime.Unit{{ID: "c1", Project: "portcullis-ghost", Instance: "ghost", State: "running"}}
	for name, c := range map[string]struct {
		id     string
		setup  func(f *apiFixture)
		units  []runtime.Unit
		stops  bool
		want   int
		downed bool
	}{
		"a tombstone + a leftover stopped": {"ghost", ghost, leftover, true, 204, true},
		"a tombstone + a leftover stays":   {"ghost", ghost, leftover, false, 409, true},
		"a tombstone, nothing there":       {"ghost", ghost, nil, false, 204, false},
		"an unknown id":                    {"stranger", nil, []runtime.Unit{{ID: "c2", Project: "portcullis-stranger", Instance: "stranger", State: "running"}}, true, 404, false},
		"the agent's own project":          {"worker", nil, nil, true, 400, false},
		"an own container under the label": {"ghost", ghost, []runtime.Unit{{ID: "own-1", Project: "portcullis-ghost", Instance: "ghost", State: "running"}}, true, 409, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAPI(t)
			f.api.cfg.OwnProject, f.api.cfg.OwnContainers = "portcullis-worker", []string{"own-1"}
			if c.setup != nil {
				c.setup(f)
			}
			f.rt.Lock()
			f.rt.Units = append(f.rt.Units, c.units...)
			f.rt.Unlock()
			before := len(f.rt.Calls())
			f.api.cfg.Runtime = &stoppingFake{eventsFake: f.rt, stops: c.stops}
			if got := f.code(t, "POST", "/v1/projects/"+c.id+"/down", nil); got != c.want {
				t.Fatalf("down: %d, want %d", got, c.want)
			}
			downed := slices.Contains(f.rt.Calls()[before:], "down-by-name portcullis-"+c.id)
			if downed != c.downed {
				t.Errorf("down-by-name called = %v, want %v (%v)", downed, c.downed, f.rt.Calls()[before:])
			}
		})
	}
}
