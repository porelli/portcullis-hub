package hub

import (
	"reflect"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/runtime"
	dockerrt "github.com/portcullis/hub/internal/runtime/docker"
)

// newTestHub is New with the docker backend over a fake runner and engine
// (the Hub's tests drive the real backend). No runner and no engine = no
// runtime; a runner alone has no engine (EngineAbsent).
func newTestHub(cfg Config, runner compose.Runner, eng dockerrt.Engine, idp IdP) (*Hub, error) {
	isNil := func(v any) bool {
		if v == nil {
			return true
		}
		rv := reflect.ValueOf(v)
		return rv.Kind() == reflect.Pointer && rv.IsNil()
	}
	if isNil(runner) && isNil(eng) {
		return New(cfg, nil, idp)
	}
	if isNil(eng) {
		eng = nil
	}
	return New(cfg, dockerrt.New(runner, eng, dockerrt.Options{Kind: cfg.Runtime, Guard: cfg.Guard, HelperImage: HelperImage}), idp)
}

// setRuntime switches f's Hub to runtime kind (its config and its
// backend: the docker backend's Podman quirks follow the kind).
func (f *fixture) setRuntime(kind runtime.Kind) {
	f.h.cfg.Runtime = kind
	f.h.rt = dockerrt.New(f.runner, f.engine, dockerrt.Options{Kind: kind, Guard: f.h.cfg.Guard, HelperImage: HelperImage})
}
