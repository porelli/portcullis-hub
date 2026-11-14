package httpapi

import (
	"reflect"

	"github.com/portcullis/hub/internal/compose"
	"github.com/portcullis/hub/internal/hub"
	dockerrt "github.com/portcullis/hub/internal/runtime/docker"
)

// newTestHub is hub.New with the docker backend over a fake runner and
// engine (no engine: EngineAbsent, the Hub skips the engine).
func newTestHub(cfg hub.Config, runner compose.Runner, eng dockerrt.Engine, idp hub.IdP) (*hub.Hub, error) {
	if eng == nil || reflect.ValueOf(eng).Kind() == reflect.Pointer && reflect.ValueOf(eng).IsNil() {
		eng = nil
	}
	return hub.New(cfg, dockerrt.New(runner, eng, dockerrt.Options{Kind: cfg.Runtime, Guard: cfg.Guard, HelperImage: hub.HelperImage}), idp)
}
