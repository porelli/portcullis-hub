package agent

// The usage routes (contract §17.4, ux3): one stats sample and the
// writable layer of a bundled project's container (the List row's
// scope), an image's size (the Pull row's: a ref in a bundle's model),
// the worker's host counters from the agent's own procfs, and the
// usage fixer's volume scope. Every route sits behind the same guard as
// the others (hub.control only, ready only: Agent.Handler).

import (
	"context"
	"net/http"
	"time"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/usage"
	"github.com/prometheus/procfs"
	"github.com/prometheus/procfs/blockdevice"
)

// layerSizeTimeout: the size=true inspect (contract §11.11).
const layerSizeTimeout = 10 * time.Second

func (a *API) stats(w http.ResponseWriter, r *http.Request, cid string) {
	s, err := a.cfg.Runtime.Stats(r.Context(), cid)
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agentapi.UnitStatsOf(s))
}

func (a *API) layerSize(w http.ResponseWriter, r *http.Request, cid string) {
	ctx, cancel := context.WithTimeout(r.Context(), layerSizeTimeout)
	defer cancel()
	n, err := a.cfg.Runtime.LayerSize(ctx, cid)
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agentapi.SizeBody{Bytes: max(n, 0)})
}

// imageSize: GET /v1/images/size?ref= (one ref, in a bundle's model or
// the pinned helper image; anything else 403 before the engine).
func (a *API) imageSize(w http.ResponseWriter, r *http.Request) {
	refs := r.URL.Query()[agentapi.QueryRef]
	if len(refs) != 1 || refs[0] == "" {
		writeError(w, http.StatusBadRequest, "ref must be given once")
		return
	}
	if !a.imageOK(refs[0]) {
		writeError(w, http.StatusForbidden, "the image is in no bundle")
		return
	}
	n, err := a.cfg.Runtime.ImageSize(r.Context(), refs[0])
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agentapi.SizeBody{Bytes: max(n, 0)})
}

// hostUsage: GET /v1/host/usage, the agent container's own /proc (its
// stat, meminfo and diskstats aren't namespaced: the host's figures; no
// mount, no capability). A file that can't be read is a 503, never a
// partial answer; the error names no path.
func (a *API) hostUsage(w http.ResponseWriter, r *http.Request) {
	proc, sys := a.cfg.ProcDir, a.cfg.SysDir
	if proc == "" {
		proc = "/proc"
	}
	if sys == "" {
		sys = "/sys"
	}
	c, err := readHost(proc, sys)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the host's counters can't be read")
		return
	}
	writeJSON(w, http.StatusOK, agentapi.HostCountersOf(c))
}

func readHost(proc, sys string) (usage.HostCounters, error) {
	fs, err := procfs.NewFS(proc)
	if err != nil {
		return usage.HostCounters{}, err
	}
	bfs, err := blockdevice.NewFS(proc, sys)
	if err != nil {
		return usage.HostCounters{}, err
	}
	return usage.ReadHost(fs, bfs)
}

// usageVolumeInScope is fixerspec.Rebuild's volume check for spec: the
// volume is a bundled project's (by its compose labels) and that project
// is the instance the spec names.
func (a *API) usageVolumeInScope(ctx context.Context, spec *agentapi.FixerSpec) func(string) bool {
	return func(name string) bool {
		if len(spec.Volumes) != 1 || spec.Volumes[0].Name != name {
			return false
		}
		v, err := a.cfg.Runtime.InspectVolume(ctx, name)
		if err != nil {
			return false
		}
		owner, ok := a.volumeOwner(v)
		return ok && owner == spec.Volumes[0].Instance
	}
}

// fixerBind is a folder_fix spec's one bind source (false: a usage run on
// a volume).
func fixerBind(s *agentapi.FixerSpec) (string, bool) {
	if s == nil || len(s.Binds) != 1 {
		return "", false
	}
	return s.Binds[0].Source, true
}
