package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	"github.com/portcullis/hub/internal/agentapi"
	rt "github.com/portcullis/hub/internal/runtime"
)

func (a *Agent) handleInfo(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Info == nil {
		writeError(w, http.StatusServiceUnavailable, "the engine can't be read")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	info, err := a.cfg.Info(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the engine can't be read")
		return
	}
	info.AgentVersion, info.API = Version, agentapi.Version
	info.Runtime = a.cfg.Runtime
	info.BindRoots = a.cfg.BindRoots
	info.DataDir = a.cfg.DataDir
	info.DataTotal, info.DataFree = diskOf(a.cfg.DataDir)
	info.Clock = a.cfg.Now().UTC()
	b, err := json.Marshal(info)
	if err != nil || len(b) > agentapi.MaxInfo {
		writeError(w, http.StatusInternalServerError, "info over its cap")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// diskOf is a filesystem's total and free bytes (0, 0 when unreadable).
func diskOf(path string) (int64, int64) {
	var st unix.Statfs_t
	if path == "" || unix.Statfs(path, &st) != nil {
		return 0, 0
	}
	return int64(st.Blocks) * int64(st.Bsize), int64(st.Bavail) * int64(st.Bsize)
}

// EngineInfo is the engine's part of /v1/info from the runtime backend
// (the Hub's docker backend pointed at socket-proxy-agent): verified
// state, data root, API version, security options, id mapping and
// networks, plus the host's CPUs, memory and unprivileged port start.
func EngineInfo(engine rt.Instances, portStart int) func(ctx context.Context) (agentapi.Info, error) {
	return func(ctx context.Context) (agentapi.Info, error) {
		ri, err := engine.Info(ctx)
		if err != nil {
			return agentapi.Info{}, err
		}
		out := agentapi.Info{Arch: runtime.GOARCH, EngineVersion: ri.EngineVersion, EngineAPI: ri.APIVersion,
			Verified: ri.Verified, Why: ri.Why, SecurityOptions: ri.SecurityOptions, SELinux: ri.SELinux,
			IDMapped: ri.IDMapped, Remapped: ri.Remapped, Rootless: ri.Kind == rt.KindPodman,
			CPUs: runtime.NumCPU(), MemBytes: memTotal(), UnprivilegedPortStart: portStart}
		if len(ri.ForbiddenRoots) > 0 {
			out.DockerRootDir = ri.ForbiddenRoots[0]
			out.DiskTotal, out.DiskFree = diskOf(out.DockerRootDir)
		}
		for _, n := range ri.Networks {
			out.Networks = append(out.Networks, agentapi.Network{Name: n.Name, Subnets: n.Subnets})
		}
		return out, nil
	}
}

func memTotal() int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n << 10
		}
	}
	return 0
}

// metrics: the agent's own registry (node and state; Task 6 adds the
// containers').
func (a *Agent) registry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "portcullis_agent_info", Help: "The agent's version.",
		ConstLabels: prometheus.Labels{"version": Version, "runtime": a.cfg.Runtime}}, func() float64 { return 1 }))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "portcullis_agent_ready", Help: "1 when the agent is ready."},
		func() float64 {
			if a.State() == StateReady {
				return 1
			}
			return 0
		}))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "portcullis_agent_link_handshake_age_seconds", Help: "Seconds since link's last handshake (-1: none)."},
		func() float64 {
			a.mu.Lock()
			t := a.tunnel
			a.mu.Unlock()
			if t == nil {
				return -1
			}
			hs := t.LastHandshake()
			if hs.IsZero() {
				return -1
			}
			return time.Since(hs).Seconds()
		}))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "portcullis_agent_data_free_bytes", Help: "Free bytes of the agent's data dir."},
		func() float64 { _, f := diskOf(a.cfg.DataDir); return float64(f) }))
	return reg
}

func (a *Agent) handleMetrics(w http.ResponseWriter, r *http.Request) {
	a.metricsOnce.Do(func() {
		a.metrics = promhttp.HandlerFor(a.registry(), promhttp.HandlerOpts{})
	})
	a.metrics.ServeHTTP(w, r)
}
