package hub

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/idmap"
)

// VarUnprivilegedPortStart is core's net.ipv4.ip_unprivileged_port_start,
// written into secrets/hub/core.env under podman only (contract §2). It is
// not a template variable: the Hub never passes it to an instance.
const VarUnprivilegedPortStart = "PORTCULLIS_UNPRIVILEGED_PORT_START"

// DefaultUnprivilegedPortStart is the kernel's default, used for a missing
// or unreadable core value (fail closed: the stricter limit).
const DefaultUnprivilegedPortStart = 1024

// RuntimeView is GET /api/runtime (contract §11): the configured runtime,
// what the guard verified, and under podman the Hub's own id maps (every
// container shares the operator's default namespace) and the host's
// unprivileged port start. Maps and the port are null under Docker.
type RuntimeView struct {
	Runtime               docker.Runtime `json:"runtime"`
	Verified              bool           `json:"verified"`
	Engine                string         `json:"engine"`
	EngineVersion         string         `json:"engine_version"`
	Mismatch              string         `json:"mismatch"`
	Rootless              bool           `json:"rootless"`
	UIDMap                idmap.Map      `json:"uid_map"`
	GIDMap                idmap.Map      `json:"gid_map"`
	UnprivilegedPortStart *int           `json:"unprivileged_port_start"`
	SELinux               bool           `json:"selinux"`
}

// readProcIDMaps reads the Hub's own /proc/self/uid_map and gid_map.
func readProcIDMaps() (uid, gid idmap.Map, err error) {
	read := func(p string) (idmap.Map, error) {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		return idmap.Parse(string(b))
	}
	if uid, err = read("/proc/self/uid_map"); err != nil {
		return nil, nil, err
	}
	if gid, err = read("/proc/self/gid_map"); err != nil {
		return nil, nil, err
	}
	return uid, gid, nil
}

// Runtime is the runtime view. The engine's security options (rootless,
// SELinux) are read only once the guard has verified it.
func (h *Hub) Runtime(ctx context.Context) RuntimeView {
	v := RuntimeView{Runtime: h.cfg.Runtime}
	if g := h.cfg.Guard; g != nil {
		i := g.Info()
		v.Verified, v.Engine, v.EngineVersion, v.Mismatch = i.Verified, i.Engine, i.Version, i.Mismatch
	}
	if v.Verified && h.engine != nil {
		if opts, err := h.engine.SecurityOptions(ctx); err == nil {
			v.Rootless = securityOption(opts, "rootless")
			v.SELinux = securityOption(opts, "selinux")
		}
	}
	if h.cfg.Runtime == docker.RuntimePodman {
		read := h.readIDMaps
		if read == nil {
			read = readProcIDMaps
		}
		if uid, gid, err := read(); err == nil {
			v.UIDMap, v.GIDMap = uid, gid
		} else {
			log.Printf("runtime: can't read the Hub's id maps: %v", err)
		}
		p := h.unprivilegedPortStart()
		v.UnprivilegedPortStart = &p
	}
	return v
}

// unprivilegedPortStart is core's PORTCULLIS_UNPRIVILEGED_PORT_START (the
// core env subset at <ProjectDir>/.env): an integer 1–65535, anything else
// (missing included) DefaultUnprivilegedPortStart.
func (h *Hub) unprivilegedPortStart() int {
	raw := strings.TrimSpace(readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env"))[VarUnprivilegedPortStart])
	if raw == "" || raw[0] < '0' || raw[0] > '9' {
		return DefaultUnprivilegedPortStart
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return DefaultUnprivilegedPortStart
	}
	return n
}

// securityOption reports whether Info's SecurityOptions carry name=<name>.
func securityOption(opts []string, name string) bool {
	for _, o := range opts {
		for _, kv := range strings.Split(o, ",") {
			if k, v, _ := strings.Cut(kv, "="); k == "name" && v == name {
				return true
			}
		}
	}
	return false
}

// engineVerifiedNow: the guard has verified the engine (no guard: unit
// tests with fake engines, nothing to wait for).
func (h *Hub) engineVerifiedNow() bool {
	g := h.cfg.Guard
	return g == nil || g.Err() == nil
}

// waitEngine blocks until the guard is settled; true = verified (no guard:
// true at once). Start-time engine work waits here (P5): an unverified
// engine is never a reason to stop.
func (h *Hub) waitEngine() bool {
	g := h.cfg.Guard
	if g == nil {
		return true
	}
	<-g.Settled()
	return g.Err() == nil
}

// afterEngineVerified runs fn in the background once the engine is
// verified; a mismatch skips it (logged).
func (h *Hub) afterEngineVerified(what string, fn func()) {
	h.goBackground(func() {
		if !h.waitEngine() {
			log.Printf("%s: skipped: %v", what, h.cfg.Guard.Err())
			return
		}
		fn()
	})
}
