package hub

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/templates"
)

// ContainerStatus is one container of an app.
type ContainerStatus struct {
	Name     string `json:"name"`
	Service  string `json:"service"`
	State    string `json:"state"`
	Status   string `json:"status"`
	Job      bool   `json:"job,omitempty"`       // true for one-off jobs (§3)
	JobState string `json:"job_state,omitempty"` // done | failed | running | pending
}

// Job states (contract §11.9 "One-off jobs").
const (
	jobDone    = "done"
	jobFailed  = "failed"
	jobRunning = "running"
	jobPending = "pending"
)

// jobState is a job container's state (contract §11.9), the one
// implementation (status rows, drift, readiness): running (running or
// restarting), pending (created, never started), done (exited 0), and
// failed for everything else — exited non-zero, dead, and any other
// state (paused, removing, unknown): fail closed, never done.
func jobState(st docker.State) string {
	switch st.Status {
	case "running", "restarting":
		return jobRunning
	case "created":
		return jobPending
	case "exited":
		if st.ExitCode == 0 {
			return jobDone
		}
	}
	return jobFailed
}

// appContainers lists the app's project containers that belong to services
// of its compose file (one-off `compose run` containers excluded).
func (h *Hub) appContainers(ctx context.Context, t *templates.Template) ([]docker.Container, []string, error) {
	if h.engine == nil {
		return nil, nil, fmt.Errorf("docker engine not configured")
	}
	services := templates.Services(t.ReadCompose())
	known := map[string]bool{}
	for _, s := range services {
		known[s] = true
	}
	cs, err := h.engine.ListContainers(ctx, docker.ProjectFilter(projectName(t.ID)))
	if err != nil {
		return nil, services, err
	}
	out := cs[:0]
	for _, c := range cs {
		if c.Project() != projectName(t.ID) || c.Labels[docker.LabelOneoff] == "True" {
			continue
		}
		if len(known) > 0 && !known[c.Service()] {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, services, nil
}

// Status returns the app's containers: those of the services the
// instance's setup choices select (a leftover container of a compose
// profile they leave off is not listed, §13.18), then one row per such
// service with no container at all (§11.9 "One-off jobs": state
// "missing", status "no container"; a job's job_state "missing"). A
// companion service scaled to 0 (its AI support off) expects none.
func (h *Hub) Status(ctx context.Context, id string) ([]ContainerStatus, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	inactive, scaledOff := h.statusSkips(t)
	cs, services, err := h.appContainers(ctx, t)
	if err != nil {
		return nil, statusErr(502, "docker: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range cs {
		seen[c.Service()] = true
	}
	missing := []ContainerStatus{}
	for _, svc := range services {
		if seen[svc] || inactive[svc] || scaledOff[svc] {
			continue
		}
		row := ContainerStatus{Service: svc, State: StateMissing, Status: "no container"}
		if t.Jobs[svc] {
			row.Job, row.JobState = true, StateMissing
		}
		missing = append(missing, row)
	}
	out := make([]ContainerStatus, 0, len(cs))
	for _, c := range cs {
		if inactive[c.Service()] {
			continue
		}
		status := ContainerStatus{Name: c.Name(), Service: c.Service(), State: c.State, Status: c.Status}
		if t.Jobs[c.Service()] {
			status.Job = true
			// Get detailed state to determine JobState (I1: never omit it).
			st, err := h.engine.ContainerState(ctx, c.ID)
			if err == nil {
				status.JobState = jobState(st)
			} else {
				// Fallback to the list's state/status.
				status.JobState = jobState(docker.State{
					Running:  c.State == "running",
					Status:   c.State,
					ExitCode: 0, // unknown, but Status parsing below handles it
				})
				// Parse exit code from Status for exited containers (prefix check).
				if c.State == "exited" {
					if strings.HasPrefix(c.Status, "Exited (0)") {
						status.JobState = "done"
					} else {
						status.JobState = "failed"
					}
				}
			}
		}
		out = append(out, status)
	}
	return append(out, missing...), nil
}

// StateMissing is a status row's state (and a job's job_state) for an
// active service with no container (§11.9).
const StateMissing = "missing"

// statusSkips: the services Status expects no container of — those of
// a compose profile the setup choices leave off, and companion
// services scaled to 0.
func (h *Hub) statusSkips(t *templates.Template) (inactive, scaledOff map[string]bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	scaledOff = map[string]bool{}
	for svc, cs := range h.companionServicesLocked(t) {
		if cs.scale != nil && *cs.scale == 0 {
			scaledOff[svc] = true
		}
	}
	return h.inactiveServicesLocked(t), scaledOff
}

// Logs returns the last lines of the app's containers (optionally one
// service), interleaved by timestamp.
func (h *Hub) Logs(ctx context.Context, id, service string, lines int) ([]byte, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	if lines < 1 || lines > 10000 {
		return nil, statusErr(400, "lines must be 1-10000")
	}
	cs, services, err := h.appContainers(ctx, t)
	if service != "" && !contains(services, service) {
		return nil, statusErr(400, "invalid service")
	}
	if err != nil {
		return nil, statusErr(502, "docker: %v", err)
	}
	// An instance's current NT hashes never reach the logs API (F44):
	// unreadable ones = 503 before anything is read.
	if _, err := h.redactCredentialHashes(t, "", false); err != nil {
		return nil, err
	}
	sources := map[string][]byte{}
	for _, c := range cs {
		if service != "" && c.Service() != service {
			continue
		}
		out, err := h.engine.Logs(ctx, c.ID, lines, true)
		if err != nil {
			out = []byte(fmt.Sprintf("[hub: cannot read logs: %v]\n", err))
		}
		// The engine caps the bytes it reads: a source may end in a cut
		// hash.
		red, rerr := h.redactCredentialHashes(t, strings.TrimRight(string(out), "\n"), true)
		if rerr != nil {
			return nil, rerr
		}
		sources[c.Name()] = []byte(red + "\n")
	}
	return docker.MergeLogs(sources, lines), nil
}

// ExecResult is the outcome of Exec.
type ExecResult struct {
	Output   string `json:"output"`
	ExitCode int    `json:"exitCode"`
}

// Exec runs `/bin/sh -c command` in a running container of service.
func (h *Hub) Exec(ctx context.Context, id, service, command string) (*ExecResult, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	if service == "" || command == "" {
		return nil, statusErr(400, "service and command required")
	}
	cs, services, err := h.appContainers(ctx, t)
	if !contains(services, service) {
		return nil, statusErr(400, "invalid service: %s", service)
	}
	if err != nil {
		return nil, statusErr(502, "docker: %v", err)
	}
	target := runningContainer(cs, service)
	if target == nil {
		return nil, statusErr(409, "service %s has no running container", service)
	}
	if _, err := h.redactCredentialHashes(t, "", false); err != nil {
		return nil, err // F44: unreadable hashes, nothing run
	}
	res, err := h.engine.Exec(ctx, target.ID, []string{"/bin/sh", "-c", command}, execTimeout)
	if err != nil && res == nil {
		return nil, statusErr(502, "docker: %v", err)
	}
	// F44: the instance's hashes blanked (a cut one too) before the
	// Hub's notes are added.
	out, rerr := h.redactCredentialHashes(t, string(res.Output), res.Truncated)
	if rerr != nil {
		return nil, rerr
	}
	if res.Truncated {
		out += "\n[hub: output truncated]\n"
	}
	if res.TimedOut {
		out += fmt.Sprintf("\n[hub: command timed out after %s]\n", execTimeout)
	}
	if err != nil {
		out += fmt.Sprintf("\n[hub: %v]\n", err)
	}
	return &ExecResult{Output: out, ExitCode: res.ExitCode}, nil
}

// runningContainer is the running container of service among cs (an
// instance's appContainers: its own project only, no one-off
// containers), replica 1 preferred like `docker compose exec`; nil: none.
// Shared by Exec and the settings hooks.
func runningContainer(cs []docker.Container, service string) *docker.Container {
	var target *docker.Container
	for i := range cs {
		c := &cs[i]
		if c.Service() != service || c.State != "running" {
			continue
		}
		if target == nil || c.Labels[docker.LabelNumber] == "1" {
			target = c
		}
	}
	return target
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
