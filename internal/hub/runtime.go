package hub

import (
	"context"
	"fmt"
	"sort"

	"github.com/portcullis/hub/internal/docker"
	"github.com/portcullis/hub/internal/templates"
)

// ContainerStatus is one container of an app.
type ContainerStatus struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	State   string `json:"state"`
	Status  string `json:"status"`
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

// Status returns the app's containers.
func (h *Hub) Status(ctx context.Context, id string) ([]ContainerStatus, error) {
	t := h.Template(id)
	if t == nil {
		return nil, ErrNotFound
	}
	cs, _, err := h.appContainers(ctx, t)
	if err != nil {
		return nil, statusErr(502, "docker: %v", err)
	}
	out := make([]ContainerStatus, 0, len(cs))
	for _, c := range cs {
		out = append(out, ContainerStatus{Name: c.Name(), Service: c.Service(), State: c.State, Status: c.Status})
	}
	return out, nil
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
	sources := map[string][]byte{}
	for _, c := range cs {
		if service != "" && c.Service() != service {
			continue
		}
		out, err := h.engine.Logs(ctx, c.ID, lines, true)
		if err != nil {
			out = []byte(fmt.Sprintf("[hub: cannot read logs: %v]\n", err))
		}
		sources[c.Name()] = out
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
	var target *docker.Container
	for i := range cs {
		c := &cs[i]
		if c.Service() != service || c.State != "running" {
			continue
		}
		// Prefer replica 1, like `docker compose exec`.
		if target == nil || c.Labels[docker.LabelNumber] == "1" {
			target = c
		}
	}
	if target == nil {
		return nil, statusErr(409, "service %s has no running container", service)
	}
	res, err := h.engine.Exec(ctx, target.ID, []string{"/bin/sh", "-c", command}, execTimeout)
	if err != nil && res == nil {
		return nil, statusErr(502, "docker: %v", err)
	}
	out := string(res.Output)
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

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
