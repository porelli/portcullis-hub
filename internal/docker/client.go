// Package docker is the Hub's Docker Engine API client, a thin layer over
// the official SDK (github.com/moby/moby/client) for DOCKER_HOST =
// tcp://host:port or unix:///path. It covers only what the Hub needs:
// container listing, logs, exec and events (all read-only; `docker
// compose` does up/down).
//
// The SDK negotiates the API version on first use (GET/HEAD /_ping, which
// the Hub's socket proxy allows), so the Hub keeps working across Engine
// releases that raise the minimum API version.
package docker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

// DefaultHost is used when DOCKER_HOST is unset.
const DefaultHost = "unix:///var/run/docker.sock"

// Labels set by docker compose.
const (
	LabelProject = "com.docker.compose.project"
	LabelService = "com.docker.compose.service"
	LabelNumber  = "com.docker.compose.container-number"
	LabelOneoff  = "com.docker.compose.oneoff"
)

// requestTimeout bounds the non-streaming calls (list, inspect, ping, exec
// create/inspect); logs, exec output and events are bounded by the
// caller's context instead.
const requestTimeout = 30 * time.Second

// Client talks to one Docker daemon.
type Client struct {
	api *client.Client
}

// New parses a DOCKER_HOST value. "" means DefaultHost.
func New(host string) (*Client, error) {
	if host == "" {
		host = DefaultHost
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("invalid DOCKER_HOST %q: %w", host, err)
	}
	// Our own transport: bounded dials, no HTTP(S)_PROXY from the
	// environment (the SDK's default would honour it for tcp).
	tr := &http.Transport{MaxIdleConns: 8, IdleConnTimeout: 90 * time.Second}
	d := &net.Dialer{Timeout: 10 * time.Second}
	var sdkHost string
	switch u.Scheme {
	case "unix":
		sock := u.Path
		if sock == "" {
			return nil, fmt.Errorf("invalid DOCKER_HOST %q: missing socket path", host)
		}
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", sock)
		}
		sdkHost = "unix://" + sock
	case "tcp", "http":
		if u.Host == "" {
			return nil, fmt.Errorf("invalid DOCKER_HOST %q: missing host:port", host)
		}
		addr := u.Host
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
		sdkHost = "tcp://" + addr
	case "https":
		// TLS to the daemon would need client certs; the Hub talks to a
		// socket proxy on an internal network instead.
		return nil, fmt.Errorf("DOCKER_HOST %q: https is not supported, use tcp:// to a socket proxy", host)
	default:
		return nil, fmt.Errorf("DOCKER_HOST %q: unsupported scheme %q", host, u.Scheme)
	}
	api, err := client.New(
		client.WithHost(sdkHost),
		client.WithHTTPClient(&http.Client{Transport: tr, CheckRedirect: client.CheckRedirect}),
	)
	if err != nil {
		return nil, fmt.Errorf("DOCKER_HOST %q: %w", host, err)
	}
	return &Client{api: api}, nil
}

// IsNotFound reports whether err is a 404 from the daemon.
func IsNotFound(err error) bool { return cerrdefs.IsNotFound(err) }

// Ping checks the daemon is reachable.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_, err := c.api.Ping(ctx, client.PingOptions{})
	return err
}

// Filters encodes Engine API filters ({"label": ["a=b"], …}).
type Filters map[string][]string

func (f Filters) sdk() client.Filters {
	out := client.Filters{}
	for term, values := range f {
		out.Add(term, values...)
	}
	return out
}

// Container is the subset of /containers/json the Hub uses.
type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`  // running, exited, restarting, …
	Status string            `json:"Status"` // "Up 3 minutes (healthy)"
	Labels map[string]string `json:"Labels"`
}

// Name returns the primary container name without the leading "/".
func (c Container) Name() string {
	if len(c.Names) == 0 {
		if len(c.ID) > 12 {
			return c.ID[:12]
		}
		return c.ID
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// Project returns the compose project label.
func (c Container) Project() string { return c.Labels[LabelProject] }

// Service returns the compose service label.
func (c Container) Service() string { return c.Labels[LabelService] }

// ListContainers lists containers (including stopped ones) matching f.
func (c *Client) ListContainers(ctx context.Context, f Filters) ([]Container, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: f.sdk()})
	if err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(res.Items))
	for _, s := range res.Items {
		out = append(out, Container{ID: s.ID, Names: s.Names, Image: s.Image, State: string(s.State), Status: s.Status, Labels: s.Labels})
	}
	return out, nil
}

// ProjectFilter selects the containers of one compose project.
func ProjectFilter(project string) Filters {
	return Filters{"label": {LabelProject + "=" + project}}
}

func (c *Client) tty(ctx context.Context, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	res, err := c.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return false, err
	}
	return res.Container.Config != nil && res.Container.Config.Tty, nil
}
