// Package docker is a minimal Docker Engine API client over net/http
// (DOCKER_HOST = tcp://host:port or unix:///path). It covers only what the
// Hub needs: container listing, logs, exec and events.
//
// Paths are unversioned so the daemon picks its current API version; that
// keeps working across Engine releases that raise the minimum API version,
// and socket proxies match both forms.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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

// Client talks to one Docker daemon.
type Client struct {
	base string
	http *http.Client // bounded requests
	// stream has no overall timeout: used for logs/exec/events, which are
	// bounded by the caller's context instead.
	stream *http.Client
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
	tr := &http.Transport{
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0,
	}
	var base string
	switch u.Scheme {
	case "unix":
		sock := u.Path
		if sock == "" {
			return nil, fmt.Errorf("invalid DOCKER_HOST %q: missing socket path", host)
		}
		d := &net.Dialer{Timeout: 10 * time.Second}
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", sock)
		}
		base = "http://docker"
	case "tcp", "http":
		if u.Host == "" {
			return nil, fmt.Errorf("invalid DOCKER_HOST %q: missing host:port", host)
		}
		tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
		base = "http://" + u.Host
	case "https":
		// TLS to the daemon would need client certs; the Hub talks to a
		// socket proxy on an internal network instead.
		return nil, fmt.Errorf("DOCKER_HOST %q: https is not supported, use tcp:// to a socket proxy", host)
	default:
		return nil, fmt.Errorf("DOCKER_HOST %q: unsupported scheme %q", host, u.Scheme)
	}
	return &Client{
		base:   base,
		http:   &http.Client{Transport: tr, Timeout: 30 * time.Second},
		stream: &http.Client{Transport: tr},
	}, nil
}

// APIError is a non-2xx response from the daemon.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("docker API: HTTP %d: %s", e.Status, e.Message)
}

// IsNotFound reports whether err is a 404 from the daemon.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

func (c *Client) do(ctx context.Context, cl *http.Client, method, path string, q url.Values, body interface{}) (*http.Response, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var m struct {
			Message string `json:"message"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &m) == nil && m.Message != "" {
			msg = m.Message
		}
		return nil, &APIError{Status: resp.StatusCode, Message: msg}
	}
	return resp, nil
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, out interface{}) error {
	resp, err := c.do(ctx, c.http, http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// Ping checks the daemon is reachable.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, c.http, http.MethodGet, "/_ping", nil, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Filters encodes Engine API filters ({"label": ["a=b"], …}).
type Filters map[string][]string

func (f Filters) encode() string {
	b, _ := json.Marshal(map[string][]string(f))
	return string(b)
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
	q := url.Values{"all": {"1"}}
	if len(f) > 0 {
		q.Set("filters", f.encode())
	}
	var out []Container
	if err := c.getJSON(ctx, "/containers/json", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ProjectFilter selects the containers of one compose project.
func ProjectFilter(project string) Filters {
	return Filters{"label": {LabelProject + "=" + project}}
}

type inspect struct {
	Config struct {
		Tty bool `json:"Tty"`
	} `json:"Config"`
}

func (c *Client) tty(ctx context.Context, id string) (bool, error) {
	var in inspect
	if err := c.getJSON(ctx, "/containers/"+url.PathEscape(id)+"/json", nil, &in); err != nil {
		return false, err
	}
	return in.Config.Tty, nil
}
