package nodeagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/jsonstrict"
)

// The Hub's client of a node's nodeagent (contract §20.4), over pcmesh at
// https://<mesh ip>:7443 with the hub.control certificate. Only the
// routes the Hub's cluster-node operations use: the health read, the mesh
// peer plan and its RTT, the host checks (the HA checklist's watchdog
// before fencing runs) and the k3s uninstall after a cooperative removal. Every request goes through
// fsutil.Do (the write fence, §20.5).

// Port is the nodeagent API's port on the node's mesh address.
const Port = 7443

// ServerName is node id's node-cluster certificate name.
func ServerName(id string) string { return id + ".cluster.portcullis.internal" }

// Health is GET /v1/health.
type Health struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	MeshIP  string `json:"mesh_ip"`
	MeshPub string `json:"mesh_pub"`
	K3s     string `json:"k3s"`
	Time    string `json:"time"`
	// Peers is each plan peer's WireGuard state (by peer id): its latest
	// handshake (RFC 3339 UTC, null: none yet) and the endpoint the device
	// uses for it (null: none). The Hub confirms a public endpoint as
	// reachable from it (contract §20.11).
	Peers map[string]PeerStatus `json:"peers"`
}

// PeerStatus is one peer's state in GET /v1/health.
type PeerStatus struct {
	LatestHandshake jsonstrict.Nullable[string] `json:"latest_handshake"`
	Endpoint        jsonstrict.Nullable[string] `json:"endpoint"`
}

// Client is one node's nodeagent: BaseURL (https://<mesh ip>:7443) and
// TLS (the hub.control certificate, the pki_node CA, ServerName(id)).
// HTTP replaces the client built from TLS (tests).
type Client struct {
	BaseURL string
	TLS     *tls.Config
	HTTP    *http.Client

	once sync.Once
	hc   *http.Client
}

func (c *Client) client() *http.Client {
	c.once.Do(func() {
		if c.HTTP != nil {
			c.hc = c.HTTP
			return
		}
		c.hc = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: c.TLS, TLSHandshakeTimeout: 10 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	})
	return c.hc
}

// Health reads GET /v1/health.
func (c *Client) Health(ctx context.Context) (Health, error) {
	var h Health
	err := c.do(ctx, http.MethodGet, "/v1/health", nil, &h, http.StatusOK)
	return h, err
}

// Uninstall is POST /v1/k3s/uninstall: the node removes k3s and pcmesh
// and stops its nodeagent.
func (c *Client) Uninstall(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/k3s/uninstall", struct{}{}, nil, http.StatusNoContent)
}

// PutMeshPeers is PUT /v1/mesh/peers: the node's full peer plan.
func (c *Client) PutMeshPeers(ctx context.Context, p MeshPlan) error {
	return c.do(ctx, http.MethodPut, "/v1/mesh/peers", p, nil, http.StatusNoContent)
}

// RTT is GET /v1/mesh/rtt: the p95 (ms) of 20 echo rounds to each peer.
func (c *Client) RTT(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	err := c.do(ctx, http.MethodGet, "/v1/mesh/rtt", nil, &out, http.StatusOK)
	return out, err
}

// Checks is GET /v1/checks: the node's host checks.
func (c *Client) Checks(ctx context.Context) (Checks, error) {
	var out Checks
	err := c.do(ctx, http.MethodGet, "/v1/checks", nil, &out, http.StatusOK)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, want int) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := fsutil.Do(c.client(), req)
	if err != nil {
		return fmt.Errorf("nodeagent: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return fmt.Errorf("nodeagent: its answer is unreadable or over 1 MiB")
	}
	if resp.StatusCode != want {
		return fmt.Errorf("nodeagent answered %d to %s %s", resp.StatusCode, method, path)
	}
	if out != nil {
		if err := jsonstrict.Decode(b, out); err != nil {
			return fmt.Errorf("nodeagent's answer to %s doesn't decode: %v", path, err)
		}
	}
	return nil
}
