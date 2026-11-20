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
// routes the Hub's cluster-node operations use: the health read and the
// k3s uninstall after a cooperative removal. Every request goes through
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
