package nodeadm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/portcullis/hub/internal/fsutil"
	"github.com/portcullis/hub/internal/jsonstrict"
)

// DefaultURL is nodeadm's internal listener (contract §20.2).
const DefaultURL = "https://nodeadm.portcullis-nodeadm.svc:8443"

// ServerName is the SAN of nodeadm's serving certificate (node-nodeadm),
// verified against the pki_node CA.
const ServerName = "nodeadm.portcullis-nodeadm.svc"

// The limits of one call.
const (
	// maxBody bounds a request body and every answer but the snapshot
	// (nodeadm's own 64 KiB).
	maxBody = 64 << 10
	// maxSnapshot bounds the snapshot (it lists every pod).
	maxSnapshot = 16 << 20
	// callTimeout bounds a short call; longTimeout a drain or a
	// cooperative removal (nodeadm drains for at most 10 min).
	callTimeout = 30 * time.Second
	longTimeout = 15 * time.Minute
)

// The error kinds callers branch on (§20.2).
const (
	KindQuorumMinimum    = "quorum_minimum"
	KindReplicaMinimum   = "replica_minimum"
	KindUnknownNode      = "unknown_node"
	KindProofInvalid     = "proof_invalid"
	KindWaitingAdmission = "waiting_admission"
	KindMeshPending      = "mesh_pending"
	KindNotLeader        = "not_leader"
)

// APIError is an answer outside 2xx: its status, nodeadm's kind ("" when
// it has none) and its text (one line, at most 200 characters).
type APIError struct {
	Status int
	Kind   string
	Text   string
}

func (e *APIError) Error() string {
	if e.Text != "" {
		return e.Text
	}
	return fmt.Sprintf("nodeadm answered %d", e.Status)
}

// IsKind: err is an APIError of kind k.
func IsKind(err error, k string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Kind == k
}

// Client is the Hub's nodeadm client: BaseURL (DefaultURL) and the TLS
// configuration (the hub.control client certificate, the pki_node CA as
// the only root, ServerName). HTTP, when set, replaces the client built
// from TLS (tests). Every request goes through fsutil.Do: a write is
// refused, and cancelled in flight, once the Hub stands by (§20.5).
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
		tr := &http.Transport{Proxy: nil, TLSClientConfig: c.TLS, ForceAttemptHTTP2: true, MaxIdleConns: 4, IdleConnTimeout: time.Minute,
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: longTimeout}
		c.hc = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	})
	return c.hc
}

// IssueCode is POST /v1/codes: a join code v2 for a cluster node.
func (c *Client) IssueCode(ctx context.Context, r CodeRequest) (CodeAnswer, error) {
	var a CodeAnswer
	err := c.do(ctx, http.MethodPost, "/v1/codes", r, &a, http.StatusCreated, maxBody, callTimeout)
	if err != nil {
		return CodeAnswer{}, err
	}
	if !strings.HasPrefix(a.Code, "pcj2.") {
		return CodeAnswer{}, errors.New("nodeadm answered no join code")
	}
	return a, nil
}

// Cluster is GET /v1/cluster.
func (c *Client) Cluster(ctx context.Context) (Snapshot, error) {
	var s Snapshot
	if err := c.do(ctx, http.MethodGet, "/v1/cluster", nil, &s, http.StatusOK, maxSnapshot, callTimeout); err != nil {
		return Snapshot{}, err
	}
	if s.V != 1 {
		return Snapshot{}, fmt.Errorf("nodeadm's snapshot is version %d (1 is understood)", s.V)
	}
	return s, nil
}

// SetLabels is PUT /v1/nodes/{id}/labels.
func (c *Client) SetLabels(ctx context.Context, id string, l Labels) error {
	return c.do(ctx, http.MethodPut, "/v1/nodes/"+url.PathEscape(id)+"/labels", l, nil, http.StatusNoContent, maxBody, callTimeout)
}

// Cordon is POST /v1/nodes/{id}/cordon.
func (c *Client) Cordon(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/nodes/"+url.PathEscape(id)+"/cordon", struct{}{}, nil, http.StatusNoContent, maxBody, callTimeout)
}

// Uncordon is POST /v1/nodes/{id}/uncordon.
func (c *Client) Uncordon(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/nodes/"+url.PathEscape(id)+"/uncordon", struct{}{}, nil, http.StatusNoContent, maxBody, callTimeout)
}

// Drain is POST /v1/nodes/{id}/drain (at most 10 min on nodeadm's side).
func (c *Client) Drain(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/nodes/"+url.PathEscape(id)+"/drain", struct{}{}, nil, http.StatusNoContent, maxBody, longTimeout)
}

// Remove is DELETE /v1/nodes/{id}?mode=<mode>.
func (c *Client) Remove(ctx context.Context, id string, mode RemoveMode) error {
	if mode != Cooperative && mode != Revoke {
		return fmt.Errorf("mode must be cooperative or revoke")
	}
	return c.do(ctx, http.MethodDelete, "/v1/nodes/"+url.PathEscape(id)+"?mode="+string(mode), nil, nil, http.StatusNoContent, maxBody, longTimeout)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, want int, limit int64, timeout time.Duration) error {
	base := c.BaseURL
	if base == "" {
		base = DefaultURL
	}
	var body io.Reader
	if in != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(in); err != nil {
			return err
		}
		b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		if len(b) > maxBody {
			return errors.New("the request to nodeadm is over 64 KiB")
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := fsutil.Do(c.client(), req)
	if err != nil {
		return fmt.Errorf("nodeadm: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("nodeadm: reading its answer: %w", err)
	}
	if int64(len(b)) > limit {
		return fmt.Errorf("nodeadm's answer is over %d bytes", limit)
	}
	if resp.StatusCode != want {
		return apiError(resp.StatusCode, b)
	}
	if out == nil {
		return nil
	}
	if err := jsonstrict.Decode(b, out); err != nil {
		return fmt.Errorf("nodeadm's answer to %s %s doesn't decode: %v", method, strings.SplitN(path, "?", 2)[0], err)
	}
	return nil
}

// apiError reads nodeadm's {"error", "kind"?} (anything else: the status
// only). The text is one clipped line without control characters.
func apiError(status int, b []byte) error {
	var e struct {
		Error string `json:"error"`
		Kind  string `json:"kind"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil {
		e.Error, e.Kind = "", ""
	}
	return &APIError{Status: status, Kind: clean(e.Kind, 40), Text: clean(e.Error, 200)}
}

func clean(s string, n int) string {
	r := []rune(s)
	for i, c := range r {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			r[i] = ' '
		}
	}
	if len(r) > n {
		r = r[:n]
	}
	return strings.TrimSpace(string(r))
}
