// Package agent is the Hub's runtime.Instances backend for an instance
// placed on a worker server (contract §17.4): every method is one agent
// API v1 call (agentapi.Routes), over mTLS inside the WireGuard tunnel,
// reached through link's control CONNECT (HUB_LINK_PROXY). Everything the
// agent answers is untrusted: size-capped, strictly decoded, never
// executed and never used as a path.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	"github.com/portcullis/hub/internal/agentapi"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/servers"
	"github.com/portcullis/hub/internal/version"
)

// Dialer opens a TCP connection to addr (the agent's <tunnel ip>:7443);
// in production a CONNECT through link (LinkDialer).
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// LinkDialer dials through link's control CONNECT listener (contract
// §17.2: only CONNECT <peer ip>:7443).
type LinkDialer struct{ Proxy string }

func (d LinkDialer) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "tcp", d.Proxy)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(15 * time.Second))
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("link refused the control tunnel: %s", resp.Status)
	}
	c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// Config is one worker server's backend.
type Config struct {
	ServerID string
	TunnelIP netip.Addr
	// CACert is the pki_node CA; SPKI the pinned sha256 of the worker
	// certificate's SubjectPublicKeyInfo, Serial its serial (hex, lower
	// case) — both from state (contract §17.4).
	CACert *x509.Certificate
	SPKI   []byte
	Serial string
	// ControlCert is the Hub's hub.control certificate.
	ControlCert tls.Certificate
	Dial        Dialer
	// Kind is the worker's runtime (from its last /v1/info); Env the
	// Hub's own compose environment (contract §17.4).
	Kind runtime.Kind
	Env  []string
	// OnMismatch is called when the worker presents another identity
	// (the server goes offline with server_identity_mismatch).
	OnMismatch func()
	// HubVersion is the Hub's version ("" = internal/version's): only an
	// agent servers.Compatible pairs with it gets any call but GET
	// /v1/info (so a new request field never reaches an agent that
	// doesn't know it).
	HubVersion string
	// Enrolling: the worker is still enrolling (contract §17.5 step 3):
	// it presents a self-signed certificate, so nothing is pinned; the
	// agent checks the Hub instead (ca_sha256). The SPKI it presented is
	// kept (PeerSPKI) for the enrolment proof, which binds the channel.
	Enrolling bool
}

// ErrIncompatible: the agent's version doesn't go with the Hub's.
var ErrIncompatible = errors.New("server_agent_incompatible")

// SameSerial compares a certificate serial with a stored one (Vault's
// "0a:1b:…" form or plain hex, any case).
func SameSerial(n *big.Int, stored string) bool {
	v, ok := new(big.Int).SetString(strings.ReplaceAll(strings.TrimSpace(stored), ":", ""), 16)
	return ok && n != nil && v.Cmp(n) == 0
}

// ErrIdentityMismatch: the worker's certificate isn't the pinned one.
var ErrIdentityMismatch = errors.New("server_identity_mismatch: the worker presented another certificate than the one pinned")

// Error is a refusal or failure answered by the agent (or the transport):
// its HTTP status (502 for transport and identity failures) and message.
type Error struct {
	Status int
	Msg    string
	// AgentStatus is the status the agent answered (0: none, a transport
	// or identity failure); Status may be 502 for it (passedStatuses).
	AgentStatus int
	err         error
}

func (e *Error) Error() string   { return e.Msg }
func (e *Error) HTTPStatus() int { return e.Status }
func (e *Error) Unwrap() error   { return e.err }
func (e *Error) NotFound() bool  { return e.Status == http.StatusNotFound }
func (e *Error) Is(t error) bool { return t == cerrdefs.ErrNotFound && e.Status == http.StatusNotFound }

// passedStatuses are the agent statuses the Hub passes on (with the
// agent's message, sanitized and capped); any other is 502.
var passedStatuses = map[int]bool{400: true, 404: true, 409: true, 422: true, 503: true}

// agentError is the Hub's view of an agent's error answer: a worker is
// untrusted, so only passedStatuses keep their code and message.
func (c *client) agentError(status int, msg string) *Error {
	if !passedStatuses[status] {
		return &Error{Status: http.StatusBadGateway, Msg: "the server " + c.cfg.ServerID + " answered unexpectedly", AgentStatus: status}
	}
	msg = sanitize(msg)
	if msg == "" {
		msg = "the server " + c.cfg.ServerID + " refused the call"
	}
	return &Error{Status: status, Msg: msg, AgentStatus: status}
}

// sanitize keeps printable text only, at most 200 runes.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return ' '
		}
		return r
	}, s)
	return clip(strings.TrimSpace(s))
}

func transportErr(err error) error {
	if errors.Is(err, ErrIdentityMismatch) {
		return &Error{Status: http.StatusBadGateway, Msg: ErrIdentityMismatch.Error(), err: ErrIdentityMismatch}
	}
	return &Error{Status: http.StatusBadGateway, Msg: "the worker can't be reached: " + clip(err.Error()), err: err}
}

func clip(s string) string {
	if r := []rune(s); len(r) > 200 {
		return string(r[:199]) + "…"
	}
	return s
}

// client is the HTTP side: a transport that only ever dials the agent
// through cfg.Dial and verifies its pinned identity.
type client struct {
	cfg  Config
	base string
	http *http.Client

	mu           sync.Mutex
	agentVersion string
	peerSPKI     []byte
}

// gate refuses every call but /v1/info to an agent of an incompatible
// version (its version read once, then from each /v1/info).
func (c *client) gate(ctx context.Context) error {
	c.mu.Lock()
	v := c.agentVersion
	c.mu.Unlock()
	if v == "" {
		var i agentapi.Info
		if err := c.json(ctx, "GET", agentapi.Routes["Info"][0].Path, nil, nil, &i, agentapi.MaxInfo); err != nil {
			return err
		}
		c.setAgentVersion(i.AgentVersion)
		v = i.AgentVersion
	}
	hub := c.cfg.HubVersion
	if hub == "" {
		hub = version.Version
	}
	if !servers.Compatible(hub, v) {
		return &Error{Status: http.StatusConflict, Msg: fmt.Sprintf("server_agent_incompatible: the worker's agent is %s, the Hub %s (the same or the previous minor): upgrade the worker", clip(v), hub), err: ErrIncompatible}
	}
	return nil
}

func (c *client) setAgentVersion(v string) {
	c.mu.Lock()
	c.agentVersion = v
	c.mu.Unlock()
}

func newClient(cfg Config) *client {
	roots := x509.NewCertPool()
	if cfg.CACert != nil {
		roots.AddCert(cfg.CACert)
	}
	addr := netip.AddrPortFrom(cfg.TunnelIP, 7443).String()
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		ServerName:   servers.NodeName(cfg.ServerID),
		Certificates: []tls.Certificate{cfg.ControlCert},
	}
	c := &client{cfg: cfg, base: "https://" + servers.NodeName(cfg.ServerID)}
	tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return ErrIdentityMismatch
		}
		leaf := cs.PeerCertificates[0]
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if cfg.Enrolling {
			c.mu.Lock()
			c.peerSPKI = sum[:]
			c.mu.Unlock()
			return nil
		}
		if !bytes.Equal(sum[:], cfg.SPKI) || !SameSerial(leaf.SerialNumber, cfg.Serial) {
			if cfg.OnMismatch != nil {
				cfg.OnMismatch()
			}
			return ErrIdentityMismatch
		}
		return nil
	}
	if cfg.Enrolling {
		// Only the SPKI is read (above); the proof binds it.
		tlsCfg.InsecureSkipVerify = true
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			raw, err := cfg.Dial.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, tlsCfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
		MaxIdleConnsPerHost: 4, IdleConnTimeout: 60 * time.Second, ForceAttemptHTTP2: false,
	}
	c.http = &http.Client{Transport: tr}
	return c
}

// path fills a route's {name} wildcards (each value path-escaped).
func path(r agentapi.Route, vals ...string) string {
	p := r.Path
	for i := 0; i+1 < len(vals); i += 2 {
		p = strings.Replace(p, "{"+vals[i]+"}", url.PathEscape(vals[i+1]), 1)
	}
	return p
}

// do sends one request; a non-2xx answer becomes *Error from the agent's
// {"error"} (≤ MaxJSON read, strictly decoded, else a generic message).
func (c *client) do(ctx context.Context, method, p string, q url.Values, body io.Reader, ctype string, hdr map[string]string) (*http.Response, error) {
	if p != agentapi.Routes["Info"][0].Path {
		if err := c.gate(ctx); err != nil {
			return nil, err
		}
	}
	u := c.base + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportErr(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var e agentapi.Error
		msg := ""
		if agentapi.Decode(resp.Body, agentapi.MaxJSON, &e) == nil {
			msg = e.Error
		}
		return nil, c.agentError(resp.StatusCode, msg)
	}
	return resp, nil
}

// json sends v (nil: no body) and decodes the answer into out (nil: none)
// at most max bytes, strictly.
func (c *client) json(ctx context.Context, method, p string, q url.Values, v, out any, max int64) error {
	var body io.Reader
	ct := ""
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body, ct = bytes.NewReader(b), "application/json"
	}
	resp, err := c.do(ctx, method, p, q, body, ct, opHeader(ctx))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, agentapi.MaxJSON))
		return nil
	}
	if err := agentapi.Decode(resp.Body, max, out); err != nil {
		return &Error{Status: http.StatusBadGateway, Msg: "the agent's answer is refused: " + clip(err.Error()), err: err}
	}
	return nil
}

// ndjson reads lines (each ≤ MaxLine: a longer one is dropped), calling
// fn for each until EOF.
func ndjson(r io.Reader, fn func([]byte) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br)
		if len(line) > 0 && line != nil {
			if ferr := fn(line); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

var errLong = errors.New("line over the cap")

func readLine(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(out)+len(chunk) > agentapi.MaxLine+1 {
			// Drop the line: skip to its end.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil && err != io.EOF {
				return nil, err
			}
			return nil, err
		}
		out = append(out, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimRight(out, "\n"), err
	}
}

// opKey carries the op id for OpHeader (WithOp).
type opKey struct{}

// WithOp names ctx's long calls with the Hub's op id (Stop cancels it on
// the agent too: DELETE /v1/ops/{op}).
func WithOp(ctx context.Context, op string) context.Context {
	return context.WithValue(ctx, opKey{}, op)
}

func opHeader(ctx context.Context) map[string]string {
	if op, ok := ctx.Value(opKey{}).(string); ok && op != "" {
		return map[string]string{agentapi.OpHeader: op}
	}
	return nil
}

func itoa(n int) string { return strconv.Itoa(n) }
