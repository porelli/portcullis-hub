package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"

	na "github.com/portcullis/hub/internal/nodeagent"
)

// The public ingress probes (contract §20.4, §20.8, spike S6): every 10 s
// GET https://auth.<domain>/healthz with SNI auth.<domain> to each target's
// public address (5 s), ok = a completed handshake whose leaf names
// auth.<domain> and status 200 (the chain isn't verified: staging
// certificates count). The node's own site and address are probed too (a
// blind prober fails them all); that same-site results never count is the
// front door's rule. egress_ok is a verified TLS connect to the egress host.

const (
	probeEvery = 10 * time.Second
	keepRounds = 3
)

var probeTimeout = 5 * time.Second

var hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type prober struct {
	a      *Agent
	mu     sync.Mutex
	tg     *na.ProbeTargets
	rounds []na.ProbeRound
}

func newProber(a *Agent) *prober { return &prober{a: a} }

func (p *prober) load() {
	b, err := p.a.fs.read(targetsFile)
	if err != nil {
		return
	}
	var t na.ProbeTargets
	if json.Unmarshal(b, &t) == nil && validTargets(t) == nil {
		p.mu.Lock()
		p.tg = &t
		p.mu.Unlock()
	}
}

func validTargets(t na.ProbeTargets) error {
	if !hostRe.MatchString(t.Domain) || len(t.Domain) > 240 {
		return errStatus(400, "domain: not a domain name")
	}
	if t.EgressHost != "" && (!hostRe.MatchString(t.EgressHost) || len(t.EgressHost) > 253) {
		return errStatus(400, "egress_host: not a host name")
	}
	if t.Targets == nil || len(t.Targets) > 1024 {
		return errStatus(400, "targets: missing or more than 1024")
	}
	for _, x := range t.Targets {
		if !idRe.MatchString(x.Node) || !idRe.MatchString(x.Site) {
			return errStatus(400, "a target's node or site is malformed")
		}
		if _, err := netip.ParseAddr(x.Address); err != nil {
			if _, err := netip.ParseAddrPort(x.Address); err != nil {
				return errStatus(400, "target %s: its address isn't an IP address", x.Node)
			}
		}
	}
	return nil
}

// SetTargets is PUT /v1/probes/targets.
func (p *prober) SetTargets(t na.ProbeTargets) error {
	if err := validTargets(t); err != nil {
		return err
	}
	b, _ := json.Marshal(t)
	if err := p.a.fs.write(targetsFile, b, 0o600, 0o700); err != nil {
		return err
	}
	p.mu.Lock()
	p.tg = &t
	p.mu.Unlock()
	p.a.log.Info("probe targets set", "targets", len(t.Targets))
	return nil
}

// Rounds is GET /v1/probes (newest first).
func (p *prober) Rounds() na.Probes {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]na.ProbeRound, len(p.rounds))
	copy(out, p.rounds)
	return na.Probes{Rounds: out}
}

// Run probes every 10 s until ctx ends.
func (p *prober) Run(ctx context.Context) {
	t := time.NewTicker(probeEvery)
	defer t.Stop()
	for {
		p.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round runs one probe round (nothing without targets).
func (p *prober) Round(ctx context.Context) {
	p.mu.Lock()
	tg := p.tg
	p.mu.Unlock()
	if tg == nil {
		return
	}
	st := p.a.state()
	site := st.Site
	for _, x := range tg.Targets {
		if x.Node == st.ID {
			site = x.Site
		}
	}
	type res struct {
		node  string
		class string
	}
	ch := make(chan res, len(tg.Targets))
	var wg sync.WaitGroup
	for _, x := range tg.Targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch <- res{x.Node, p.probe(ctx, tg.Domain, x.Address)}
		}()
	}
	egress := make(chan bool, 1)
	go func() { egress <- p.egress(ctx, tg.EgressHost) }()
	wg.Wait()
	close(ch)
	results := map[string]na.ProbeResult{}
	reached := false
	for r := range ch {
		cur, seen := results[r.node]
		switch {
		case r.class == na.ClassOK:
			results[r.node] = na.ProbeResult{OK: true, Class: na.ClassOK}
			reached = true
		case !seen:
			results[r.node] = na.ProbeResult{OK: false, Class: r.class}
		case !cur.OK && r.class < cur.Class:
			// A node with several addresses: the lowest class name, so a
			// round's answer doesn't depend on goroutine order.
			results[r.node] = na.ProbeResult{OK: false, Class: r.class}
		}
	}
	round := na.ProbeRound{T: p.a.cfg.Now().UTC().Format(time.RFC3339), Prober: st.ID, Site: site,
		ReachedAny: reached, EgressOK: <-egress, Results: results}
	p.mu.Lock()
	p.rounds = append([]na.ProbeRound{round}, p.rounds...)
	if len(p.rounds) > keepRounds {
		p.rounds = p.rounds[:keepRounds]
	}
	p.mu.Unlock()
}

func target443(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.String()
	}
	return net.JoinHostPort(addr, "443")
}

// probe classifies one GET https://auth.<domain>/healthz at addr.
func (p *prober) probe(ctx context.Context, domain, addr string) string {
	name := "auth." + domain
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	raw, err := p.a.cfg.Dial(ctx, "tcp", target443(addr))
	if err != nil {
		return dialClass(ctx, err)
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	// #nosec G402: the chain isn't verified (staging certificates count);
	// the leaf must name auth.<domain>.
	tc := tls.Client(raw, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		if isTimeout(ctx, err) {
			return na.ClassTimeout
		}
		return na.ClassTLS
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].VerifyHostname(name) != nil {
		return na.ClassTLS
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+name+"/healthz", nil)
	req.Header.Set("User-Agent", "portcullis-nodeagent-probe")
	req.Close = true
	if err := req.Write(tc); err != nil {
		if isTimeout(ctx, err) {
			return na.ClassTimeout
		}
		return na.ClassHTTPStatus
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		if isTimeout(ctx, err) {
			return na.ClassTimeout
		}
		return na.ClassHTTPStatus
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return na.ClassHTTPStatus
	}
	return na.ClassOK
}

func isTimeout(ctx context.Context, err error) bool {
	var ne net.Error
	return ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// dialClass: a connect that timed out is timeout; any other connect
// failure (refused, no route, unreachable) is refused.
func dialClass(ctx context.Context, err error) string {
	if isTimeout(ctx, err) && !errors.Is(err, syscall.ECONNREFUSED) {
		return na.ClassTimeout
	}
	return na.ClassRefused
}

// egress: a verified TLS connect to the DNS provider's API host.
func (p *prober) egress(ctx context.Context, host string) bool {
	if host == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	raw, err := p.a.cfg.Dial(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return false
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: p.a.cfg.EgressRoots, MinVersion: tls.VersionTLS12})
	return tc.HandshakeContext(ctx) == nil
}

// stop ends probing (the uninstall).
func (p *prober) stop() {
	p.mu.Lock()
	p.tg = nil
	p.rounds = nil
	p.mu.Unlock()
}
