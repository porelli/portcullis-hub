package hub

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// The MTA-STS policy check (contract §19.7, P12): every 6 h the Hub
// fetches each mail domain's /.well-known/mta-sts.txt through Traefik's
// websecure entrypoint on portcullis-proxy (SNI and Host mta-sts.<e>;
// content only: the local hop's chain isn't verified) and refuses a
// policy without exactly one mx: line equal to MAIL_HOSTNAME and
// version: STSv1 (doctor mail_records_wrong). Skipped while the domain's
// MTA-STS is off (VPN server mode included).

const (
	// DefaultMailPolicyAddr is Traefik's websecure on portcullis-proxy.
	DefaultMailPolicyAddr = "traefik:443"
	// MailPolicyEvery is the check's period.
	MailPolicyEvery = 6 * time.Hour
	// mailPolicyMax bounds a policy (RFC 8461 policies are tiny).
	mailPolicyMax = 64 << 10
)

// mailPolicyAddr is the address the policy is fetched from.
func (h *Hub) mailPolicyAddr() string {
	if h.cfg.MailPolicyAddr != "" {
		return h.cfg.MailPolicyAddr
	}
	return DefaultMailPolicyAddr
}

// checkMTASTSPolicy fetches and judges domain's policy; nil when it is
// right or the check is skipped. The outcome is recorded for the doctor.
func (h *Hub) checkMTASTSPolicy(ctx context.Context, domain string) error {
	e := strings.ToLower(domain)
	if h.mailPolicySkipped(ctx, e) {
		h.recordMailPolicy(e, "")
		return nil
	}
	err := h.fetchMTASTSPolicy(ctx, e)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	h.recordMailPolicy(e, msg)
	return err
}

// mailPolicySkipped: MTA-STS is off for e — the well-known router isn't
// on websecure (VPN server mode) or the provider reports mode off.
func (h *Hub) mailPolicySkipped(ctx context.Context, e string) bool {
	h.mu.RLock()
	ep := h.mailEntrypointsLocked()
	h.mu.RUnlock()
	if !strings.Contains(ep, "websecure") {
		return true
	}
	api := h.mailClient()
	if api == nil {
		return true
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := api.Status(sctx)
	if err != nil {
		return true // unknown: nothing judged (the provider's own checks report it)
	}
	for _, m := range st.MTASTS {
		if strings.EqualFold(m.Domain, e) {
			return m.Mode == "off"
		}
	}
	return true // no MTA-STS state for e: nothing published yet
}

// fetchMTASTSPolicy reads and judges e's policy.
func (h *Hub) fetchMTASTSPolicy(ctx context.Context, e string) error {
	host := "mta-sts." + e
	addr := h.mailPolicyAddr()
	tr := &http.Transport{
		// A local hop with staging certificates: content only.
		TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true}, // #nosec G402 -- P12: the content is judged, not the chain
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		Proxy: nil,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/.well-known/mta-sts.txt", nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("%s: the MTA-STS policy can't be fetched: %v", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: the MTA-STS policy answers HTTP %d", host, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, mailPolicyMax+1))
	if err != nil || len(b) > mailPolicyMax {
		return fmt.Errorf("%s: the MTA-STS policy can't be read", host)
	}
	return judgeMTASTSPolicy(host, b, h.mailCore().Hostname)
}

// judgeMTASTSPolicy: version: STSv1 and exactly one mx: equal to
// mailHost (RFC 8461 key: value lines, CRLF or LF).
func judgeMTASTSPolicy(host string, b []byte, mailHost string) error {
	version, mx := "", []string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimRight(sc.Text(), "\r"), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "version":
			version = v
		case "mx":
			mx = append(mx, v)
		}
	}
	if version != "STSv1" {
		return fmt.Errorf("%s: the MTA-STS policy isn't version: STSv1", host)
	}
	if len(mx) != 1 || !strings.EqualFold(strings.TrimSuffix(mx[0], "."), mailHost) {
		return fmt.Errorf("%s: the MTA-STS policy must name exactly one mx: %s (it names %s)", host, mailHost, strings.Join(mx, ", "))
	}
	return nil
}

// recordMailPolicy keeps e's policy refusal ("" = none).
func (h *Hub) recordMailPolicy(e, msg string) {
	h.mailDNSProb.mu.Lock()
	defer h.mailDNSProb.mu.Unlock()
	if h.mailDNSProb.policy == nil {
		h.mailDNSProb.policy = map[string]string{}
	}
	if msg == "" {
		delete(h.mailDNSProb.policy, e)
		return
	}
	if h.mailDNSProb.policy[e] != msg {
		log.Printf("mail: %s", msg)
	}
	h.mailDNSProb.policy[e] = msg
}

// RunMailPolicyCheck checks every mail domain's policy every `every`
// (main: 6 h), the first time after `every` too.
func (h *Hub) RunMailPolicyCheck(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if h.mailClient() == nil {
			continue
		}
		h.mu.RLock()
		ds := h.mailDomainsLocked(true)
		h.mu.RUnlock()
		for _, d := range ds {
			h.checkMTASTSPolicy(ctx, d)
		}
	}
}
