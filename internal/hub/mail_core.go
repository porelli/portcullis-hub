package hub

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
)

// Core env keys of mail (contract §2, §19.1): the whole PORTCULLIS_MAIL
// prefix is core's, never a template variable. Core writes exactly these
// (mail provider plan Task 20); the Hub validates each one strictly.
const (
	VarMailPrefix            = "PORTCULLIS_MAIL"
	VarMail                  = "PORTCULLIS_MAIL"
	VarMailHostname          = "PORTCULLIS_MAIL_HOSTNAME"
	VarMailSubmissionLANOnly = "PORTCULLIS_MAIL_SUBMISSION_LAN_ONLY"
	// VarMailClientIP is core's client-address mode (preserved |
	// rewritten), sent as MailState v2 client_ip.
	VarMailClientIP = "PORTCULLIS_MAIL_CLIENT_IP"
	// The portcullis-mail-api network (§19.1).
	VarMailAPISubnet     = "PORTCULLIS_MAIL_API_SUBNET"
	VarMailAPIHubIP      = "PORTCULLIS_MAIL_API_HUB_IP"
	VarMailAPIProviderIP = "PORTCULLIS_MAIL_API_PROVIDER_IP"
)

// The portcullis-mail-api defaults (contract §19.1).
var (
	DefaultMailAPISubnet     = netip.MustParsePrefix("172.31.255.16/28")
	DefaultMailAPIHubIP      = netip.MustParseAddr("172.31.255.18")
	DefaultMailAPIProviderIP = netip.MustParseAddr("172.31.255.19")
)

// coreOnlyVar: a core env key the Hub never copies into an instance.
func coreOnlyVar(k string) bool {
	return k == VarUnprivilegedPortStart || strings.HasPrefix(k, VarMailPrefix)
}

// mailReservedLabels are reserved on every mail domain (contract §5).
var mailReservedLabels = []string{"mail", "mta-sts", "autoconfig", "autodiscover"}

// mailPorts are the host ports the wired provider gets (contract §19.2).
var mailPorts = []int{25, 465, 587, 993}

// mailCoreEnv is the mail part of core.env.
type mailCoreEnv struct {
	On              bool
	Hostname        string
	SubmissionLAN   bool
	HostnameMissing bool
	// ClientIPRewritten: PORTCULLIS_MAIL_CLIENT_IP isn't exactly
	// preserved.
	ClientIPRewritten bool
	// APISubnet, HubIP, ProviderIP: portcullis-mail-api (the defaults
	// when unset).
	APISubnet         netip.Prefix
	HubIP, ProviderIP netip.Addr
	// Err: a mail key holds a value the contract doesn't allow; the slot
	// then counts as closed (fail closed) and the doctor says why.
	Err string
}

// mailHostnameRe is MAIL_HOSTNAME's shape (a lowercase DNS name).
var mailHostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// mailCore reads core.env's mail keys. Fail closed: PORTCULLIS_MAIL is on
// only when it says exactly "on" and every other mail key is valid.
func (h *Hub) mailCore() mailCoreEnv {
	if c := h.mailCoreForTest.Load(); c != nil {
		m := *c
		if !m.APISubnet.IsValid() {
			m.APISubnet, m.HubIP, m.ProviderIP = DefaultMailAPISubnet, DefaultMailAPIHubIP, DefaultMailAPIProviderIP
		}
		return m
	}
	return parseMailCore(readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env")), h.cfg.Domain)
}

// parseMailCore is mailCore over core's env (domain: the main domain).
func parseMailCore(core map[string]string, domain string) mailCoreEnv {
	m := mailCoreEnv{APISubnet: DefaultMailAPISubnet, HubIP: DefaultMailAPIHubIP, ProviderIP: DefaultMailAPIProviderIP}
	var bad []string
	get := func(k string) (string, bool) {
		v, ok := core[k]
		return strings.TrimSpace(v), ok
	}
	switch v, _ := get(VarMail); v {
	case "on":
		m.On = true
	case "", "off":
	default:
		bad = append(bad, VarMail)
	}
	m.Hostname = strings.ToLower(strings.TrimSuffix(core[VarMailHostname], "."))
	m.Hostname = strings.TrimSpace(m.Hostname)
	if m.Hostname == "" {
		m.HostnameMissing = true
		m.Hostname = "mail." + strings.ToLower(domain)
	} else if !mailHostnameRe.MatchString(m.Hostname) || len(m.Hostname) > 253 {
		bad = append(bad, VarMailHostname)
	}
	switch v, _ := get(VarMailSubmissionLANOnly); v {
	case "true":
		m.SubmissionLAN = true
	case "", "false":
	default:
		bad = append(bad, VarMailSubmissionLANOnly)
	}
	switch v, ok := get(VarMailClientIP); {
	case v == mailprovider.ClientIPPreserved:
	case v == mailprovider.ClientIPRewritten, !ok || v == "":
		// Unknown is rewritten (the provider then runs degraded, §19.8).
		m.ClientIPRewritten = true
	default:
		m.ClientIPRewritten = true
		bad = append(bad, VarMailClientIP)
	}
	if v, ok := get(VarMailAPISubnet); ok && v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() > 29 {
			bad = append(bad, VarMailAPISubnet)
		} else {
			m.APISubnet = p
		}
	}
	for _, a := range []struct {
		key string
		dst *netip.Addr
	}{{VarMailAPIHubIP, &m.HubIP}, {VarMailAPIProviderIP, &m.ProviderIP}} {
		if v, ok := get(a.key); ok && v != "" {
			ip, err := netip.ParseAddr(v)
			if err != nil || !ip.Is4() {
				bad = append(bad, a.key)
				continue
			}
			*a.dst = ip
		}
	}
	for _, a := range []struct {
		key string
		ip  netip.Addr
	}{{VarMailAPIHubIP, m.HubIP}, {VarMailAPIProviderIP, m.ProviderIP}} {
		if !slices.Contains(bad, a.key) && !slices.Contains(bad, VarMailAPISubnet) && !hostIn(m.APISubnet, a.ip) {
			bad = append(bad, a.key)
		}
	}
	if m.HubIP == m.ProviderIP && !slices.Contains(bad, VarMailAPIProviderIP) {
		bad = append(bad, VarMailAPIProviderIP)
	}
	if len(bad) > 0 {
		m.Err = "core.env holds an invalid " + strings.Join(bad, ", ") + ": mail stays off until ./portcullis up rewrites it"
		m.On = false
	}
	return m
}

// hostIn: ip is a host address of p (not its network or broadcast).
func hostIn(p netip.Prefix, ip netip.Addr) bool {
	if !p.Contains(ip) || ip == p.Addr() {
		return false
	}
	b := p.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	bcast := n | (1<<(32-p.Bits()) - 1)
	x := ip.As4()
	return uint32(x[0])<<24|uint32(x[1])<<16|uint32(x[2])<<8|uint32(x[3]) != bcast
}

// mailOn reports PORTCULLIS_MAIL=on.
func (h *Hub) mailOn() bool { return h.mailCore().On }

// mailDomainStateLocked is name's mail state: on, draining or off
// (mailDomainState). Caller must hold mu.
func (h *Hub) mailDomainStateLocked(name string, coreOn bool) string {
	return mailDomainState(h.st.Mail, h.cfg.Domain, coreOn, name)
}

// mailDomainsLocked are the domains mail is on or draining for, sorted.
// Caller must hold mu.
func (h *Hub) mailDomainsLocked(coreOn bool) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.ToLower(n)
		if !seen[n] && h.mailDomainStateLocked(n, coreOn) != "off" {
			seen[n] = true
			out = append(out, n)
		}
	}
	add(h.cfg.Domain)
	for n := range h.st.Mail.Domains {
		add(n)
	}
	sort.Strings(out)
	return out
}

func mailReservedIn(host string, domains []string) string {
	for _, e := range domains {
		for _, l := range mailReservedLabels {
			if r := l + "." + e; host == r || strings.HasSuffix(host, "."+r) {
				return "hostname " + host + " is reserved for mail on " + e
			}
		}
	}
	return ""
}

// MailAPI is the wired mail provider's API v1 (internal/mailprovider.Client,
// contract §19.5): the seam the Hub's tests replace.
type MailAPI interface {
	Provider(ctx context.Context) (mailprovider.ProviderInfo, error)
	Void(ctx context.Context, reason string) (mailprovider.VoidResult, error)
	TLSReload(ctx context.Context, spki []string) (string, error)
	Test(ctx context.Context, to string) (string, error)
	Available() error
	PutState(ctx context.Context, st *mailprovider.MailState) (int, error)
	State(ctx context.Context) (mailprovider.StateStatus, error)
	DNS(ctx context.Context, domain string, wildcard bool) (mailprovider.DNSSet, error)
	Checks(ctx context.Context, refresh bool) (mailprovider.Checks, error)
	Status(ctx context.Context) (mailprovider.Status, error)
	Credentials(ctx context.Context, uuid string) ([]mailprovider.Credential, error)
	CreateCredential(ctx context.Context, user, uuid, label string, expires *time.Time) (mailprovider.Created, error)
	RevokeCredential(ctx context.Context, uuid, id string) error
	Action(ctx context.Context, name, domain string) error
}

// SetMailAPI replaces the wired provider's client (tests: a fake; nil =
// the client on HUB_MAIL_API_URL with the instance's API secret).
func (h *Hub) SetMailAPI(api MailAPI) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mailAPI = api
}

// mailClient is the wired provider's API when mail works for the Hub
// (contract §19.1, fail closed): PORTCULLIS_MAIL=on with valid keys, a
// provider wired and in normal mode (no void owed, not held), and its
// secret readable; else nil (the mail routes answer 503).
func (h *Hub) mailClient() MailAPI {
	if !h.mailOn() {
		return nil
	}
	h.mu.RLock()
	var api MailAPI
	held := false
	if p := h.st.Mail.Provider; p != nil && h.mailModeLocked(p.Instance) == mailNormal {
		if hd := h.st.Mail.Held; hd == nil || hd.Stopped == nil {
			api = h.mailProviderAPILocked()
			held = hd != nil
		}
	}
	h.mu.RUnlock()
	if api == nil || api.Available() != nil {
		return nil
	}
	if held {
		return &heldMailAPI{MailAPI: api, h: h}
	}
	return api
}

// heldMailAPI is the held provider's client (Ruling R-HH1): the running,
// confirmed containers take every revocation, removal and document as
// usual; one they can't take stops the provider (fail closed).
type heldMailAPI struct {
	MailAPI
	h *Hub
}

// mailRefusedByProvider: a 4xx answer (the provider took the request and
// refused it, e.g. the mass-removal guard) rather than a failure.
func mailRefusedByProvider(err error) bool {
	var ae *mailprovider.APIError
	return errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500
}

func (a *heldMailAPI) PutState(ctx context.Context, st *mailprovider.MailState) (int, error) {
	g, err := a.MailAPI.PutState(ctx, st)
	if err != nil && !mailRefusedByProvider(err) {
		a.h.mailStopHeld("the mail document: " + err.Error())
	}
	return g, err
}

func (a *heldMailAPI) RevokeCredential(ctx context.Context, uuid, id string) error {
	err := a.MailAPI.RevokeCredential(ctx, uuid, id)
	if err != nil && mailprovider.StatusOf(err) != http.StatusNotFound {
		a.h.mailStopHeld("a revocation: " + err.Error())
	}
	return err
}

func (a *heldMailAPI) State(ctx context.Context) (mailprovider.StateStatus, error) {
	st, err := a.MailAPI.State(ctx)
	if err != nil {
		a.h.mailStopHeld("its state: " + err.Error())
	}
	return st, err
}

// mailStopHeld stops the held provider (R-HH1): it can't take what the
// Hub must send, and its changed tree can't be started. The stop is
// recorded in the hold (saved) BEFORE the down, so mailClient and the
// targets treat it as stopped at once (fail closed); a failed down is
// kept (StopError, a doctor Problem) and retried (mailRetryHeldStop)
// until it succeeds. Mail stays down until the re-confirm.
func (h *Hub) mailStopHeld(why string) {
	now := h.mailNow().UTC()
	h.mu.Lock()
	p, hd := h.st.Mail.Provider, h.st.Mail.Held
	if p == nil || hd == nil || hd.Stopped != nil {
		h.mu.Unlock()
		return
	}
	c := *hd
	c.Stopped, c.DownOwed = &now, true
	h.st.Mail.Held = &c
	h.saveLocked()
	h.mu.Unlock()
	log.Printf("mail: the held provider %s can't take %s: stopping it (no mail until an administrator confirms its template)", p.Instance, why)
	h.writeMailTargets()
	h.mailRetryHeldStop()
}

// mailStopTimeout bounds one owed down.
const mailStopTimeout = 2 * time.Minute

// mailRetryHeldStop runs the owed down of a stopped hold (at the stop,
// at every start and from the void retry loop), bounded: DownOwed is
// cleared only once it succeeded; a failure keeps its error.
func (h *Hub) mailRetryHeldStop() {
	h.mu.RLock()
	p, hd := h.st.Mail.Provider, h.st.Mail.Held
	h.mu.RUnlock()
	if p == nil || hd == nil || !hd.DownOwed {
		return
	}
	var err error
	if h.rt == nil {
		err = errors.New("no container runtime")
	} else {
		timeout := mailStopTimeout
		if h.mailStopWait > 0 {
			timeout = h.mailStopWait
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err = h.rt.DownByName(ctx, projectName(p.Instance))
		cancel()
	}
	msg := ""
	if err != nil {
		msg = err.Error()
		log.Printf("mail: stopping the held provider %s failed (retrying): %v", p.Instance, err)
	}
	h.mu.Lock()
	if cur := h.st.Mail.Held; cur != nil && cur.DownOwed && h.st.Mail.Provider != nil && h.st.Mail.Provider.Instance == p.Instance {
		c := *cur
		c.StopError, c.DownOwed = msg, err != nil
		h.st.Mail.Held = &c
		h.saveLocked()
	}
	h.mu.Unlock()
}

// MailHeldStopError is the owed stop's state ("" = none owed, or done):
// the doctor's Problem (the held provider may still serve).
func (h *Hub) MailHeldStopError() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if hd := h.st.Mail.Held; hd != nil && hd.DownOwed {
		if hd.StopError != "" {
			return "stopping the held mail provider failed (retrying): " + hd.StopError
		}
		return "stopping the held mail provider is owed and not done yet"
	}
	return ""
}

// WireMailForTest records instance as the wired provider in normal mode
// (tests outside the package that drive the fake provider).
func (h *Hub) WireMailForTest(instance string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st.Mail.Provider = &state.MailProvider{Instance: instance, Template: instance}
}

// MailDomainStates is every domain's mail state (on, draining, off) as
// the Hub's mail settings say (the per-domain mail flags): the main
// domain and every added domain the Hub knows of.
func (h *Hub) MailDomainStates() map[string]string {
	coreOn := h.mailOn()
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := map[string]string{strings.ToLower(h.cfg.Domain): h.mailDomainStateLocked(h.cfg.Domain, coreOn)}
	for _, d := range h.st.Domains {
		out[strings.ToLower(d.Name)] = h.mailDomainStateLocked(d.Name, coreOn)
	}
	for n := range h.st.Mail.Domains {
		if _, ok := out[n]; !ok {
			out[n] = h.mailDomainStateLocked(n, coreOn)
		}
	}
	return out
}

// SetMailCoreForTest replaces core.env's mail keys (tests outside the
// package; nil = read core.env again).
func (h *Hub) SetMailCoreForTest(on bool, hostname string) {
	h.mailCoreForTest.Store(&mailCoreEnv{On: on, Hostname: hostname})
}

// SyncMailForTest runs one mail sync pass now.
func (h *Hub) SyncMailForTest(ctx context.Context) { h.mailSyncOnce(ctx) }
