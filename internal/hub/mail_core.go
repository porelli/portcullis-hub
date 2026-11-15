package hub

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/mailctl"
)

// Core env keys of mail (contract §2): the whole PORTCULLIS_MAIL prefix
// (PORTCULLIS_MAILCTL_* included) is core's, never a template variable.
const (
	VarMailPrefix            = "PORTCULLIS_MAIL"
	VarMail                  = "PORTCULLIS_MAIL"
	VarMailHostname          = "PORTCULLIS_MAIL_HOSTNAME"
	VarMailSubmissionLANOnly = "PORTCULLIS_MAIL_SUBMISSION_LAN_ONLY"
	VarMailRelay             = "PORTCULLIS_MAIL_RELAY"
)

// coreOnlyVar: a core env key the Hub never copies into an instance.
func coreOnlyVar(k string) bool {
	return k == VarUnprivilegedPortStart || strings.HasPrefix(k, VarMailPrefix)
}

// mailReservedLabels are reserved on every mail domain (contract §5).
var mailReservedLabels = []string{"mail", "mta-sts", "autoconfig", "autodiscover"}

// mailPorts are the host ports core's mail publishes (contract §19.2).
var mailPorts = []int{25, 465, 587, 993}

// mailCoreEnv is the mail part of core.env.
type mailCoreEnv struct {
	On              bool
	Hostname        string
	SubmissionLAN   bool
	Relay           bool
	HostnameMissing bool
}

// mailCore reads core.env's mail keys. Fail closed: PORTCULLIS_MAIL is on
// only when it says exactly "on".
func (h *Hub) mailCore() mailCoreEnv {
	if c := h.mailCoreForTest.Load(); c != nil {
		return *c
	}
	core := readEnvRaw(filepath.Join(h.cfg.ProjectDir, ".env"))
	m := mailCoreEnv{
		On:            strings.TrimSpace(core[VarMail]) == "on",
		Hostname:      strings.ToLower(strings.TrimSuffix(strings.TrimSpace(core[VarMailHostname]), ".")),
		SubmissionLAN: strings.TrimSpace(core[VarMailSubmissionLANOnly]) == "true",
		Relay:         strings.TrimSpace(core[VarMailRelay]) == "on",
	}
	if m.Hostname == "" {
		m.HostnameMissing = true
		m.Hostname = "mail." + strings.ToLower(h.cfg.Domain)
	}
	return m
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

// MailAPI is core's mailctl (internal/mailctl.Client, contract §19.5).
type MailAPI interface {
	Available() error
	PutState(ctx context.Context, st *mailctl.MailState) (int, error)
	State(ctx context.Context) (mailctl.StateStatus, error)
	DNS(ctx context.Context, domain string, wildcard bool) (mailctl.DNSSet, error)
	Checks(ctx context.Context, refresh bool) (mailctl.Checks, error)
	Status(ctx context.Context) (mailctl.Status, error)
	Credentials(ctx context.Context, user string) ([]mailctl.Credential, error)
	CreateCredential(ctx context.Context, user, label string, expires *time.Time) (mailctl.Created, error)
	RevokeCredential(ctx context.Context, user, id string) error
	Action(ctx context.Context, name, domain string) error
}

// SetMailAPI connects mailctl (nil: not connected).
func (h *Hub) SetMailAPI(api MailAPI) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mailAPI = api
}

// mailClient is mailctl when mail is on for the Hub: PORTCULLIS_MAIL=on
// and a readable secret (contract §19.1); else nil.
func (h *Hub) mailClient() MailAPI {
	h.mu.Lock()
	api := h.mailAPI
	h.mu.Unlock()
	if api == nil || !h.mailOn() || api.Available() != nil {
		return nil
	}
	return api
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
