package hub

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/portcullis/hub/internal/mailprovider"
	"github.com/portcullis/hub/internal/state"
)

// The Hub's judgement of a provider's mail sets (contract §19.7): every
// set is checked against the shared table (mailprovider.ValidateSet)
// before it is written; a refused set is dropped (the last good one stays
// published) and recorded per domain for the doctor's mail_records_wrong,
// as are MTA-STS policy refusals (mail_mtasts.go).

// mailDNSProblems are the refusals per domain (memory).
type mailDNSProblems struct {
	mu     sync.Mutex
	sets   map[string]string // domain → the set's refusal
	policy map[string]string // domain → the MTA-STS policy's refusal
}

// MailDNSProblem is one domain's refusal.
type MailDNSProblem struct {
	Domain string
	Reason string
}

// errMailSetRefused marks a refused set (errors.Is on a mailSetRefusal).
var errMailSetRefused = errors.New("the provider's mail set was refused")

// mailSetRefusal is a refused set: the rule's text.
type mailSetRefusal struct{ msg string }

func (e *mailSetRefusal) Error() string        { return e.msg }
func (e *mailSetRefusal) Is(target error) bool { return target == errMailSetRefused }

// mailRuleContextLocked is the rules' context for domain name. Caller
// must hold mu (read).
func (h *Hub) mailRuleContextLocked(name string, wildcard bool) mailprovider.RuleContext {
	n := strings.ToLower(name)
	start := "reject"
	if e, ok := h.st.Mail.Domains[n]; ok && e.HadMailRecords {
		start = "none"
	}
	include := ""
	if r := h.st.Mail.Relay; r != nil {
		include = r.SPFInclude
	}
	return mailprovider.RuleContext{Domain: n, MailHostname: h.mailCore().Hostname, RelayInclude: include,
		DMARCFloor: mailDMARCFloor(h.st.Mail, n, start), Wildcard: wildcard,
		Draining: mailDomainState(h.st.Mail, h.cfg.Domain, true, n) == mailprovider.MailDraining}
}

// validateMailSet judges name's set; a refusal is recorded and logged.
func (h *Hub) validateMailSet(name string, wildcard bool, rs []mailprovider.Record) error {
	h.mu.RLock()
	c := h.mailRuleContextLocked(name, wildcard)
	h.mu.RUnlock()
	err := mailprovider.ValidateSet(c, rs)
	// The refusal echoes provider names and values: shaped (one
	// printable line, clipped) before a log, the doctor or a host answer
	// sees it (M9).
	msg := ""
	if err != nil {
		msg = mailprovider.Shape(err.Error(), 500)
	}
	h.mailDNSProb.mu.Lock()
	if h.mailDNSProb.sets == nil {
		h.mailDNSProb.sets = map[string]string{}
	}
	prev := h.mailDNSProb.sets[c.Domain]
	if err != nil {
		h.mailDNSProb.sets[c.Domain] = msg
	} else {
		delete(h.mailDNSProb.sets, c.Domain)
	}
	h.mailDNSProb.mu.Unlock()
	if err != nil {
		if prev != msg {
			log.Printf("mail: DNS: %s: the provider's set is refused (the last good one stays): %s", c.Domain, msg)
		}
		return &mailSetRefusal{msg}
	}
	return nil
}

// mailSetPublished records the DMARC policy of a set just published
// (dmarc_floor's input).
func (h *Hub) mailSetPublished(name string, rs []mailprovider.Record) {
	n := strings.ToLower(name)
	p := mailprovider.DMARCPolicy(n, rs)
	sts := false
	for _, r := range rs {
		if strings.EqualFold(strings.TrimSuffix(r.Name, "."), "_mta-sts."+n) && strings.EqualFold(r.Type, "TXT") {
			sts = true
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	changed := false
	if p != "" && h.st.Mail.DMARCPublished[n] != p {
		if h.st.Mail.DMARCPublished == nil {
			h.st.Mail.DMARCPublished = map[string]string{}
		}
		h.st.Mail.DMARCPublished[n] = p
		changed = true
	}
	if h.st.Mail.MTASTSPublished[n] != sts {
		if h.st.Mail.MTASTSPublished == nil {
			h.st.Mail.MTASTSPublished = map[string]bool{}
		}
		if sts {
			h.st.Mail.MTASTSPublished[n] = true
		} else {
			delete(h.st.Mail.MTASTSPublished, n)
		}
		changed = true
	}
	if changed {
		h.saveLocked()
	}
}

// MailDNSProblems are the refused sets and policies, sorted by domain.
func (h *Hub) MailDNSProblems() []MailDNSProblem {
	h.mailDNSProb.mu.Lock()
	defer h.mailDNSProb.mu.Unlock()
	var out []MailDNSProblem
	for d, r := range h.mailDNSProb.sets {
		out = append(out, MailDNSProblem{Domain: d, Reason: r})
	}
	for d, r := range h.mailDNSProb.policy {
		out = append(out, MailDNSProblem{Domain: d, Reason: r})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// HostMailDNSMain is GET /host/mail/dns/main (contract §19.7): the
// wired provider's main-domain set, validated (wildcard: the main
// domain's *.<d> is core's), plus any retiring DKIM; 409 "no mail
// provider is wired"; a refused set 409 with its reason (the CLI then
// writes nothing: the published records stay).
func (h *Hub) HostMailDNSMain(ctx context.Context) ([]mailprovider.Record, error) {
	h.mu.RLock()
	wired := h.st.Mail.Provider != nil
	h.mu.RUnlock()
	if !wired {
		return nil, statusErr(http.StatusConflict, "no mail provider is wired")
	}
	api := h.mailClient()
	if api == nil {
		return nil, errMailDown
	}
	main := strings.ToLower(h.cfg.Domain)
	dctx, cancel := context.WithTimeout(ctx, mailCallTimeout)
	set, err := api.DNS(dctx, main, true)
	cancel()
	if err != nil {
		if mailprovider.StatusOf(err) == http.StatusNotFound {
			return nil, statusErr(http.StatusConflict, "the provider has no set for %s yet: try again after its first document", main)
		}
		return nil, statusErr(http.StatusServiceUnavailable, "the mail provider can't be read: %v", err)
	}
	if err := h.validateMailSet(main, true, set.Records); err != nil {
		return nil, statusErr(http.StatusConflict, "%v", err)
	}
	now := h.mailNow()
	h.mu.RLock()
	ret, ok := h.st.Mail.RetiringDKIM[main]
	h.mu.RUnlock()
	if ok && !now.Before(ret.Until) {
		h.mu.Lock()
		if r, still := h.st.Mail.RetiringDKIM[main]; still && !now.Before(r.Until) {
			delete(h.st.Mail.RetiringDKIM, main)
			h.saveLocked()
		}
		h.mu.Unlock()
	}
	out := append([]mailprovider.Record{}, set.Records...)
	if ok && now.Before(ret.Until) {
		h.mu.RLock()
		rc := h.mailRuleContextLocked(main, true)
		h.mu.RUnlock()
		out = mailMergeRetiring(rc, set.Records, ret.Records)
	}
	h.mailSetPublished(main, set.Records)
	return out, nil
}

// mailRetiringShape: a retiring record is exactly one DKIM TXT at
// <selector>._domainkey.<domain> (one label) starting v=DKIM1; (M8).
func mailRetiringShape(domain string, r state.MailRecord) bool {
	sel, ok := strings.CutSuffix(strings.ToLower(strings.TrimSuffix(r.Name, ".")), "._domainkey."+strings.ToLower(domain))
	return ok && strings.EqualFold(r.Type, "TXT") && sel != "" && !strings.Contains(sel, ".") && strings.HasPrefix(r.Value, "v=DKIM1;")
}

// mailMergeRetiring is set with domain's retiring DKIM records added
// (M8): never into a draining set; never one whose name the new set uses
// (a reused selector: one TXT per name); each only when the merged set
// still passes the shared rules.
func mailMergeRetiring(c mailprovider.RuleContext, set []mailprovider.Record, ret []state.MailRecord) []mailprovider.Record {
	out := append([]mailprovider.Record{}, set...)
	if c.Draining {
		return out
	}
	used := map[string]bool{}
	for _, r := range set {
		used[strings.ToLower(strings.TrimSuffix(r.Name, "."))] = true
	}
	for _, r := range ret {
		n := strings.ToLower(strings.TrimSuffix(r.Name, "."))
		if used[n] || !mailRetiringShape(c.Domain, r) {
			continue
		}
		cand := append(append([]mailprovider.Record{}, out...), mailprovider.Record{Name: r.Name, Type: r.Type, TTL: r.TTL, Value: r.Value})
		if mailprovider.ValidateSet(c, cand) != nil {
			continue
		}
		out, used[n] = cand, true
	}
	return out
}
