package hub

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailprovider"
)

// mailDNSHashEvery: how often mailctl's per-domain set hashes are
// compared (DKIM keys are made and move stages on mailctl's own passes).
const mailDNSHashEvery = 60 * time.Second

// mailDNSIfDue runs the full rewrite (syncMailDNS) after an accepted
// document (force) or every mailDNSEvery (the backstop), and otherwise
// the hash pass (mailDNSByHash) every mailDNSHashEvery: a domain whose
// set hash in mailctl's status changed since the Hub last wrote it is
// written again. It returns the sleep until the next one.
func (h *Hub) mailDNSIfDue(ctx context.Context, api MailAPI, now time.Time, force bool) time.Duration {
	s := &h.mailState
	s.mu.Lock()
	full := force || s.dnsAt.IsZero() || !now.Before(s.dnsAt.Add(mailDNSEvery))
	hash := full || s.hashAt.IsZero() || !now.Before(s.hashAt.Add(mailDNSHashEvery))
	if full {
		s.dnsAt = now
	}
	if hash {
		s.hashAt = now
	}
	nextFull := s.dnsAt.Add(mailDNSEvery).Sub(now)
	nextHash := s.hashAt.Add(mailDNSHashEvery).Sub(now)
	s.mu.Unlock()
	if hash {
		var st *mailprovider.Status
		if v, err := api.Status(ctx); err == nil {
			st = &v
		}
		var err error
		if full {
			err = h.syncMailDNS(ctx, api, st)
		} else if st != nil {
			err = h.mailDNSByHash(ctx, api, st)
		}
		if err != nil {
			log.Printf("mail: DNS: %v", err)
		}
	}
	return min(max(min(nextFull, nextHash), time.Second), mailIdle)
}

// mailDNSDomains are the added mail domains (never the main domain: the
// CLI's dns-tool owns it) that aren't retired, with their state.
func (h *Hub) mailDNSDomains() []mailDNSDomain {
	h.mu.RLock()
	defer h.mu.RUnlock()
	main := strings.ToLower(h.cfg.Domain)
	var ds []mailDNSDomain
	for n, e := range h.st.Mail.Domains {
		n = strings.ToLower(n)
		if n == main || e.Retired {
			continue
		}
		ds = append(ds, mailDNSDomain{n, mailDomainState(h.st.Mail, main, true, n)})
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].name < ds[j].name })
	return ds
}

type mailDNSDomain struct{ name, state string }

// mailDNSByHash writes again the set of every added domain on or
// draining whose hash in st differs from the one last written; the hash
// is recorded only after the PUT succeeded (a failure retries next pass).
func (h *Hub) mailDNSByHash(ctx context.Context, api MailAPI, st *mailprovider.Status) error {
	h.mu.RLock()
	dapi := h.domainsAPI
	h.mu.RUnlock()
	if dapi == nil {
		return nil
	}
	s := &h.mailState
	var errs []string
	for _, d := range h.mailDNSDomains() {
		if d.state != mailprovider.MailOn && d.state != mailprovider.MailDraining {
			continue
		}
		want := st.DNS[d.name]
		s.mu.Lock()
		have := s.dnsHash[d.name]
		s.mu.Unlock()
		if want == "" || want == have {
			continue
		}
		if err := h.writeMailSet(ctx, api, dapi, d.name); err != nil {
			h.mailForgetDNSHash(d.name)
			if errors.Is(err, errNotApplied) {
				log.Printf("mail: DNS: %v (written on the next pass)", err)
			} else {
				errs = append(errs, err.Error())
			}
			continue
		}
		h.mailRecordDNSHash(d.name, want)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// mailForgetDNSHash drops name's recorded hash (a failed write, a set
// removed): the next hash pass writes it whatever the hash.
func (h *Hub) mailForgetDNSHash(name string) {
	s := &h.mailState
	s.mu.Lock()
	delete(s.dnsHash, name)
	s.mu.Unlock()
}

func (h *Hub) mailRecordDNSHash(name, hash string) {
	if hash == "" {
		return
	}
	s := &h.mailState
	s.mu.Lock()
	if s.dnsHash == nil {
		s.dnsHash = map[string]string{}
	}
	s.dnsHash[name] = hash
	s.mu.Unlock()
}

// errNotApplied: mailctl doesn't have the domain in its applied document
// yet (GET /v1/dns 404): the next pass writes it.
var errNotApplied = errors.New("not applied yet")

// writeMailSet fetches name's wanted set from mailctl (with ?wildcard=
// from its plan) and PUTs it to the domains service.
func (h *Hub) writeMailSet(ctx context.Context, api MailAPI, dapi DomainsAPI, name string) error {
	// No *.<e> address record: mailctl adds the CNAMEs for mta-sts,
	// autoconfig and autodiscover (?wildcard=false). A plan that can't be
	// read skips the domain this pass.
	wild, err := planHasWildcard(ctx, dapi, name)
	if err != nil {
		return fmt.Errorf("%s: reading the DNS plan: %v", name, err)
	}
	set, err := api.DNS(ctx, name, wild)
	if err != nil {
		if mailprovider.StatusOf(err) == 404 {
			return fmt.Errorf("%s: %w", name, errNotApplied)
		}
		return fmt.Errorf("%s: reading the wanted mail records: %v", name, err)
	}
	recs := make([]domains.MailRecord, 0, len(set.Records))
	for _, r := range set.Records {
		recs = append(recs, domains.MailRecord{Name: r.Name, Type: r.Type, TTL: r.TTL, Value: r.Value})
	}
	if _, err := dapi.SetMailSet(ctx, name, recs); err != nil {
		return fmt.Errorf("%s: writing the mail set: %v", name, err)
	}
	return nil
}

// syncMailDNS writes the added mail domains' mail sets (contract §19.7):
// for a domain on or draining, mailctl's wanted set → PUT sets/mail; a
// draining domain mailctl reports off (MTA-STS mode off) becomes off and
// a sync is asked for (its document says off); an off domain not yet
// retired gets DELETE sets/mail, then is retired. The main domain is
// never written here (the CLI's dns-tool owns it).
// st is mailctl's status read for this pass (nil: unreadable): the
// draining domains' MTA-STS modes, and the set hashes recorded for the
// sets written.
func (h *Hub) syncMailDNS(ctx context.Context, api MailAPI, st *mailprovider.Status) error {
	h.mu.RLock()
	dapi := h.domainsAPI
	h.mu.RUnlock()
	ds := h.mailDNSDomains()
	if dapi == nil || len(ds) == 0 {
		return nil
	}
	modes := map[string]string{}
	if st != nil {
		for _, m := range st.MTASTS {
			modes[strings.ToLower(m.Domain)] = m.Mode
		}
	}
	var errs []string
	for _, d := range ds {
		switch d.state {
		case mailprovider.MailOn, mailprovider.MailDraining:
			if d.state == mailprovider.MailDraining && modes[d.name] == mailprovider.MailOff {
				h.mu.Lock()
				if e, ok := h.st.Mail.Domains[d.name]; ok && e.Draining {
					e.Draining = false
					h.st.Mail.Domains[d.name] = e
					h.saveLocked()
				}
				h.mu.Unlock()
				log.Printf("mail: %s finished draining: mail is off for it", d.name)
				h.TriggerMailSync()
				continue
			}
			// The hash read before the write: a set changed meanwhile
			// differs from it, so the hash pass writes it again.
			if err := h.writeMailSet(ctx, api, dapi, d.name); err != nil {
				h.mailForgetDNSHash(d.name)
				if errors.Is(err, errNotApplied) {
					log.Printf("mail: DNS: %v (written on the next pass)", err)
				} else {
					errs = append(errs, err.Error())
				}
				continue
			}
			if st != nil {
				h.mailRecordDNSHash(d.name, st.DNS[d.name])
			}
		case mailprovider.MailOff:
			if _, err := dapi.DeleteMailSet(ctx, d.name); err != nil && domainsStatus(err) != 404 {
				errs = append(errs, fmt.Sprintf("%s: removing the mail set: %v", d.name, err))
				continue
			}
			h.mailForgetDNSHash(d.name)
			h.mu.Lock()
			if e, ok := h.st.Mail.Domains[d.name]; ok && !e.Enabled && !e.Draining {
				e.Retired = true
				h.st.Mail.Domains[d.name] = e
				h.saveLocked()
			}
			h.mu.Unlock()
			h.TriggerMailSync()
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// domainsStatus is a domains APIError's status (0 otherwise).
func domainsStatus(err error) int {
	if ae, ok := err.(*domains.APIError); ok {
		return ae.Status
	}
	return 0
}

// planHasWildcard: name's cached DNS plan has a live *.<name> A or AAAA
// address record.
func planHasWildcard(ctx context.Context, dapi DomainsAPI, name string) (bool, error) {
	p, err := dapi.Plan(ctx, name, false)
	if err != nil {
		return false, err
	}
	for _, it := range p.Items {
		if it.Set == domains.SetAddress && strings.EqualFold(it.Name, "*."+name) && (it.Type == "A" || it.Type == "AAAA") && len(it.Live) > 0 {
			return true, nil
		}
	}
	return false, nil
}
