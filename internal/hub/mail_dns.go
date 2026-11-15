package hub

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailctl"
)

// mailDNSIfDue runs syncMailDNS after an accepted document (force) or
// when mailDNSEvery has passed; it returns the sleep until the next one
// (at most mailIdle).
func (h *Hub) mailDNSIfDue(ctx context.Context, api MailAPI, now time.Time, force bool) time.Duration {
	s := &h.mailState
	s.mu.Lock()
	due := force || s.dnsAt.IsZero() || !now.Before(s.dnsAt.Add(mailDNSEvery))
	if due {
		s.dnsAt = now
	}
	next := s.dnsAt.Add(mailDNSEvery).Sub(now)
	s.mu.Unlock()
	if due {
		if err := h.syncMailDNS(ctx, api); err != nil {
			log.Printf("mail: DNS: %v", err)
		}
	}
	return min(max(next, time.Second), mailIdle)
}

// syncMailDNS writes the added mail domains' mail sets (contract §19.7):
// for a domain on or draining, mailctl's wanted set → PUT sets/mail; a
// draining domain mailctl reports off (MTA-STS mode off) becomes off and
// a sync is asked for (its document says off); an off domain not yet
// retired gets DELETE sets/mail, then is retired. The main domain is
// never written here (the CLI's dns-tool owns it).
func (h *Hub) syncMailDNS(ctx context.Context, api MailAPI) error {
	h.mu.RLock()
	dapi := h.domainsAPI
	main := strings.ToLower(h.cfg.Domain)
	type dom struct {
		name, state string
	}
	var ds []dom
	for n, e := range h.st.Mail.Domains {
		n = strings.ToLower(n)
		if n == main || e.Retired {
			continue
		}
		ds = append(ds, dom{n, mailDomainState(h.st.Mail, main, true, n)})
	}
	h.mu.RUnlock()
	if dapi == nil || len(ds) == 0 {
		return nil
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].name < ds[j].name })
	var modes map[string]string
	for _, d := range ds {
		if d.state == mailctl.MailDraining && modes == nil {
			modes = map[string]string{}
			if st, err := api.Status(ctx); err == nil {
				for _, m := range st.MTASTS {
					modes[strings.ToLower(m.Domain)] = m.Mode
				}
			}
		}
	}
	var errs []string
	for _, d := range ds {
		switch d.state {
		case mailctl.MailOn, mailctl.MailDraining:
			if d.state == mailctl.MailDraining && modes[d.name] == mailctl.MailOff {
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
			// No *.<e> address record: mailctl adds the CNAMEs for
			// mta-sts, autoconfig and autodiscover (?wildcard=false). A
			// plan that can't be read skips the domain this pass.
			wild, err := planHasWildcard(ctx, dapi, d.name)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: reading the DNS plan: %v", d.name, err))
				continue
			}
			set, err := api.DNS(ctx, d.name, wild)
			if err != nil {
				// 404: not in the applied document yet (the next pass).
				if mailctl.StatusOf(err) != 404 {
					errs = append(errs, fmt.Sprintf("%s: reading the wanted mail records: %v", d.name, err))
				}
				continue
			}
			recs := make([]domains.MailRecord, 0, len(set.Records))
			for _, r := range set.Records {
				recs = append(recs, domains.MailRecord{Name: r.Name, Type: r.Type, TTL: r.TTL, Value: r.Value})
			}
			if _, err := dapi.SetMailSet(ctx, d.name, recs); err != nil {
				errs = append(errs, fmt.Sprintf("%s: writing the mail set: %v", d.name, err))
			}
		case mailctl.MailOff:
			if _, err := dapi.DeleteMailSet(ctx, d.name); err != nil && domainsStatus(err) != 404 {
				errs = append(errs, fmt.Sprintf("%s: removing the mail set: %v", d.name, err))
				continue
			}
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
