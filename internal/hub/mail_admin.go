package hub

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/domains"
	"github.com/portcullis/hub/internal/mailctl"
	"github.com/portcullis/hub/internal/runtime"
	"github.com/portcullis/hub/internal/state"
	"github.com/portcullis/hub/internal/templates"
)

// Settings → Mail and the person, group and host mail routes (contract
// §19.9, §19.10). The settings routes read and save the Hub's own state
// with mail off too; the routes that need mailctl answer 503.

// MailDomainView is one domain of Settings → Mail.
type MailDomainView struct {
	Name    string   `json:"name"`
	Enabled bool     `json:"enabled"`
	State   string   `json:"state"`
	Groups  []string `json:"groups"`
}

// MailSpamView is the spam settings on the wire.
type MailSpamView struct {
	RejectScore int           `json:"reject_score"`
	JunkScore   int           `json:"junk_score"`
	DNSBL       mailctl.DNSBL `json:"dnsbl"`
	Allow       []string      `json:"allow"`
	Block       []string      `json:"block"`
}

// MailSettingsView is GET /api/mail/settings.
type MailSettingsView struct {
	Mail          string               `json:"mail"`
	Kubernetes    bool                 `json:"kubernetes"`
	Hostname      string               `json:"hostname"`
	PrimaryDomain string               `json:"primary_domain"`
	Domains       []MailDomainView     `json:"domains"`
	Spam          MailSpamView         `json:"spam"`
	Limits        mailctl.Limits       `json:"limits"`
	Quotas        []state.MailQuotaRow `json:"quotas"`
	// Lists are the groups made lists, by group (controller ruling).
	Lists             []MailListView `json:"lists"`
	Relay             string         `json:"relay"`
	SubmissionLANOnly bool           `json:"submission_lan_only"`
	FormerRetention   string         `json:"former_retention"`
	DQSKey            string         `json:"dqs_key"`
	// SubmissionLANOnlyRefusal (rootless Podman only): why LAN-only can't
	// be turned on here (controller ruling; the CLI refuses it).
	SubmissionLANOnlyRefusal string `json:"submission_lan_only_refusal,omitempty"`
	// PendingRemoval: a mass removal mailctl refused, waiting for an
	// administrator's confirmation (null: none).
	PendingRemoval *MailPendingView `json:"pending_removal"`
	// Problem: mail is on but can't be managed (the Hub's mail secret is
	// missing or too short); "" = none.
	Problem string `json:"problem,omitempty"`
}

// MailLANOnlyPodmanRefusal: LAN-only judges the client address, which
// rootless Podman rewrites.
const MailLANOnlyPodmanRefusal = "LAN-only needs the real client address; rootless Podman rewrites it"

// MailListView is one group list of Settings → Mail: the group, its
// address, its domain and who may post (members | anyone).
type MailListView struct {
	Group   string `json:"group"`
	Address string `json:"address"`
	Domain  string `json:"domain"`
	Posting string `json:"posting"`
}

// MailSettingsInput is PUT /api/mail/settings.
type MailSettingsInput struct {
	PrimaryDomain string               `json:"primary_domain"`
	Spam          MailSpamView         `json:"spam"`
	Limits        mailctl.Limits       `json:"limits"`
	Quotas        []state.MailQuotaRow `json:"quotas"`
}

// core.env keys Settings → Mail shows read-only (contract §19.9 lists the
// facts; core writes these two when it has them).
const (
	VarMailFormerRetention = "PORTCULLIS_MAIL_FORMER_RETENTION"
	VarMailDQS             = "PORTCULLIS_MAIL_DQS"
)

// mailDomainNames are the main domain and every added domain the Hub
// knows of or has a mail entry for, main first.
func (h *Hub) mailDomainNamesLocked() []string {
	main := strings.ToLower(h.cfg.Domain)
	set := map[string]bool{}
	for _, d := range h.st.Domains {
		set[strings.ToLower(d.Name)] = true
	}
	for n := range h.st.Mail.Domains {
		set[n] = true
	}
	delete(set, main)
	out := make([]string, 0, len(set)+1)
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return append([]string{main}, out...)
}

// MailSettingsView is Settings → Mail.
func (h *Hub) MailSettingsView() MailSettingsView {
	problem := ""
	if h.mailSecretInvalid() {
		problem = MailSecretProblem
	}
	core := h.mailCore()
	env := readEnvRaw(h.coreEnvPath())
	h.mu.RLock()
	defer h.mu.RUnlock()
	st := h.st.Mail
	v := MailSettingsView{Mail: map[bool]string{true: "on", false: "off"}[core.On], Kubernetes: h.kubeOn(), Hostname: core.Hostname,
		PrimaryDomain: mailPrimary(st, h.cfg.Domain), Domains: []MailDomainView{},
		Spam: MailSpamView{RejectScore: st.Spam.RejectScore, JunkScore: st.Spam.JunkScore,
			DNSBL: mailctl.DNSBL{Spamhaus: st.Spam.Spamhaus, Spamcop: st.Spam.Spamcop, Barracuda: st.Spam.Barracuda},
			Allow: nonNil(st.Spam.Allow), Block: nonNil(st.Spam.Block)},
		Limits: mailctl.Limits{RecipientsPerHour: st.Limits.RecipientsPerHour, RecipientsPerDay: st.Limits.RecipientsPerDay},
		Quotas: append([]state.MailQuotaRow{}, st.Quotas...), Relay: map[bool]string{true: "on", false: "off"}[core.Relay],
		SubmissionLANOnly: core.SubmissionLAN, FormerRetention: "720h", DQSKey: "not set"}
	if r := strings.TrimSpace(env[VarMailFormerRetention]); r != "" {
		v.FormerRetention = r
	}
	if strings.TrimSpace(env[VarMailDQS]) == "on" {
		v.DQSKey = "set in .env"
	}
	if h.cfg.Runtime == runtime.KindPodman {
		v.SubmissionLANOnlyRefusal = MailLANOnlyPodmanRefusal
	}
	for _, n := range h.mailDomainNamesLocked() {
		s := h.mailDomainStateLocked(n, core.On)
		v.Domains = append(v.Domains, MailDomainView{Name: n, Enabled: s == mailctl.MailOn, State: s, Groups: nonNil(st.Domains[n].Groups)})
	}
	v.PendingRemoval = h.mailPendingViewLocked()
	v.Problem = problem
	v.Lists = []MailListView{}
	for g, l := range st.Lists {
		posting := l.Posting
		if posting == "" {
			posting = state.MailPostingMembers
		}
		d := strings.ToLower(l.Domain)
		v.Lists = append(v.Lists, MailListView{Group: g, Address: strings.ToLower(g) + "@" + d, Domain: d, Posting: posting})
	}
	sort.Slice(v.Lists, func(i, j int) bool { return v.Lists[i].Group < v.Lists[j].Group })
	return v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string{}, s...)
}

func (h *Hub) coreEnvPath() string { return h.cfg.ProjectDir + "/.env" }

// mailAddrOK: a domain or an address (allow / block entries).
func mailAddrOK(s string) bool {
	local, dom, ok := strings.Cut(s, "@")
	if !ok {
		return templates.ValidHostname(s)
	}
	return local != "" && len(local) <= 64 && !strings.ContainsAny(local, " \t\r\n<>()[],;:\"\\@") && templates.ValidHostname(dom)
}

// SetMailSettings saves Settings → Mail (contract §19.9): 400 for a value
// outside the contract's ranges; audited mail.settings; then a sync.
func (h *Hub) SetMailSettings(ctx context.Context, in MailSettingsInput, actor directory.Actor) (err error) {
	if err := h.mailWriteGuard(); err != nil {
		return err
	}
	defer func() { h.auditOp(actor, "mail.settings", "mail", mailSettingsDetail(in), err) }()
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(http.StatusBadRequest, "no signed-in user to audit the change as")
	}
	s, l := in.Spam, in.Limits
	if s.JunkScore < 1 || s.JunkScore >= s.RejectScore || s.RejectScore > 100 {
		return statusErr(http.StatusBadRequest, "spam scores must satisfy 1 ≤ junk < reject ≤ 100")
	}
	for _, n := range []int{l.RecipientsPerHour, l.RecipientsPerDay} {
		if n < 1 || n > state.MaxMailLimit {
			return statusErr(http.StatusBadRequest, "limits must be 1 to 100000")
		}
	}
	norm := func(list []string, what string) ([]string, error) {
		out := []string{}
		for _, a := range list {
			a = strings.ToLower(strings.TrimSpace(a))
			if !mailAddrOK(a) {
				return nil, statusErr(http.StatusBadRequest, "%s entry %q isn't a domain or an address", what, clipText(a))
			}
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
		if len(out) > 1000 {
			return nil, statusErr(http.StatusBadRequest, "at most 1000 %s entries", what)
		}
		return out, nil
	}
	allow, err := norm(s.Allow, "allow")
	if err != nil {
		return err
	}
	block, err := norm(s.Block, "block")
	if err != nil {
		return err
	}
	if len(in.Quotas) > 100 {
		return statusErr(http.StatusBadRequest, "at most 100 quota rows")
	}
	var m *directory.Membership
	if len(in.Quotas) > 0 {
		if m, err = h.membership(ctx); err != nil {
			return err
		}
	}
	for _, q := range in.Quotas {
		if _, ok := m.Groups[q.Group]; !ok {
			return statusErr(http.StatusBadRequest, "quota row: no group %q", clipText(q.Group))
		}
		if q.Bytes <= 0 || q.Bytes > state.MaxMailQuotaBytes {
			return statusErr(http.StatusBadRequest, "quota row %s: the size must be more than 0 and at most 1 TiB", q.Group)
		}
	}
	primary := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.PrimaryDomain), "."))
	main := strings.ToLower(h.cfg.Domain)
	coreOn := h.mailOn()
	h.mu.Lock()
	defer h.mu.Unlock()
	if primary != main {
		ok := false
		for _, d := range h.st.Domains {
			ok = ok || (strings.EqualFold(d.Name, primary) && knownAssignable(d, h.mailNow()))
		}
		if !ok {
			return statusErr(http.StatusBadRequest, "the primary domain must be the main domain or an assignable added domain")
		}
	}
	// Every login is on the primary domain: it must be one mail is on for
	// (else no document could be sent, removals included).
	if mailDomainState(h.st.Mail, h.cfg.Domain, coreOn || primary == main, primary) != mailctl.MailOn {
		return statusErr(http.StatusBadRequest, "turn mail on for %s first", primary)
	}
	old := h.st.Mail
	if primary == main {
		h.st.Mail.PrimaryDomain = ""
	} else {
		h.st.Mail.PrimaryDomain = primary
	}
	h.st.Mail.Spam = state.MailSpam{RejectScore: s.RejectScore, JunkScore: s.JunkScore, Spamhaus: s.DNSBL.Spamhaus, Spamcop: s.DNSBL.Spamcop,
		Barracuda: s.DNSBL.Barracuda, Allow: allow, Block: block}
	h.st.Mail.Limits = state.MailLimits{RecipientsPerHour: l.RecipientsPerHour, RecipientsPerDay: l.RecipientsPerDay}
	h.st.Mail.Quotas = append([]state.MailQuotaRow(nil), in.Quotas...)
	if err := h.saveStateLocked(); err != nil {
		h.st.Mail = old
		return err
	}
	h.TriggerMailSync()
	return nil
}

func mailSettingsDetail(in MailSettingsInput) string {
	return fmt.Sprintf("primary=%s reject=%d junk=%d limits=%d/%d quotas=%d", in.PrimaryDomain, in.Spam.RejectScore, in.Spam.JunkScore,
		in.Limits.RecipientsPerHour, in.Limits.RecipientsPerDay, len(in.Quotas))
}

// clipText is s, at most 64 bytes of it (refusal texts).
func clipText(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// ensureMailUsers creates mail_users as actor when it is missing (like an
// app's access group); a failure is logged, never a refusal.
func (h *Hub) ensureMailUsers(ctx context.Context, actor directory.Actor) {
	h.mu.RLock()
	g := h.groups
	h.mu.RUnlock()
	if g == nil || strings.TrimSpace(actor.User) == "" {
		return
	}
	missing, err := g.MissingInstanceGroups(ctx, []string{MailUsersGroup})
	if err != nil || len(missing) == 0 {
		return
	}
	if _, w, err := g.CreateInstanceGroup(ctx, actor, MailUsersGroup); err != nil || len(w) > 0 {
		log.Printf("mail: creating %s: %v %v", MailUsersGroup, err, w)
	}
}

// hadMailRecords: the domain's plan shows an MX or SPF that isn't
// Portcullis's nomail (DMARC then starts at p=none). Unreadable: true
// (the gentler start).
func (h *Hub) hadMailRecords(ctx context.Context, name string) bool {
	h.mu.RLock()
	api := h.domainsAPI
	main := strings.EqualFold(name, h.cfg.Domain)
	h.mu.RUnlock()
	if api == nil {
		return true
	}
	var p domains.Plan
	var err error
	if main {
		p, err = api.MainPlan(ctx, false)
	} else {
		p, err = api.Plan(ctx, name, false)
	}
	if err != nil {
		return true
	}
	for _, it := range p.Items {
		if it.Set == domains.SetMail || !strings.EqualFold(it.Name, name) {
			continue
		}
		for _, v := range it.Live {
			switch {
			case it.Type == "MX" && strings.TrimSuffix(strings.TrimSpace(v), ".") != "0":
				return true
			case it.Type == "TXT" && strings.HasPrefix(strings.ToLower(strings.Trim(v, `"`)), "v=spf1") && strings.TrimSpace(strings.Trim(v, `"`)) != "v=spf1 -all":
				return true
			}
		}
	}
	return false
}

// SetMailDomain turns mail on or off for the main domain or an added one
// and sets its groups (contract §19.9). On: refused while an instance
// uses a reserved mail hostname there (409, naming it); records whether
// the domain had an MX or SPF before (dmarc_start). Off: the domain
// drains (MTA-STS mode none for max_age, then off). Audited mail.domain.
func (h *Hub) SetMailDomain(ctx context.Context, name string, enabled bool, groups []string, actor directory.Actor) (err error) {
	if err := h.mailWriteGuard(); err != nil {
		return err
	}
	name = NormalizeHost(name)
	defer func() {
		h.auditOp(actor, "mail.domain", name, fmt.Sprintf("enabled=%v groups=%s", enabled, strings.Join(groups, ",")), err)
	}()
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(http.StatusBadRequest, "no signed-in user to audit the change as")
	}
	main := strings.ToLower(h.cfg.Domain)
	h.mu.RLock()
	known := name == main || h.knownLocked(name)
	h.mu.RUnlock()
	if !known {
		return statusErr(http.StatusNotFound, "%s is neither the main domain nor an added domain", name)
	}
	if len(groups) > 0 {
		m, err := h.membership(ctx)
		if err != nil {
			return err
		}
		for _, g := range groups {
			if _, ok := m.Groups[g]; !ok {
				return statusErr(http.StatusBadRequest, "no group %q", clipText(g))
			}
		}
	}
	had := false
	if enabled {
		had = h.hadMailRecords(ctx, name)
		h.ensureMailUsers(ctx, actor)
	}
	coreOn := h.mailOn()
	h.mu.Lock()
	defer h.mu.Unlock()
	cur := h.mailDomainStateLocked(name, coreOn)
	e := h.st.Mail.Domains[name]
	if enabled {
		if cur != mailctl.MailOn {
			if id, host := h.mailReservedUserLocked(name); id != "" {
				return statusErr(http.StatusConflict, "instance %s uses %s, which mail reserves on %s: move it first", id, host, name)
			}
		}
		if cur == mailctl.MailOff {
			e.HadMailRecords = had
		}
		e.Enabled, e.Draining, e.Retired = true, false, false
	} else {
		if name == mailPrimary(h.st.Mail, h.cfg.Domain) && cur != mailctl.MailOff {
			return statusErr(http.StatusConflict, "%s is the primary mail domain: pick another one first", name)
		}
		if cur == mailctl.MailOn {
			e.Draining = true
		}
		e.Enabled = false
	}
	e.Groups = append([]string(nil), groups...)
	if h.st.Mail.Domains == nil {
		h.st.Mail.Domains = map[string]state.MailDomain{}
	}
	old, had2 := h.st.Mail.Domains[name]
	h.st.Mail.Domains[name] = e
	if err := h.saveStateLocked(); err != nil {
		if had2 {
			h.st.Mail.Domains[name] = old
		} else {
			delete(h.st.Mail.Domains, name)
		}
		return err
	}
	h.TriggerMailSync()
	return nil
}

// mailReservedUserLocked is an instance (and its host) using a mail
// reserved hostname on domain e ("" = none). Caller holds mu.
func (h *Hub) mailReservedUserLocked(e string) (string, string) {
	main := strings.ToLower(h.cfg.Domain)
	check := func(id string, hosts []string) (string, string) {
		for _, host := range hosts {
			if mailReservedIn(NormalizeHost(host), []string{e}) != "" {
				return id, NormalizeHost(host)
			}
		}
		return "", ""
	}
	for i := range h.instances {
		in := &h.instances[i]
		hosts := make([]string, 0, len(in.Hosts)+len(in.Subdomains))
		for _, x := range in.Hosts {
			hosts = append(hosts, x)
		}
		for _, s := range in.Subdomains {
			hosts = append(hosts, s+"."+main)
		}
		if id, host := check(in.ID, hosts); id != "" {
			return id, host
		}
	}
	for id, inst := range h.st.Instances {
		hosts := make([]string, 0, len(inst.Hosts))
		for _, x := range inst.Hosts {
			hosts = append(hosts, x)
		}
		if id, host := check(id, hosts); id != "" {
			return id, host
		}
	}
	return "", ""
}

// mailAddressOwner is who uses addr in the document the directory builds
// now (an account, someone's alias, a list) or a reserved local part;
// "" = free. exceptUUID: the person whose aliases are being replaced.
func mailAddressOwner(doc *mailctl.MailState, st state.MailSettings, addr, exceptUUID string) string {
	local, _, _ := strings.Cut(addr, "@")
	if slices.Contains(mailctl.ReservedLocalParts, local) {
		return "reserved for mail"
	}
	for _, a := range doc.Accounts {
		if slices.Contains(a.Addresses, addr) {
			return a.Username + "'s address"
		}
	}
	for id, al := range st.Aliases {
		if id != exceptUUID && slices.Contains(al.Addresses, addr) {
			return al.Username + "'s alias"
		}
	}
	for g, l := range st.Lists {
		if strings.ToLower(g)+"@"+strings.ToLower(l.Domain) == addr {
			return "the list of group " + g
		}
	}
	return ""
}

// mailAddrOnMail: addr is an address on a domain mail is on or draining.
func (h *Hub) mailAddrOnMailLocked(addr string, coreOn bool) bool {
	local, dom, ok := strings.Cut(addr, "@")
	return ok && local != "" && localPartRe.MatchString(local) && h.mailDomainStateLocked(dom, coreOn) != mailctl.MailOff
}

// SetUserAliases replaces user's aliases (contract §19.9): each an
// address on a mail domain (400), unique Hub-wide (409 naming the owner).
// Audited mail.alias.
func (h *Hub) SetUserAliases(ctx context.Context, user string, addrs []string, actor directory.Actor) (err error) {
	if err := h.mailWriteGuard(); err != nil {
		return err
	}
	user = strings.ToLower(strings.TrimSpace(user))
	defer func() { h.auditOp(actor, "mail.alias", user, fmt.Sprintf("count=%d", len(addrs)), err) }()
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(http.StatusBadRequest, "no signed-in user to audit the change as")
	}
	if len(addrs) > 50 {
		return statusErr(http.StatusBadRequest, "at most 50 aliases per person")
	}
	doc, err := h.mailBuild(ctx)
	if err != nil {
		if _, ok := err.(*StatusError); ok {
			return err
		}
		return statusErr(http.StatusConflict, "mail isn't on for the primary domain: no aliases can be set")
	}
	i := slices.IndexFunc(doc.Accounts, func(a mailctl.Account) bool { return a.Username == user })
	if i < 0 {
		return statusErr(http.StatusNotFound, "%s has no mailbox (not in %s)", user, MailUsersGroup)
	}
	uuid := doc.Accounts[i].UUID
	coreOn := h.mailOn()
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []string{}
	for _, a := range addrs {
		a = strings.ToLower(strings.TrimSpace(a))
		if !h.mailAddrOnMailLocked(a, coreOn) {
			return statusErr(http.StatusBadRequest, "%q isn't an address on a mail domain", clipText(a))
		}
		if slices.Contains(out, a) {
			continue
		}
		if owner := mailAddressOwner(doc, h.st.Mail, a, uuid); owner != "" {
			return statusErr(http.StatusConflict, "%s is already %s", a, owner)
		}
		out = append(out, a)
	}
	if h.st.Mail.Aliases == nil {
		h.st.Mail.Aliases = map[string]state.MailAliases{}
	}
	old, had := h.st.Mail.Aliases[uuid]
	if len(out) == 0 {
		delete(h.st.Mail.Aliases, uuid)
	} else {
		h.st.Mail.Aliases[uuid] = state.MailAliases{Username: user, Addresses: out}
	}
	if err := h.saveStateLocked(); err != nil {
		if had {
			h.st.Mail.Aliases[uuid] = old
		} else {
			delete(h.st.Mail.Aliases, uuid)
		}
		return err
	}
	h.TriggerMailSync()
	return nil
}

// SetGroupList makes group a list at <group>@<domain> or stops it
// (contract §19.9; posting members|anyone, default members). Audited
// mail.list.
func (h *Hub) SetGroupList(ctx context.Context, group string, enabled bool, domain, posting string, actor directory.Actor) (err error) {
	if err := h.mailWriteGuard(); err != nil {
		return err
	}
	domain = NormalizeHost(domain)
	defer func() {
		h.auditOp(actor, "mail.list", group, fmt.Sprintf("enabled=%v domain=%s posting=%s", enabled, domain, posting), err)
	}()
	if strings.TrimSpace(actor.User) == "" {
		return statusErr(http.StatusBadRequest, "no signed-in user to audit the change as")
	}
	m, err := h.membership(ctx)
	if err != nil {
		return err
	}
	if _, ok := m.Groups[group]; !ok {
		return statusErr(http.StatusNotFound, "no group %q", clipText(group))
	}
	if !enabled {
		h.mu.Lock()
		defer h.mu.Unlock()
		old, had := h.st.Mail.Lists[group]
		if !had {
			return nil
		}
		delete(h.st.Mail.Lists, group)
		if err := h.saveStateLocked(); err != nil {
			h.st.Mail.Lists[group] = old
			return err
		}
		h.TriggerMailSync()
		return nil
	}
	if posting == "" {
		posting = state.MailPostingMembers
	}
	if posting != state.MailPostingMembers && posting != state.MailPostingAnyone {
		return statusErr(http.StatusBadRequest, "posting must be members or anyone")
	}
	local := strings.ToLower(group)
	if !localPartRe.MatchString(local) {
		return statusErr(http.StatusBadRequest, "the group name %s can't be an address (letters, digits, dot, dash and underscore only)", clipText(group))
	}
	addr := local + "@" + domain
	doc, err := h.mailBuild(ctx)
	if err != nil {
		if _, ok := err.(*StatusError); ok {
			return err
		}
		return statusErr(http.StatusConflict, "mail isn't on for the primary domain: no list can be made")
	}
	coreOn := h.mailOn()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mailDomainStateLocked(domain, coreOn) != mailctl.MailOn {
		return statusErr(http.StatusBadRequest, "mail isn't on for %s", domain)
	}
	cur, had := h.st.Mail.Lists[group]
	if !had || !strings.EqualFold(cur.Domain, domain) {
		st := h.st.Mail
		lists := map[string]state.MailList{}
		for g, l := range st.Lists {
			if g != group {
				lists[g] = l
			}
		}
		st.Lists = lists
		if owner := mailAddressOwner(doc, st, addr, ""); owner != "" {
			return statusErr(http.StatusConflict, "%s is already %s", addr, owner)
		}
	}
	if h.st.Mail.Lists == nil {
		h.st.Mail.Lists = map[string]state.MailList{}
	}
	h.st.Mail.Lists[group] = state.MailList{Domain: domain, Posting: posting}
	if err := h.saveStateLocked(); err != nil {
		if had {
			h.st.Mail.Lists[group] = cur
		} else {
			delete(h.st.Mail.Lists, group)
		}
		return err
	}
	h.TriggerMailSync()
	return nil
}

// MailStatusView is GET /api/mail/status (and the mail_status tool).
type MailStatusView struct {
	Mail      string               `json:"mail"`
	Reachable bool                 `json:"reachable"`
	Status    *mailctl.Status      `json:"status"`
	Domains   []MailDomainStateRow `json:"domains"`
}

// MailDomainStateRow is one domain's mail state (also the host routes').
type MailDomainStateRow struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// mailDomainRows are every domain's state (mail on, draining or off).
func (h *Hub) mailDomainRows() []MailDomainStateRow {
	states := h.MailDomainStates()
	names := make([]string, 0, len(states))
	for n := range states {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]MailDomainStateRow, 0, len(names))
	for _, n := range names {
		out = append(out, MailDomainStateRow{Name: n, State: states[n]})
	}
	return out
}

// MailStatus is GET /api/mail/status: never a credential.
func (h *Hub) MailStatus(ctx context.Context) MailStatusView {
	v := MailStatusView{Mail: "off", Domains: h.mailDomainRows()}
	api := h.mailClient()
	if api == nil {
		return v
	}
	v.Mail = "on"
	if st, err := api.Status(ctx); err == nil {
		v.Reachable, v.Status = true, &st
	}
	return v
}

// MailChecks is mailctl's GET /v1/checks (503 while mail isn't running).
func (h *Hub) MailChecks(ctx context.Context, refresh bool) (*mailctl.Checks, error) {
	api, err := h.mailUp(ctx)
	if err != nil {
		return nil, err
	}
	c, err := api.Checks(ctx, refresh)
	if err != nil {
		return nil, errMailDown
	}
	return &c, nil
}

// MailAction runs one of mailctl's actions on domain (contract §19.5):
// 202; 404 not a mail domain; 409 nothing to do. Audited mail.<action>.
func (h *Hub) MailAction(ctx context.Context, action, domain string, actor directory.Actor) (err error) {
	domain = NormalizeHost(domain)
	audit := map[string]string{mailctl.ActionDKIMRotate: "mail.dkim_rotate", mailctl.ActionDMARCPromote: "mail.dmarc_promote", mailctl.ActionMTASTSEnforce: "mail.mtasts_enforce"}[action]
	if audit == "" {
		return statusErr(http.StatusNotFound, "no mail action %q", clipText(action))
	}
	defer func() { h.auditOp(actor, audit, domain, "", err) }()
	api, err := h.mailUp(ctx)
	if err != nil {
		return err
	}
	if err := api.Action(ctx, action, domain); err != nil {
		var ae *mailctl.APIError
		if asAPIError(err, &ae) && (ae.Status == http.StatusNotFound || ae.Status == http.StatusConflict || ae.Status == http.StatusBadRequest) {
			return statusErr(ae.Status, "%s", ae.Msg)
		}
		return errMailDown
	}
	return nil
}

func asAPIError(err error, out **mailctl.APIError) bool {
	ae, ok := err.(*mailctl.APIError)
	if ok {
		*out = ae
	}
	return ok
}

// PersonMailView is GET /api/directory/users/{username}/mail.
type PersonMailView struct {
	Addresses []string           `json:"addresses"`
	Aliases   []string           `json:"aliases"`
	Passwords []MailPasswordView `json:"passwords"`
}

// mailHelpAllowed: an administrator, or a sign_in_help holder who may
// target user (contract §19.9 "Who"); admin reports which.
func (h *Hub) mailHelpAllowed(ctx context.Context, c *directory.Caller, user string) (u string, admin bool, err error) {
	u, err = helpTarget(user)
	if err != nil {
		return "", false, err
	}
	if c != nil && c.Admin {
		return u, true, nil
	}
	if err := h.checkHelp(ctx, c, u); err != nil {
		return u, false, err
	}
	return u, false, nil
}

// PersonMail is a person's mail section for c: addresses, aliases (only
// for administrators; [] for a sign_in_help holder) and passwords,
// reconciled with mailctl first (as MyMail; contract §19.11); while
// mailctl can't be read, every active row is "unconfirmed".
func (h *Hub) PersonMail(ctx context.Context, c *directory.Caller, user string) (*PersonMailView, error) {
	u, admin, err := h.mailHelpAllowed(ctx, c, user)
	if err != nil {
		return nil, err
	}
	v := &PersonMailView{Addresses: []string{}, Aliases: []string{}, Passwords: []MailPasswordView{}}
	uuid := ""
	if acct, _, err := h.mailAccount(ctx, u); err == nil {
		v.Addresses = acct.Addresses
		uuid = acct.UUID
		if admin {
			h.mu.RLock()
			v.Aliases = nonNil(h.st.Mail.Aliases[acct.UUID].Addresses)
			h.mu.RUnlock()
		}
	} else if m, err := h.membership(ctx); err == nil {
		uuid = m.UUIDs[u]
	} else {
		return v, nil
	}
	confirmed := false
	if api, err := h.mailUp(ctx); err == nil {
		confirmed = h.reconcileMailPasswords(ctx, api, u, uuid) == nil
	}
	v.Passwords = h.MailPasswords(u, uuid)
	if !confirmed {
		for i := range v.Passwords {
			if v.Passwords[i].Status == "active" {
				v.Passwords[i].Status = "unconfirmed"
			}
		}
	}
	return v, nil
}

// PersonRevokeMailPassword revokes one of user's mail passwords for an
// administrator or a sign_in_help holder who may target them.
func (h *Hub) PersonRevokeMailPassword(ctx context.Context, c *directory.Caller, user, id string) error {
	u, _, err := h.mailHelpAllowed(ctx, c, user)
	if err != nil {
		return err
	}
	return h.AdminRevokeMailPassword(ctx, u, id, directory.Actor{User: c.User, Via: c.Via, Client: c.Client, Confirmation: c.Confirmation})
}

// HostMailDrain makes every mail domain drain (POST /host/mail/drain,
// actor host; contract §19.10).
func (h *Hub) HostMailDrain(ctx context.Context) []MailDomainStateRow {
	coreOn := h.mailOn()
	h.mu.Lock()
	var changed []string
	for _, n := range h.mailDomainNamesLocked() {
		if h.mailDomainStateLocked(n, coreOn) != mailctl.MailOn {
			continue
		}
		if h.st.Mail.Domains == nil {
			h.st.Mail.Domains = map[string]state.MailDomain{}
		}
		e := h.st.Mail.Domains[n]
		e.Enabled, e.Draining = false, true
		h.st.Mail.Domains[n] = e
		changed = append(changed, n)
	}
	if len(changed) > 0 {
		h.saveLocked()
	}
	h.mu.Unlock()
	for _, n := range changed {
		h.auditOp(directory.Human(HostActor), "mail.domain", n, "enabled=false (drain)", nil)
	}
	h.TriggerMailSync()
	return h.mailDomainRows()
}

// HostMailDomains is GET /host/mail/domains: every domain mail is or was
// on for, with its state.
func (h *Hub) HostMailDomains() []MailDomainStateRow {
	coreOn := h.mailOn()
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := []MailDomainStateRow{}
	for _, n := range h.mailDomainNamesLocked() {
		_, entry := h.st.Mail.Domains[n]
		s := h.mailDomainStateLocked(n, coreOn)
		if s == mailctl.MailOff && !entry {
			continue
		}
		// Off but its mail set not removed yet: still draining for the
		// CLI (mail disable waits for every domain off).
		if e := h.st.Mail.Domains[n]; s == mailctl.MailOff && entry && !e.Retired && n != strings.ToLower(h.cfg.Domain) {
			s = mailctl.MailDraining
		}
		out = append(out, MailDomainStateRow{Name: n, State: s})
	}
	return out
}
