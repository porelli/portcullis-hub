package hub

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/mailctl"
	"github.com/portcullis/hub/internal/state"
)

// MailUsersGroup is the Hub-managed group whose members get a mailbox
// (contract §19.6).
const MailUsersGroup = "mail_users"

// mailNeverAccount: the LLDAP admin user never gets a mailbox (the Hub's
// service account isn't in the Membership at all).
const mailNeverAccount = "admin"

// localPartRe: a group name usable as a list's local part.
var localPartRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)

// MailBuildInput is everything BuildMailState reads.
type MailBuildInput struct {
	Membership *directory.Membership
	Settings   state.MailSettings
	// MainDomain is Portcullis's main domain; CoreOn PORTCULLIS_MAIL=on.
	MainDomain string
	CoreOn     bool
	// DNSSEC: domain → its zone's DNSSEC state ("" or absent: unknown).
	DNSSEC        map[string]string
	LocalNetworks []string
	Generation    int
}

// mailDomainState is name's mail state from the settings: on, draining or
// off. The main domain is on while core mail is on, unless an entry turns
// it off; an added domain only by its entry.
func mailDomainState(st state.MailSettings, main string, coreOn bool, name string) string {
	name = strings.ToLower(name)
	d, ok := st.Domains[name]
	switch {
	case ok && d.Draining:
		return mailctl.MailDraining
	case ok && d.Enabled:
		return mailctl.MailOn
	case !ok && coreOn && name == strings.ToLower(main):
		return mailctl.MailOn
	}
	return mailctl.MailOff
}

// mailPrimary is the primary domain ("" = the main domain).
func mailPrimary(st state.MailSettings, main string) string {
	if st.PrimaryDomain != "" {
		return strings.ToLower(st.PrimaryDomain)
	}
	return strings.ToLower(main)
}

// BuildMailState is the MailState document for a membership and the
// settings (pure). nil when there is no document to send: core mail off,
// or the primary domain isn't a mail domain. notes say what was left out
// and why (the caller logs them once): a person without a uuid, a
// reserved username, an alias or list mailctl would refuse. Left out
// means fewer addresses, never a refused document.
func BuildMailState(in MailBuildInput) (*mailctl.MailState, []string) {
	if !in.CoreOn {
		return nil, []string{"core mail is off"}
	}
	st, m := in.Settings, in.Membership
	main := strings.ToLower(in.MainDomain)
	primary := mailPrimary(st, main)
	var notes []string
	note := func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }

	// Domains: the main one, then the added ones by name; retired ones
	// aren't sent.
	names := []string{main}
	for n := range st.Domains {
		if n = strings.ToLower(n); n != main {
			names = append(names, n)
		}
	}
	sort.Strings(names[1:])
	doc := &mailctl.MailState{Version: mailctl.StateVersion, Generation: in.Generation, PrimaryDomain: primary,
		Domains: []mailctl.Domain{}, Accounts: []mailctl.Account{}, Aliases: []mailctl.Alias{}, Lists: []mailctl.List{},
		Postmaster: []string{}, LocalNetworks: append([]string{}, in.LocalNetworks...),
		Limits: mailctl.Limits{RecipientsPerHour: st.Limits.RecipientsPerHour, RecipientsPerDay: st.Limits.RecipientsPerDay},
		Spam: mailctl.Spam{RejectScore: st.Spam.RejectScore, JunkScore: st.Spam.JunkScore,
			DNSBL: mailctl.DNSBL{Spamhaus: st.Spam.Spamhaus, Spamcop: st.Spam.Spamcop, Barracuda: st.Spam.Barracuda},
			Allow: append([]string{}, st.Spam.Allow...), Block: append([]string{}, st.Spam.Block...)}}
	live := map[string]bool{} // on or draining: addresses live there
	for _, n := range names {
		s := mailDomainState(st, main, in.CoreOn, n)
		e, ok := st.Domains[n]
		if s == mailctl.MailOff && (!ok || e.Retired) {
			continue
		}
		dmarc := "reject"
		if e.HadMailRecords {
			dmarc = "none"
		}
		dnssec := in.DNSSEC[n]
		if dnssec == "" {
			dnssec = "unknown"
		}
		doc.Domains = append(doc.Domains, mailctl.Domain{Name: n, DMARCStart: dmarc, Mail: s, DNSSEC: dnssec})
		if s != mailctl.MailOff {
			live[n] = true
		}
	}
	if !live[primary] {
		return nil, append(notes, fmt.Sprintf("the primary mail domain %s isn't on: no document", primary))
	}
	if m == nil {
		return nil, append(notes, "no directory")
	}
	inGroup := func(u, g string) bool {
		_, ok := m.Users[u][g]
		return ok && !m.Expired[u][g]
	}
	reserved := func(local string) bool { return slices.Contains(mailctl.ReservedLocalParts, local) }
	used := map[string]string{}

	// Accounts: mail_users' members (a membership that has expired
	// doesn't count), never the LLDAP admin user.
	accounts := map[string]bool{}
	members := append([]string{}, m.Groups[MailUsersGroup].Members...)
	sort.Strings(members)
	for _, u := range members {
		u = strings.ToLower(u)
		switch {
		case u == mailNeverAccount || !inGroup(u, MailUsersGroup):
			continue
		case m.UUIDs[u] == "":
			note("mail: %s has no LLDAP uuid: left out of mail", u)
			continue
		case reserved(u) || !lldap.ValidUsername(u):
			note("mail: the username %s is reserved for mail: left out of mail", u)
			continue
		}
		addrs := []string{u + "@" + primary}
		for _, d := range doc.Domains {
			if d.Name == primary || !live[d.Name] {
				continue
			}
			groups := st.Domains[d.Name].Groups
			// The main domain as a second domain: everyone, unless it has
			// groups; an added domain: its groups' members only.
			ok := d.Name == main && len(groups) == 0
			for _, g := range groups {
				ok = ok || inGroup(u, g)
			}
			if ok {
				addrs = append(addrs, u+"@"+d.Name)
			}
		}
		for _, a := range addrs {
			used[a] = u
		}
		accounts[u] = true
		doc.Accounts = append(doc.Accounts, mailctl.Account{Username: u, UUID: m.UUIDs[u], DisplayName: m.DisplayNames[u], Addresses: addrs, QuotaBytes: mailQuota(st, m, u)})
	}
	// addrOK: addr is on a live mail domain, not reserved and unused.
	addrOK := func(addr, what string) bool {
		local, dom, ok := strings.Cut(addr, "@")
		switch {
		case !ok || !live[dom]:
			note("mail: %s %s isn't on a mail domain: left out", what, addr)
		case reserved(local):
			note("mail: %s %s is a reserved address: left out", what, addr)
		case used[addr] != "":
			note("mail: %s %s is already %s's: left out", what, addr, used[addr])
		default:
			return true
		}
		return false
	}
	users := make([]string, 0, len(st.Aliases))
	for u := range st.Aliases {
		users = append(users, u)
	}
	sort.Strings(users)
	for _, u := range users {
		if !accounts[strings.ToLower(u)] {
			if len(st.Aliases[u]) > 0 {
				note("mail: %s's aliases are left out: they have no mailbox", u)
			}
			continue
		}
		for _, a := range st.Aliases[u] {
			a = strings.ToLower(a)
			if addrOK(a, "alias") {
				used[a] = u
				doc.Aliases = append(doc.Aliases, mailctl.Alias{Address: a, Username: strings.ToLower(u)})
			}
		}
	}
	groups := make([]string, 0, len(st.Lists))
	for g := range st.Lists {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	for _, g := range groups {
		l := st.Lists[g]
		local := strings.ToLower(g)
		if !localPartRe.MatchString(local) {
			note("mail: the group %s can't be a list address: left out", g)
			continue
		}
		addr := local + "@" + strings.ToLower(l.Domain)
		if !addrOK(addr, "list") {
			continue
		}
		used[addr] = "the list " + g
		var ms []string
		for _, u := range m.Groups[g].Members {
			if u = strings.ToLower(u); accounts[u] && inGroup(u, g) {
				ms = append(ms, u)
			}
		}
		sort.Strings(ms)
		if ms == nil {
			ms = []string{}
		}
		posting := l.Posting
		if posting == "" {
			posting = state.MailPostingMembers
		}
		doc.Lists = append(doc.Lists, mailctl.List{Address: addr, Members: ms, Posting: posting})
	}
	for _, u := range m.Groups[lldap.AdminGroup].Members {
		if u = strings.ToLower(u); accounts[u] {
			doc.Postmaster = append(doc.Postmaster, u)
		}
	}
	sort.Strings(doc.Postmaster)
	return doc, notes
}

// mailQuota is u's quota: the largest of the rows of groups u is in, else
// the default (10 GiB).
func mailQuota(st state.MailSettings, m *directory.Membership, u string) int64 {
	var q int64
	for _, r := range st.Quotas {
		if _, ok := m.Users[u][r.Group]; ok && !m.Expired[u][r.Group] && r.Bytes > q {
			q = r.Bytes
		}
	}
	if q == 0 {
		q = state.DefaultMailQuotaBytes
	}
	return q
}

// mailDiff classifies the change from one document to the next.
type mailDiff struct {
	// removal: an account, an address, an alias, a list or a list member
	// (or a postmaster) is gone: sent at once.
	removal bool
	// addition: something new to deliver to (debounced 60 s).
	addition bool
	// other: anything else differs (settings, domain states, names).
	other bool
	// removedUsers: accounts gone (their usernames); removedAccounts the
	// count.
	removedUsers    []string
	removedAccounts int
	// removedUUIDs: each removed account's username → its uuid (the
	// mail passwords created under it end, revoke_leave).
	removedUUIDs map[string]string
}

func (d mailDiff) any() bool { return d.removal || d.addition || d.other }

func diffMail(prev, next *mailctl.MailState) mailDiff {
	var d mailDiff
	if prev == nil {
		d.other = true
		return d
	}
	pa, na := map[string]mailctl.Account{}, map[string]mailctl.Account{}
	for _, a := range prev.Accounts {
		pa[a.UUID] = a
	}
	for _, a := range next.Accounts {
		na[a.UUID] = a
	}
	for id, a := range pa {
		b, ok := na[id]
		if !ok || b.Username != a.Username {
			d.removal = true
			d.removedAccounts++
			d.removedUsers = append(d.removedUsers, a.Username)
			if d.removedUUIDs == nil {
				d.removedUUIDs = map[string]string{}
			}
			d.removedUUIDs[a.Username] = id
			continue
		}
		if !subset(a.Addresses, b.Addresses) {
			d.removal = true
		}
		if !subset(b.Addresses, a.Addresses) {
			d.addition = true
		}
	}
	for id := range na {
		if _, ok := pa[id]; !ok {
			d.addition = true
		}
	}
	sort.Strings(d.removedUsers)
	alias := func(s []mailctl.Alias) []string {
		var out []string
		for _, a := range s {
			out = append(out, a.Address+"\x00"+a.Username)
		}
		return out
	}
	if !subset(alias(prev.Aliases), alias(next.Aliases)) {
		d.removal = true
	}
	if !subset(alias(next.Aliases), alias(prev.Aliases)) {
		d.addition = true
	}
	pl, nl := map[string]mailctl.List{}, map[string]mailctl.List{}
	for _, l := range prev.Lists {
		pl[l.Address] = l
	}
	for _, l := range next.Lists {
		nl[l.Address] = l
	}
	for a, l := range pl {
		n, ok := nl[a]
		if !ok || !subset(l.Members, n.Members) {
			d.removal = true
		}
		if ok && (!subset(n.Members, l.Members) || n.Posting != l.Posting) {
			if n.Posting != l.Posting {
				d.other = true
			} else {
				d.addition = true
			}
		}
	}
	for a := range nl {
		if _, ok := pl[a]; !ok {
			d.addition = true
		}
	}
	if !subset(prev.Postmaster, next.Postmaster) {
		d.removal = true
	}
	if !subset(next.Postmaster, prev.Postmaster) {
		d.addition = true
	}
	// Everything else: compare the documents without the parts above.
	strip := func(s *mailctl.MailState) mailctl.MailState {
		c := *s
		c.Generation, c.ConfirmMassRemoval = 0, false
		c.Aliases, c.Lists, c.Postmaster = nil, nil, nil
		c.Accounts = nil
		for _, a := range s.Accounts {
			a.Addresses = nil
			c.Accounts = append(c.Accounts, a)
		}
		sort.Slice(c.Accounts, func(i, j int) bool { return c.Accounts[i].UUID < c.Accounts[j].UUID })
		return c
	}
	sp, sn := strip(prev), strip(next)
	// Accounts added or removed already count; compare the kept ones.
	keep := func(s []mailctl.Account, other map[string]mailctl.Account) []mailctl.Account {
		var out []mailctl.Account
		for _, a := range s {
			if _, ok := other[a.UUID]; ok {
				out = append(out, a)
			}
		}
		return out
	}
	sp.Accounts, sn.Accounts = keep(sp.Accounts, na), keep(sn.Accounts, pa)
	if !reflect.DeepEqual(sp, sn) {
		d.other = true
	}
	return d
}

// subset: every element of a is in b.
func subset(a, b []string) bool {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	for _, x := range a {
		if !in[x] {
			return false
		}
	}
	return true
}
