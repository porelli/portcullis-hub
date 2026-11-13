package doctor

import (
	"slices"
	"sort"
	"strings"

	"github.com/portcullis/hub/internal/domains"
)

// DNS kinds (contract §14.5, DNS hardening): judged on the cached DNS
// plans (§12.2) of every added domain (Inputs.DNS) and of the main domain
// (Inputs.DNSMain). Inputs.DNS nil = the plans couldn't be read: no DNS
// findings, and Run sets Report.DNSUnavailable. Every finding carries
// Domains [<d>]; its fingerprint is the kind and <d> (plus the record's
// name for dns_dangling and dns_shadowed), its inputs digest the items'
// live values. The main domain's findings are all explain-only, with the
// step "Run `./portcullis dns setup` on the server" (dnssec_unsigned:
// DNSMainDNSSECStep). A plan whose lookups failed (an unknown item above
// info, or DNSSEC state unknown) sets Report.DNSUnavailable too
// (dnsPartial).
const (
	KindDNSRecordsWrong      = "dns_records_wrong"
	KindDNSCAAMissing        = "dns_caa_missing"
	KindDNSCAAWrongAccount   = "dns_caa_wrong_account"
	KindDNSCAAOtherIssuers   = "dns_caa_other_issuers"
	KindDNSSECBogus          = "dnssec_bogus"
	KindDNSSECDSMissing      = "dnssec_ds_missing"
	KindDNSSECUnsigned       = "dnssec_unsigned"
	KindDNSDangling          = "dns_dangling"
	KindDNSShadowed          = "dns_shadowed"
	KindDNSNoMailRecommended = "dns_nomail_recommended"
)

// DNS fix kinds (§14.6).
const (
	FixDNSApply   = "dns_apply"
	FixDNSSECSign = "dnssec_sign"
)

// DNSMainStep is the main domain's only fix: its records are set on the
// server, never by the Hub.
const DNSMainStep = "Run `./portcullis dns setup` on the server"

// DNSMainDNSSECStep is the main domain's dnssec_unsigned step: signing
// is opt-in (--dnssec) and only Cloudflare can sign through its API.
const DNSMainDNSSECStep = "Run `./portcullis dns setup --dnssec` on the server (Cloudflare only)"

// DNSKinds are the ten DNS kinds.
var DNSKinds = []string{KindDNSRecordsWrong, KindDNSCAAMissing, KindDNSCAAWrongAccount, KindDNSCAAOtherIssuers,
	KindDNSSECBogus, KindDNSSECDSMissing, KindDNSSECUnsigned, KindDNSDangling, KindDNSShadowed, KindDNSNoMailRecommended}

// DNSFixSets is the record set a dns_apply fix of a finding of kind
// writes (the param sets; nil: the kind has no dns_apply fix).
func DNSFixSets(kind string) []string {
	switch kind {
	case KindDNSRecordsWrong:
		return []string{domains.SetAddress}
	case KindDNSCAAMissing, KindDNSCAAWrongAccount:
		return []string{domains.SetCAA}
	case KindDNSNoMailRecommended:
		return []string{domains.SetNoMail}
	}
	return nil
}

func init() {
	for _, k := range DNSKinds {
		Register(dnsCheck{kind: k})
	}
}

// dnsCheck is one DNS kind (all ten judge the same plans).
type dnsCheck struct{ kind string }

func (c dnsCheck) Kind() string { return c.kind }

func (c dnsCheck) Run(in *Inputs) []Finding {
	var out []Finding
	for _, f := range dnsFindings(in) {
		if f.Kind == c.kind {
			out = append(out, f)
		}
	}
	return out
}

// dnsFindings judges every plan (none while the plans are unavailable).
func dnsFindings(in *Inputs) []Finding {
	if in.DNS == nil {
		return nil
	}
	var out []Finding
	for i := range in.DNS {
		out = append(out, planFindings(&in.DNS[i], false)...)
	}
	if in.DNSMain != nil {
		out = append(out, planFindings(in.DNSMain, true)...)
	}
	return out
}

// dnsPartial: some plan's lookups failed, so its checks didn't really
// run — an unknown item above info (the unknown-CA item is info: CAA is
// skipped on purpose), or DNSSEC state unknown.
func dnsPartial(in *Inputs) bool {
	plans := slices.Clone(in.DNS)
	if in.DNSMain != nil {
		plans = append(plans, *in.DNSMain)
	}
	for _, p := range plans {
		if p.DNSSEC.State == "unknown" {
			return true
		}
		for _, it := range p.Items {
			if it.Status == "unknown" && it.Severity != "info" {
				return true
			}
		}
	}
	return false
}

// liveOf is the items' live values (the mute's inputs), in a stable
// order (the plan's item order doesn't matter).
func liveOf(items []domains.PlanItem) [][]string {
	out := make([][]string, 0, len(items))
	for _, it := range items {
		l := append([]string{it.Set, it.Name, it.Type}, it.Live...)
		sort.Strings(l[3:])
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Join(out[i], "\x00") < strings.Join(out[j], "\x00") })
	return out
}

func stepsOf(items []domains.PlanItem) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.Steps...)
	}
	return out
}

// accountURIOf: the accounturi parameter of a CAA value ("" = none).
func accountURIOf(v string) string {
	i := strings.Index(strings.ToLower(v), "accounturi=")
	if i < 0 {
		return ""
	}
	rest := v[i+len("accounturi="):]
	if j := strings.IndexAny(rest, `;" `); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// planFindings judges one plan.
func planFindings(p *domains.Plan, main bool) []Finding {
	d := p.Name
	var out []Finding
	// mk builds a finding; fix is the one-click fix kind ("" = explain).
	mk := func(kind string, sev Severity, title, why, fix string, steps []string, inputs any, subjects ...string) {
		f := Finding{Kind: kind, Severity: sev, Title: title, Why: why, Domains: []string{d},
			FP: Fingerprint(kind, append([]string{d}, subjects...)...), Inputs: Digest(inputs)}
		switch {
		case main:
			last := DNSMainStep
			if kind == KindDNSSECUnsigned {
				last = DNSMainDNSSECStep
			}
			f.Class, f.Steps = FixExplain, append(append([]string(nil), steps...), last)
		case fix != "":
			f.Class, f.FixKind, f.Steps = FixOneClick, fix, steps
		default:
			f.Class, f.Steps = FixExplain, steps
		}
		if len(f.Steps) == 0 {
			f.Steps = nil
		}
		out = append(out, f)
	}
	var addr, caaMissing, nomail []domains.PlanItem
	blocked := false // a CNAME at <d> / *.<d>: the service refuses address
	for _, it := range p.Items {
		switch {
		case it.Set == domains.SetAddress && (it.Status == "missing" || it.Status == "wrong"):
			addr = append(addr, it)
		case it.Set == domains.SetAddress && it.Status == "foreign" && it.Severity == "problem":
			addr, blocked = append(addr, it), true
		case it.Set == domains.SetCAA && it.Status == "missing":
			caaMissing = append(caaMissing, it)
		case it.Set == domains.SetNoMail && it.Status == "missing":
			nomail = append(nomail, it)
		}
	}
	if len(addr) > 0 {
		fix := FixDNSApply
		if blocked {
			fix = ""
		}
		mk(KindDNSRecordsWrong, Problem, "The address records of "+d+" don't point at this server",
			"Apps on "+d+" are unreachable, or reach another server, until its A / AAAA records name this server's addresses.",
			fix, stepsOf(addr), liveOf(addr))
	}
	if len(caaMissing) > 0 {
		mk(KindDNSCAAMissing, Warning, d+" has no CAA record for Portcullis",
			"Without CAA, any certificate authority may issue certificates for "+d+"; the CAA pin limits it to Portcullis' CA and ACME account.",
			FixDNSApply, stepsOf(caaMissing), liveOf(caaMissing))
	}
	// A live pin naming another account: the CA would refuse our orders.
	if !p.CAA.WouldIssue {
		var wrong []domains.PlanItem
		for _, it := range p.Items {
			if it.Set != domains.SetCAA || it.Status == "missing" || it.Status == "unknown" {
				continue
			}
			for _, v := range it.Live {
				if u := accountURIOf(v); u != "" && u != p.CAA.AccountURI {
					wrong = append(wrong, it)
					break
				}
			}
		}
		if len(wrong) > 0 {
			mk(KindDNSCAAWrongAccount, Problem, "The CAA of "+d+" pins another ACME account",
				"The CA refuses to issue or renew "+d+"'s certificate for Portcullis' account while the CAA names another one.",
				FixDNSApply, stepsOf(wrong), liveOf(wrong))
		}
	}
	for _, it := range p.Items {
		if it.Set != domains.SetCAA || it.Status != "foreign" {
			continue
		}
		other := false
		for _, s := range it.Steps {
			other = other || strings.HasPrefix(s, "other CAs may also issue")
		}
		if other {
			mk(KindDNSCAAOtherIssuers, Info, "Other certificate authorities may also issue for "+d,
				"The CAA of "+d+" also allows other CAs; Portcullis leaves their entries alone.",
				"", it.Steps, liveOf([]domains.PlanItem{it}))
		}
	}
	dnssecIn := struct {
		State string
		DS    []domains.DS
	}{p.DNSSEC.State, p.DNSSEC.DS}
	switch p.DNSSEC.State {
	case "bogus", "ds_mismatch":
		mk(KindDNSSECBogus, Problem, "DNSSEC validation fails for "+d,
			"Validating resolvers (most public ones) can't resolve "+d+" or anything in the zone "+p.DNSSEC.Zone+" while its DS doesn't match the zone's keys.",
			"", p.DNSSEC.Steps, dnssecIn)
	case "ds_missing":
		mk(KindDNSSECDSMissing, Warning, "The zone of "+d+" is signed but has no DS at the registrar",
			"Signing protects nobody until the parent zone publishes the DS: add it at your registrar.",
			"", p.DNSSEC.Steps, dnssecIn)
	case "unsigned":
		fix := ""
		if p.DNSSEC.ProviderCanSign {
			fix = FixDNSSECSign
		}
		mk(KindDNSSECUnsigned, Info, "The zone of "+d+" isn't signed with DNSSEC",
			"Without DNSSEC, resolvers can't tell forged answers for "+d+" from real ones. Signing is zone-wide ("+p.DNSSEC.Zone+").",
			fix, p.DNSSEC.Steps, dnssecIn)
	}
	for _, it := range p.Items {
		if it.Set != domains.SetAddress || it.Status != "foreign" {
			continue
		}
		switch {
		case it.Severity == "warning":
			mk(KindDNSDangling, Warning, it.Name+" points at a name that doesn't exist",
				"A dangling "+it.Type+" can be taken over by whoever registers its target, and "+it.Name+" doesn't reach Portcullis.",
				"", it.Steps, liveOf([]domains.PlanItem{it}), it.Name)
		case it.Severity == "info" && !(it.Type == "TXT" && strings.HasPrefix(it.Name, "_acme-challenge.")):
			mk(KindDNSShadowed, Info, it.Name+" doesn't reach Portcullis",
				"A record of its own at "+it.Name+" overrides *."+d+": apps can't use that hostname.",
				"", it.Steps, liveOf([]domains.PlanItem{it}), it.Name)
		}
	}
	if len(nomail) > 0 {
		mk(KindDNSNoMailRecommended, Info, d+" could say it sends no mail",
			d+" has no MX and no SPF: publishing a null MX, SPF -all and DMARC reject stops others sending mail as it.",
			FixDNSApply, stepsOf(nomail), liveOf(nomail))
	}
	return out
}
