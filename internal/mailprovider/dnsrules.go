package mailprovider

// The shared mail set rules (contract §19.7 "Set validation"): one rule
// set with the domains service's PUT /domains/{name}/sets/mail (core
// domains/internal/dnsplan/mailrules.go), held equal by the shared
// vectors testdata/mail_dns_vectors.json (byte-copied into core). A
// record is allowed only with a name and value from the contract's table:
// a provider can't point mail at another host, widen SPF, receive reports
// elsewhere, lower DMARC or touch CAA, TLSA or address records.
//
// Per record, in list order (the first failing record is the answer):
// not under the domain → a type the set never holds → a name outside the
// table or the wrong type for the name → the value. Texts are
// "mail set: <name> <type>: <why>".

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

// RuleContext is what the rules judge a set against.
type RuleContext struct {
	Domain       string // the mail domain <e>
	MailHostname string // MAIL_HOSTNAME <h>
	RelayInclude string // the relay's SPF include ("" = none)
	DMARCFloor   string // none | quarantine | reject
	Wildcard     bool   // the domain's plan has a *.<e> address record (no CNAMEs then)
	// Draining: the domain's mail is draining (its set is only the
	// _mta-sts record): no _dmarc record is required then.
	Draining bool
}

var (
	reSTS       = regexp.MustCompile(`^v=STSv1; id=[A-Za-z0-9]{1,32}$`)
	reTLSRPT    = regexp.MustCompile(`^v=TLSRPTv1; rua=mailto:(\S+)$`)
	reSRV       = regexp.MustCompile(`^([0-9]{1,5}) ([0-9]{1,5}) ([0-9]{1,5}) (\S+)$`)
	reMX        = regexp.MustCompile(`^([0-9]{1,5}) (\S+)$`)
	reLabel1    = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
	reSeconds   = regexp.MustCompile(`^[0-9]{1,10}$`)
	reASCIIName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
	reDKIMTag   = regexp.MustCompile(`^[a-z]{1,8}$`)
	reBase64    = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
)

// Value shape bounds (M12).
const (
	ruleTTLMin    = 60
	ruleTTLMax    = 86400
	ruleTXTMax    = 2048 // a 4096-bit RSA DKIM key fits
	ruleTargetMax = 255
)

// valueShape: "" or the why — the TTL in range, printable ASCII only,
// at most ruleTXTMax (TXT) or ruleTargetMax (others) characters.
func valueShape(t string, ttl int, v string) string {
	if ttl < ruleTTLMin || ttl > ruleTTLMax {
		return fmt.Sprintf("ttl must be %d–%d", ruleTTLMin, ruleTTLMax)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return "the value must be printable ASCII"
		}
	}
	// The raw value is what DNS gets (R2-N3): never trimmed, so a
	// leading or trailing space is refused (" v=DMARC1; …" is no DMARC
	// record for receivers).
	if v != strings.TrimSpace(v) {
		return "the value has leading or trailing whitespace"
	}
	max := ruleTargetMax
	if t == "TXT" {
		max = ruleTXTMax
	}
	if len(v) > max {
		return fmt.Sprintf("the value is longer than %d characters", max)
	}
	return ""
}

// u16: a decimal 0–65535.
func u16(s string) bool {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return len(s) > 0 && len(s) <= 5 && n <= 65535
}

// dkimTagsOK: after v=DKIM1; every tag is <lowercase name>=<value>,
// each once, and p= (base64, empty = revoked) is there.
func dkimTagsOK(v string) bool {
	seen := map[string]bool{}
	for _, tag := range strings.Split(v, ";")[1:] {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		k, val, ok := strings.Cut(tag, "=")
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		if !ok || !reDKIMTag.MatchString(k) || seen[k] {
			return false
		}
		seen[k] = true
		if k == "p" && !reBase64.MatchString(val) {
			return false
		}
	}
	return seen["p"]
}

var dmarcRank = map[string]int{"none": 0, "quarantine": 1, "reject": 2}

// The allowed types of the set.
var ruleTypes = map[string]bool{"MX": true, "TXT": true, "SRV": true, "CNAME": true}

// srvPorts: the SRV names with a service, by port; the others are "0 0 0 .".
var srvPorts = map[string]string{"_submissions._tcp": "465", "_submission._tcp": "587", "_imaps._tcp": "993"}
var srvNull = []string{"_imap._tcp", "_pop3._tcp", "_pop3s._tcp"}

// ValidateSet judges rs against c (contract §19.7): nil, or the first
// refusal's text.
func ValidateSet(c RuleContext, rs []Record) error {
	e := bare(c.Domain)
	h := bare(c.MailHostname)
	spf, dmarc := 0, 0
	for _, r := range rs {
		// Exact ASCII names and upper-case types (final review L2): no
		// Unicode case folding (K → k, ſ → S) decides a name or a type.
		n, t := bare(r.Name), asciiUpper(r.Type)
		refuse := func(why string) error { return fmt.Errorf("mail set: %s %s: %s", n, t, why) }
		if t != r.Type {
			return refuse("the type must be upper case")
		}
		if !reASCIIName.MatchString(r.Name) {
			return fmt.Errorf("mail set: %s %s: the name must be ASCII letters, digits, '.', '-' and '_'", r.Name, t)
		}
		if !under(n, e) {
			return refuse("not under " + e)
		}
		if !ruleTypes[t] {
			return refuse(t + " records are not allowed")
		}
		rel := strings.TrimSuffix(strings.TrimSuffix(n, e), ".")
		// A draining domain's set is only its _mta-sts record (§19.7):
		// nothing else, so the DMARC waiver can't let anything through.
		if c.Draining && !(rel == "_mta-sts" && t == "TXT") {
			return refuse("a draining set holds only _mta-sts." + e)
		}
		// The value's shape before its meaning (M12): printable ASCII
		// only (no tab, newline or control byte reaches DNS), a bounded
		// length and TTL.
		if why := valueShape(t, r.TTL, r.Value); why != "" {
			return refuse(why)
		}
		v := r.Value
		switch {
		case n == e:
			switch t {
			case "MX":
				m := reMX.FindStringSubmatch(v)
				if m == nil || !strings.EqualFold(m[2], h+".") {
					return refuse("the target must be " + h + ".")
				}
				if !u16(m[1]) {
					return refuse("the priority must be 0–65535")
				}
			case "TXT":
				if !strings.HasPrefix(v, "v=spf1 ") {
					return refuse("only one v=spf1 TXT here")
				}
				spf++
				if spf > 1 {
					return refuse("more than one SPF record")
				}
				for _, term := range strings.Fields(v)[1:] {
					ok := term == "mx" || term == "-all" || term == "~all" ||
						(c.RelayInclude != "" && strings.EqualFold(term, "include:"+bare(c.RelayInclude)))
					if !ok {
						return refuse("SPF term " + term + " is not allowed")
					}
				}
			default:
				return refuse("only MX and TXT here")
			}
		case strings.HasSuffix(rel, "._domainkey") || rel == "_domainkey":
			sel := strings.TrimSuffix(rel, "._domainkey")
			if rel == "_domainkey" || strings.Contains(sel, ".") || !reLabel1.MatchString(sel) {
				return refuse("the DKIM selector must be one DNS label")
			}
			if t != "TXT" {
				return refuse("only TXT here")
			}
			if !strings.HasPrefix(v, "v=DKIM1;") {
				return refuse("must start with v=DKIM1;")
			}
			if !dkimTagsOK(v) {
				return refuse("the DKIM tags must be <name>=<value>, with p=<base64>")
			}
		case rel == "_dmarc":
			if t != "TXT" {
				return refuse("only TXT here")
			}
			dmarc++
			if dmarc > 1 {
				return refuse("more than one DMARC record")
			}
			if err := dmarcRule(v, e, c.DMARCFloor); err != "" {
				return refuse(err)
			}
		case rel == "_mta-sts":
			if t != "TXT" {
				return refuse("only TXT here")
			}
			if !reSTS.MatchString(v) {
				return refuse("must be v=STSv1; id=<1–32 letters or digits>")
			}
		case rel == "_smtp._tls":
			if t != "TXT" {
				return refuse("only TXT here")
			}
			m := reTLSRPT.FindStringSubmatch(v)
			if m == nil || !onDomain(m[1], e) {
				return refuse("must be v=TLSRPTv1; rua=mailto:<an address on " + e + ">")
			}
		case srvPorts[rel] != "":
			if t != "SRV" {
				return refuse("only SRV here")
			}
			m := reSRV.FindStringSubmatch(v)
			if m == nil || m[3] != srvPorts[rel] || !strings.EqualFold(m[4], h+".") {
				return refuse("must be <priority> <weight> " + srvPorts[rel] + " " + h + ".")
			}
			if !u16(m[1]) || !u16(m[2]) {
				return refuse("priority and weight must be 0–65535")
			}
		case contains(srvNull, rel):
			if t != "SRV" {
				return refuse("only SRV here")
			}
			if v != "0 0 0 ." { // the raw value, exactly (L1)
				return refuse("must be 0 0 0 .")
			}
		case contains(mailCNAMELabels, rel):
			if t != "CNAME" {
				return refuse("only CNAME here")
			}
			if c.Wildcard {
				return refuse("only when the Hub asked with wildcard=false")
			}
			if !strings.EqualFold(v, h+".") {
				return refuse("the target must be " + h + ".")
			}
		default:
			return refuse("not a mail record name")
		}
	}
	// Ruling R-H3: with a floor set (quarantine or reject) an active
	// domain's set carries exactly one DMARC record, never none.
	if dmarc == 0 && !c.Draining && dmarcRank[c.DMARCFloor] > 0 {
		return fmt.Errorf("mail set: _dmarc.%s TXT: required while the DMARC floor is %s", e, c.DMARCFloor)
	}
	return nil
}

// dmarcTags are the DMARC tags a record may carry (RFC 7489 §6.3; ruf
// is then refused by its own rule).
var dmarcTags = map[string]bool{"v": true, "p": true, "sp": true, "np": true, "rua": true, "ruf": true, "adkim": true, "aspf": true,
	"fo": true, "rf": true, "ri": true, "pct": true, "t": true}

// dmarcRule: "" or the why (Ruling R-H3, canonical): lowercase tag
// names, every tag once, only the known tags; no ruf; rua only mailto:
// addresses on e; no t=y; pct only 100; p (and sp, np when given) none,
// quarantine or reject, all at or above the floor.
func dmarcRule(v, e, floor string) string {
	if !strings.HasPrefix(v, "v=DMARC1;") {
		return "must start with v=DMARC1;"
	}
	p := ""
	sub := map[string]string{} // sp, np as given
	seen := map[string]bool{"v": true}
	tags := strings.Split(v, ";")[1:]
	for i, tag := range tags {
		if strings.TrimSpace(tag) == "" {
			// Only a final separator may be empty (RFC 7489: no empty
			// tag; final review L1).
			if i == len(tags)-1 {
				continue
			}
			return "an empty tag is not allowed"
		}
		k, val, _ := strings.Cut(strings.TrimSpace(tag), "=")
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		if k != strings.ToLower(k) {
			return "tag " + k + " must be lowercase"
		}
		if seen[k] {
			return "tag " + k + " is given twice"
		}
		seen[k] = true
		if !dmarcTags[k] {
			return "tag " + k + " is not allowed"
		}
		switch k {
		case "p":
			p = strings.ToLower(val)
		case "sp", "np":
			sub[k] = strings.ToLower(val)
		case "ruf":
			return "ruf is not allowed"
		case "t":
			if strings.EqualFold(val, "y") {
				return "t=y is not allowed"
			}
		case "pct":
			if val != "100" {
				return "pct must be 100 or absent"
			}
		case "adkim", "aspf":
			if val != "r" && val != "s" {
				return k + " must be r or s"
			}
		case "fo":
			for _, o := range strings.Split(val, ":") {
				if o != "0" && o != "1" && o != "d" && o != "s" {
					return "fo must be 0, 1, d or s, colon-separated"
				}
			}
		case "rf":
			if val != "afrf" {
				return "rf must be afrf"
			}
		case "ri":
			if !reSeconds.MatchString(val) {
				return "ri must be a whole number of seconds"
			}
		case "rua":
			for _, u := range strings.Split(val, ",") {
				u = strings.TrimSpace(u)
				addr, ok := strings.CutPrefix(strings.ToLower(u), "mailto:")
				if !ok || !onDomain(addr, e) {
					return "rua " + u + " is not on " + e
				}
			}
		}
	}
	rp, ok := dmarcRank[p]
	if !ok {
		return "must carry p=none, quarantine or reject"
	}
	rf, floorSet := dmarcRank[floor]
	if floorSet && rp < rf {
		return "p=" + p + " is below the floor " + floor
	}
	for _, k := range []string{"sp", "np"} {
		val, given := sub[k]
		if !given {
			continue
		}
		rs, ok := dmarcRank[val]
		if !ok {
			return "must carry " + k + "=none, quarantine or reject"
		}
		if floorSet && rs < rf {
			return k + "=" + val + " is below the floor " + floor
		}
	}
	return ""
}

// onDomain: a is one address whose domain is exactly e.
func onDomain(a, e string) bool {
	m, err := mail.ParseAddress(a)
	if err != nil || m.Name != "" || m.Address != a {
		return false
	}
	i := strings.LastIndexByte(a, '@')
	return i > 0 && strings.EqualFold(a[i+1:], e)
}

// bare is n lowercased without a trailing dot.
func bare(n string) string { return strings.TrimSuffix(strings.ToLower(n), ".") }

// under: n is d or a name under it.
func under(n, d string) bool { return n == d || strings.HasSuffix(n, "."+d) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// mailCNAMELabels are the names a set may CNAME to MAIL_HOSTNAME.
var mailCNAMELabels = []string{"mta-sts", "autoconfig", "autodiscover"}

// DMARCPolicy is the p= of a set's _dmarc.<domain> TXT ("" = none).
func DMARCPolicy(domain string, rs []Record) string {
	e := bare(domain)
	for _, r := range rs {
		if bare(r.Name) != "_dmarc."+e || !strings.EqualFold(r.Type, "TXT") {
			continue
		}
		for _, tag := range strings.Split(r.Value, ";")[1:] {
			k, val, _ := strings.Cut(strings.TrimSpace(tag), "=")
			if strings.EqualFold(strings.TrimSpace(k), "p") {
				p := strings.ToLower(strings.TrimSpace(val))
				if _, ok := dmarcRank[p]; ok {
					return p
				}
			}
		}
	}
	return ""
}

// StricterDMARC is the stricter of two policies (unknown counts as none).
func StricterDMARC(a, b string) string {
	if dmarcRank[b] > dmarcRank[a] {
		return b
	}
	if _, ok := dmarcRank[a]; !ok {
		return "none"
	}
	return a
}

// asciiUpper upper-cases ASCII letters only (no Unicode folding).
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
