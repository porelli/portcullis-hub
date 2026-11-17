package host

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
)

// BuildReport is the state report (contract §18.11): file hashes, the
// effective sshd values, accounts, findings, counts — never log lines.
func BuildReport(ctx context.Context, sys System, hostID string, b *cliapi.Bundle, st *State, c *cliapi.Ceiling, findings []cliapi.Finding, applyErr error, since time.Time, now time.Time) cliapi.Report {
	r := cliapi.Report{Version: cliapi.ReportVersion, HostID: hostID, Time: now.UTC(), Files: map[string]string{}, Effective: map[string]map[string]string{},
		Findings: []cliapi.Finding{}, Accounts: cliapi.ReportAccounts{Present: []string{}, Missing: []string{}, Locked: []string{}, Removed: []string{}}}
	if st != nil {
		r.Serial, r.Applied = st.Serial, applyErr == nil
		for p, h := range st.Files {
			r.Files[p] = h
		}
		r.Accounts.Locked = append(r.Accounts.Locked, st.Locked...)
		r.Accounts.Removed = append(r.Accounts.Removed, st.Removed...)
	}
	if applyErr != nil {
		r.Error = clipStr(firstLine([]byte(applyErr.Error())))
	}
	r.SSHDVersion, _, _, _ = SSHDVersion(ctx, sys)
	acc, err := loadAccounts(sys)
	if err == nil && b != nil {
		for _, a := range b.Accounts {
			if _, ok := acc.users[a.Name]; ok {
				r.Accounts.Present = append(r.Accounts.Present, a.Name)
			} else {
				r.Accounts.Missing = append(r.Accounts.Missing, a.Name)
			}
			if a.Kind == cliapi.AccountShared {
				if u, ok := acc.users[a.Name]; ok {
					r.AuthorizedKeysShared += authorizedKeysCount(sys, u)
				}
			}
		}
	}
	// The effective values, and any override as a Problem.
	check, other := "", "root"
	if c != nil && c.BreakglassAccount != "" {
		other = c.BreakglassAccount
	}
	if b != nil {
		for _, a := range b.Accounts {
			if a.Kind == cliapi.AccountPerson && acc != nil && acc.ours(a.Name) {
				check = a.Name
				break
			}
		}
	}
	if bad, eff, err := EffectiveCheck(ctx, sys, check, other, b != nil && b.HostCertificate != ""); err == nil {
		for u, m := range eff {
			key := "breakglass"
			if u == check {
				key = "portcullis"
			}
			r.Effective[key] = m
		}
		if g, ok := eff[other]; ok {
			r.Effective["global"] = map[string]string{"trustedusercakeys": g["trustedusercakeys"], "authorizedprincipalsfile": g["authorizedprincipalsfile"], "revokedkeys": g["revokedkeys"], "pubkeyauthentication": g["pubkeyauthentication"]}
		}
		for _, m := range bad {
			findings = append(findings, finding(cliapi.FindingDrift, cliapi.SeverityProblem, m.Keyword, m.User+": "+m.Got))
		}
	}
	r.Findings = append(r.Findings, dedupFindings(findings)...)
	por, bg, last := loginCounts(ctx, sys, other, since)
	r.Logins = cliapi.ReportLogins{Portcullis: por, Breakglass: bg, BreakglassLast: last}
	if bg > 0 {
		r.Findings = append(r.Findings, finding(cliapi.FindingBreakglassUsed, cliapi.SeverityWarning, other, last.Time+" from "+last.From))
	}
	if len(r.Findings) > 1024 {
		r.Findings = r.Findings[:1024]
	}
	return r
}

func dedupFindings(fs []cliapi.Finding) []cliapi.Finding {
	seen := map[string]bool{}
	var out []cliapi.Finding
	for _, f := range fs {
		k := f.Kind + "\x00" + f.Subject + "\x00" + f.Detail
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

// loginCounts counts sshd's "Accepted publickey" lines since a time:
// Portcullis certificates (ID pc:) and the break-glass account; the last
// break-glass login's time and address. Counts only (journalctl when
// present; none otherwise).
func loginCounts(ctx context.Context, sys System, breakglass string, since time.Time) (int, int, cliapi.LoginEvent) {
	if sys.LookPath("journalctl") == "" {
		return 0, 0, cliapi.LoginEvent{}
	}
	if since.IsZero() {
		since = time.Now().Add(-5 * time.Minute)
	}
	out, err := sys.Run(ctx, "journalctl", "-q", "--no-pager", "-o", "short-iso", "--since", since.UTC().Format("2006-01-02 15:04:05"), "-t", "sshd", "-t", "sshd-session")
	if err != nil {
		return 0, 0, cliapi.LoginEvent{}
	}
	por, bg := 0, 0
	var last cliapi.LoginEvent
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		i := strings.Index(l, "Accepted publickey for ")
		if i < 0 {
			continue
		}
		f := strings.Fields(l[i+len("Accepted publickey for "):])
		if strings.Contains(l, " ID pc:") {
			por++
		}
		if len(f) >= 3 && f[0] == breakglass && breakglass != "" {
			bg++
			ts := strings.Fields(l)
			if len(ts) > 0 {
				last.Time = clipStr(ts[0])
			}
			last.From = clipStr(f[2])
		}
	}
	return por, bg, last
}
