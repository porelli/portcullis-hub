package doctor

// SSH access kinds (contract §14.5, §18). Explain-only. None fires while
// SSH access is off, except ssh_breakglass_cert.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SSHHostIn is one managed host as the doctor sees it.
type SSHHostIn struct {
	ID            string
	Enrolled      bool
	LastSync      time.Time
	HostCertUntil time.Time
	Oversize      bool
	// Findings are the host's last report's findings (kind, severity,
	// subject, detail; opaque strings).
	Findings []SSHHostFinding
}

// SSHHostFinding is one host-reported finding.
type SSHHostFinding struct{ Kind, Severity, Subject, Detail string }

// SSHGrantIn is one privileged grant.
type SSHGrantIn struct{ ID, Group, HostGroup, Why string }

// SSHCollisionIn is one skipped personal grant.
type SSHCollisionIn struct{ User, Grant, Reason string }

// SSHHostGroupIn is one host group's use.
type SSHHostGroupIn struct {
	ID            string
	Grants, Hosts int
}

// SSHIn is the SSH kinds' input (nil: none fire).
type SSHIn struct {
	Enabled            bool
	CAProblems         []string
	RoleProblems       map[string]string
	CLIClientConflict  bool
	Privileged         []SSHGrantIn
	Hosts              []SSHHostIn
	HostGroups         []SSHHostGroupIn
	Collisions         []SSHCollisionIn
	Incomplete         []string
	BreakglassImported int
}

// The SSH kinds.
const (
	KindSSHCAMissing            = "ssh_ca_missing"
	KindSSHCLIClientConflict    = "ssh_cli_client_conflict"
	KindSSHPrivilegedGrant      = "ssh_privileged_grant"
	KindSSHHostStale            = "ssh_host_stale"
	KindSSHHostDrift            = "ssh_host_drift"
	KindSSHHostAccountConflict  = "ssh_host_account_conflict"
	KindSSHHostAccountMissing   = "ssh_host_account_missing"
	KindSSHHostAccountInvalid   = "ssh_host_account_invalid"
	KindSSHHostCeiling          = "ssh_host_ceiling"
	KindSSHHostAuthorizedKeys   = "ssh_host_authorized_keys_shared"
	KindSSHHostCertExpiring     = "ssh_host_cert_expiring"
	KindSSHHostBundleTooLarge   = "ssh_host_bundle_too_large"
	KindSSHBreakglassUsed       = "ssh_breakglass_used"
	KindSSHBreakglassCert       = "ssh_breakglass_cert"
	KindSSHHostGroupUnused      = "ssh_hostgroup_unused"
	KindSSHUsernameCollision    = "ssh_username_collision"
	KindSSHRevocationIncomplete = "ssh_revocation_incomplete"
)

// SSH thresholds.
const (
	SSHStaleWarning  = 15 * time.Minute
	SSHStaleProblem  = 24 * time.Hour
	SSHCertExpiring  = 14 * 24 * time.Hour
	sshFindingsLimit = 20
)

func init() {
	for _, c := range []sshCheck{
		{KindSSHCAMissing, sshCAMissing}, {KindSSHCLIClientConflict, sshCLIConflict}, {KindSSHPrivilegedGrant, sshPrivileged},
		{KindSSHHostStale, sshStale}, {KindSSHHostDrift, sshHostKind(KindSSHHostDrift, "", "Drift on a managed host")},
		{KindSSHHostAccountConflict, sshHostKind(KindSSHHostAccountConflict, Warning, "Local accounts Portcullis didn't create")},
		{KindSSHHostAccountMissing, sshHostKind(KindSSHHostAccountMissing, Warning, "Shared accounts missing on a host")},
		{KindSSHHostAccountInvalid, sshHostKind(KindSSHHostAccountInvalid, Warning, "Usernames that can't be local accounts")},
		{KindSSHHostCeiling, sshHostKind(KindSSHHostCeiling, Warning, "A host's local ceiling refused part of its bundle")},
		{KindSSHHostAuthorizedKeys, sshHostKind(KindSSHHostAuthorizedKeys, Info, "Shared accounts with authorized_keys")},
		{KindSSHBreakglassUsed, sshHostKind(KindSSHBreakglassUsed, Warning, "A host's break-glass account was used")},
		{KindSSHHostCertExpiring, sshCertExpiring}, {KindSSHHostBundleTooLarge, sshTooLarge}, {KindSSHBreakglassCert, sshBreakglassCert},
		{KindSSHHostGroupUnused, sshUnused}, {KindSSHUsernameCollision, sshCollision}, {KindSSHRevocationIncomplete, sshIncomplete},
	} {
		Register(c)
	}
}

type sshCheck struct {
	kind string
	run  func(in *Inputs, s *SSHIn) []Finding
}

func (c sshCheck) Kind() string { return c.kind }

func (c sshCheck) Run(in *Inputs) []Finding {
	s := in.SSH
	if s == nil || (!s.Enabled && c.kind != KindSSHBreakglassCert) {
		return nil
	}
	return c.run(in, s)
}

func sshCAMissing(_ *Inputs, s *SSHIn) []Finding {
	var why []string
	why = append(why, s.CAProblems...)
	for _, hg := range sortedMapKeys(s.RoleProblems) {
		why = append(why, "role hg-"+hg+": "+s.RoleProblems[hg])
	}
	if len(why) == 0 {
		return nil
	}
	return []Finding{{FP: Fingerprint(KindSSHCAMissing, why...), Kind: KindSSHCAMissing, Severity: Problem,
		Title: "SSH certificates can't be issued: Vault's SSH setup differs from what Portcullis expects",
		Why:   "No SSH certificate is signed while a mount, cap, CA or role differs (fail closed): " + strings.Join(why, "; ") + ".",
		Steps: []string{"Run ./portcullis status and ./portcullis pki setup on the server: it names the mount or cap that differs.", "Fix it in Vault, then wait a minute: the Hub writes the roles again."}}}
}

func sshCLIConflict(_ *Inputs, s *SSHIn) []Finding {
	if !s.CLIClientConflict {
		return nil
	}
	return []Finding{{FP: Fingerprint(KindSSHCLIClientConflict), Kind: KindSSHCLIClientConflict, Severity: Problem,
		Title: "The Keycloak client portcullis-cli belongs to someone else",
		Why:   "A Keycloak client called portcullis-cli exists without the Hub's owner tag. Every portcullis login fails closed until it's gone.",
		Steps: []string{"In Keycloak (realm portcullis), delete or rename the client portcullis-cli that the Hub didn't create; the Hub then creates its own within a minute."}}}
}

func sshPrivileged(_ *Inputs, s *SSHIn) []Finding {
	var out []Finding
	for _, g := range s.Privileged {
		out = append(out, Finding{FP: Fingerprint(KindSSHPrivilegedGrant, g.ID), Kind: KindSSHPrivilegedGrant, Severity: Info,
			Title: fmt.Sprintf("Privileged SSH grant: %s → %s", g.Group, g.HostGroup),
			Why:   "Its members get " + g.Why + ". They are protected targets: delegates can't send them setup links. Keep the group small."})
	}
	return out
}

func sshStale(in *Inputs, s *SSHIn) []Finding {
	var out []Finding
	for _, h := range s.Hosts {
		if !h.Enrolled {
			continue
		}
		age := in.Now.Sub(h.LastSync)
		if h.LastSync.IsZero() || age <= SSHStaleWarning {
			continue
		}
		sev := Warning
		if age > SSHStaleProblem {
			sev = Problem
		}
		out = append(out, Finding{FP: Fingerprint(KindSSHHostStale, h.ID), Kind: KindSSHHostStale, Severity: sev,
			Title: "Managed host " + h.ID + " hasn't synced for " + age.Round(time.Minute).String(),
			Why:   "It keeps its last files: valid certificates still log in, but revocations and account changes wait until it syncs again.",
			Steps: []string{"On the host: systemctl status portcullis-host-sync; portcullis host status.", "Check that it can reach people." + in.Domain + " over HTTPS."}})
	}
	return out
}

func sshHostKind(kind string, sev Severity, title string) func(in *Inputs, s *SSHIn) []Finding {
	return func(_ *Inputs, s *SSHIn) []Finding {
		var out []Finding
		for _, h := range s.Hosts {
			var subj []string
			worst := sev
			for _, f := range h.Findings {
				if f.Kind != kind {
					continue
				}
				subj = append(subj, clipSSH(f.Subject)+": "+clipSSH(f.Detail))
				if kind == KindSSHHostDrift {
					if f.Severity == "problem" {
						worst = Problem
					} else if worst == "" {
						worst = Warning
					}
				}
			}
			if len(subj) == 0 {
				continue
			}
			sort.Strings(subj)
			if len(subj) > sshFindingsLimit {
				subj = append(subj[:sshFindingsLimit], fmt.Sprintf("and %d more", len(subj)-sshFindingsLimit))
			}
			out = append(out, Finding{FP: Fingerprint(kind, h.ID), Kind: kind, Severity: worst, Title: title + " (" + h.ID + ")",
				Why: "The host reports: " + strings.Join(subj, "; ") + ".", Inputs: strings.Join(subj, "\x00")})
		}
		return out
	}
}

func sshCertExpiring(in *Inputs, s *SSHIn) []Finding {
	var out []Finding
	for _, h := range s.Hosts {
		if h.HostCertUntil.IsZero() || h.HostCertUntil.Sub(in.Now) > SSHCertExpiring {
			continue
		}
		out = append(out, Finding{FP: Fingerprint(KindSSHHostCertExpiring, h.ID), Kind: KindSSHHostCertExpiring, Severity: Warning,
			Title: "Host certificate of " + h.ID + " expires " + h.HostCertUntil.UTC().Format("2006-01-02"),
			Why:   "The Hub renews it at a third of its life left; that it hasn't means the host doesn't sync or enroll can't sign. Clients then warn about the host's key."})
	}
	return out
}

func sshTooLarge(_ *Inputs, s *SSHIn) []Finding {
	var out []Finding
	for _, h := range s.Hosts {
		if h.Oversize {
			out = append(out, Finding{FP: Fingerprint(KindSSHHostBundleTooLarge, h.ID), Kind: KindSSHHostBundleTooLarge, Severity: Problem,
				Title: "The bundle of " + h.ID + " is over 4 MiB and isn't served",
				Why:   "The host keeps its last files. Usually the revoked-keys list or the account list is too long."})
		}
	}
	return out
}

func sshBreakglassCert(_ *Inputs, s *SSHIn) []Finding {
	if s.BreakglassImported == 0 {
		return nil
	}
	return []Finding{{FP: Fingerprint(KindSSHBreakglassCert, fmt.Sprint(s.BreakglassImported)), Kind: KindSSHBreakglassCert, Severity: Warning,
		Title: fmt.Sprintf("%d break-glass SSH certificate(s) were signed on the server", s.BreakglassImported),
		Why:   "./portcullis ssh breakglass-cert signed them with Vault's root token while the Hub was down. They are in the audit (ssh.certificate.breakglass): check who and why."}}
}

func sshUnused(_ *Inputs, s *SSHIn) []Finding {
	var out []Finding
	for _, g := range s.HostGroups {
		if g.ID == "all" || (g.Grants > 0 && g.Hosts > 0) {
			continue
		}
		what := "no grant"
		if g.Grants > 0 {
			what = "no host"
		}
		out = append(out, Finding{FP: Fingerprint(KindSSHHostGroupUnused, g.ID), Kind: KindSSHHostGroupUnused, Severity: Info,
			Title: "Host group " + g.ID + " has " + what, Why: "Nobody can reach a host through it yet."})
	}
	return out
}

func sshCollision(_ *Inputs, s *SSHIn) []Finding {
	var out []Finding
	for _, c := range s.Collisions {
		out = append(out, Finding{FP: Fingerprint(KindSSHUsernameCollision, c.User, c.Grant), Kind: KindSSHUsernameCollision, Severity: Problem,
			Title: "SSH access skipped for " + c.User + ": " + c.Reason, Persons: []string{c.User},
			Why:   "Grant " + c.Grant + " would give " + c.User + " their own account, but " + c.Reason + ". No principal is issued, so the account can never stand in for another.",
			Steps: []string{"Rename the shared account, or give the person a grant with a shared account instead."}})
	}
	return out
}

func sshIncomplete(_ *Inputs, s *SSHIn) []Finding {
	if len(s.Incomplete) == 0 {
		return nil
	}
	fps := append([]string(nil), s.Incomplete...)
	sort.Strings(fps)
	return []Finding{{FP: Fingerprint(KindSSHRevocationIncomplete, fps...), Kind: KindSSHRevocationIncomplete, Severity: Warning,
		Title: "Revocation incomplete: key unknown (" + strings.Join(fps, ", ") + ")",
		Why:   "These keys were revoked by fingerprint but the Hub no longer knows the keys: the Hub won't sign them again and the accounts follow the mapping, but hosts can't refuse their existing certificates until they expire (at most 12 hours)."}}
}

func clipSSH(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

func sortedMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
