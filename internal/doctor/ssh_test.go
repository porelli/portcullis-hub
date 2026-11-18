package doctor

import (
	"testing"
	"time"
)

var sshNow = time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

// runSSH is every SSH kind's findings over in, by kind (with severities).
func runSSH(in *SSHIn) map[string][]Severity {
	out := map[string][]Severity{}
	regMu.Lock()
	checks := append([]Check(nil), registry...)
	regMu.Unlock()
	for _, c := range checks {
		if _, ok := c.(sshCheck); !ok {
			continue
		}
		for _, f := range c.Run(&Inputs{Now: sshNow, Domain: "example.org", SSH: in}) {
			out[f.Kind] = append(out[f.Kind], f.Severity)
		}
	}
	return out
}

func quiet() *SSHIn {
	return &SSHIn{Enabled: true, HostGroups: []SSHHostGroupIn{{ID: "all"}, {ID: "web", Grants: 1, Hosts: 1}},
		Hosts: []SSHHostIn{{ID: "web-1", Enrolled: true, LastSync: sshNow.Add(-time.Minute), HostCertUntil: sshNow.Add(60 * 24 * time.Hour)}}}
}

func TestSSHKindsQuiet(t *testing.T) {
	if got := runSSH(nil); len(got) != 0 {
		t.Errorf("nil: %v", got)
	}
	if got := runSSH(quiet()); len(got) != 0 {
		t.Errorf("all good: %v", got)
	}
	off := quiet()
	off.Enabled = false
	off.CAProblems = []string{"no user CA"}
	off.BreakglassImported = 1
	if got := runSSH(off); len(got) != 1 || len(got[KindSSHBreakglassCert]) != 1 {
		t.Errorf("SSH off: only ssh_breakglass_cert fires: %v", got)
	}
}

func TestSSHKindsFire(t *testing.T) {
	for kind, tc := range map[string]struct {
		edit func(*SSHIn)
		want Severity
	}{
		KindSSHCAMissing:         {func(s *SSHIn) { s.CAProblems = []string{"ssh_user max_lease_ttl is 24h, not 12h"} }, Problem},
		KindSSHCLIClientConflict: {func(s *SSHIn) { s.CLIClientConflict = true }, Problem},
		KindSSHPrivilegedGrant: {func(s *SSHIn) {
			s.Privileged = []SSHGrantIn{{ID: "g", Group: "ssh_admins", HostGroup: "all", Why: "sudo"}}
		}, Info},
		KindSSHHostDrift: {func(s *SSHIn) {
			s.Hosts[0].Findings = []SSHHostFinding{{Kind: KindSSHHostDrift, Severity: "warning", Subject: "principals/alice", Detail: "fixed"}}
		}, Warning},
		KindSSHHostAccountConflict: {func(s *SSHIn) {
			s.Hosts[0].Findings = []SSHHostFinding{{Kind: KindSSHHostAccountConflict, Subject: "bob"}}
		}, Warning},
		KindSSHHostAccountMissing: {func(s *SSHIn) {
			s.Hosts[0].Findings = []SSHHostFinding{{Kind: KindSSHHostAccountMissing, Subject: "deploy"}}
		}, Warning},
		KindSSHHostAccountInvalid: {func(s *SSHIn) {
			s.Hosts[0].Findings = []SSHHostFinding{{Kind: KindSSHHostAccountInvalid, Subject: "1alice"}}
		}, Warning},
		KindSSHHostCeiling: {func(s *SSHIn) { s.Hosts[0].Findings = []SSHHostFinding{{Kind: KindSSHHostCeiling, Subject: "root"}} }, Warning},
		KindSSHHostAuthorizedKeys: {func(s *SSHIn) {
			s.Hosts[0].Findings = []SSHHostFinding{{Kind: KindSSHHostAuthorizedKeys, Subject: "deploy"}}
		}, Info},
		KindSSHBreakglassUsed: {func(s *SSHIn) {
			s.Hosts[0].Findings = []SSHHostFinding{{Kind: KindSSHBreakglassUsed, Subject: "breakglass"}}
		}, Warning},
		KindSSHHostCertExpiring:   {func(s *SSHIn) { s.Hosts[0].HostCertUntil = sshNow.Add(14 * 24 * time.Hour) }, Warning},
		KindSSHHostBundleTooLarge: {func(s *SSHIn) { s.Hosts[0].Oversize = true }, Problem},
		KindSSHBreakglassCert:     {func(s *SSHIn) { s.BreakglassImported = 2 }, Warning},
		KindSSHHostGroupUnused:    {func(s *SSHIn) { s.HostGroups = append(s.HostGroups, SSHHostGroupIn{ID: "db"}) }, Info},
		KindSSHUsernameCollision: {func(s *SSHIn) {
			s.Collisions = []SSHCollisionIn{{User: "deploy", Grant: "g", Reason: "the username is a shared account of a grant"}}
		}, Problem},
		KindSSHRevocationIncomplete: {func(s *SSHIn) { s.Incomplete = []string{"SHA256:abc"} }, Warning},
	} {
		in := quiet()
		tc.edit(in)
		got := runSSH(in)
		if len(got) != 1 || len(got[kind]) != 1 || got[kind][0] != tc.want {
			t.Errorf("%s: %v", kind, got)
		}
	}
}

func TestSSHHostStaleThresholds(t *testing.T) {
	for age, want := range map[time.Duration]Severity{14 * time.Minute: "", 16 * time.Minute: Warning, 23 * time.Hour: Warning, 25 * time.Hour: Problem} {
		in := quiet()
		in.Hosts[0].LastSync = sshNow.Add(-age)
		got := runSSH(in)[KindSSHHostStale]
		if (want == "" && len(got) != 0) || (want != "" && (len(got) != 1 || got[0] != want)) {
			t.Errorf("%s: %v, want %q", age, got, want)
		}
	}
	// Not enrolled yet: never stale.
	in := quiet()
	in.Hosts[0].Enrolled, in.Hosts[0].LastSync = false, time.Time{}
	if got := runSSH(in); len(got) != 0 {
		t.Errorf("unenrolled: %v", got)
	}
	// A drift Problem raises the drift finding's severity.
	in = quiet()
	in.Hosts[0].Findings = []SSHHostFinding{{Kind: KindSSHHostDrift, Severity: "problem", Subject: "trustedusercakeys", Detail: "/x"}}
	if got := runSSH(in)[KindSSHHostDrift]; len(got) != 1 || got[0] != Problem {
		t.Errorf("drift problem: %v", got)
	}
}

func TestSSHCertExpiring15DaysQuiet(t *testing.T) {
	in := quiet()
	in.Hosts[0].HostCertUntil = sshNow.Add(15 * 24 * time.Hour)
	if got := runSSH(in); len(got) != 0 {
		t.Errorf("15 days: %v", got)
	}
}
