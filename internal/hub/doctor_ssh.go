package hub

// The SSH access kinds' inputs (doctor.SSHIn). Never under mu across a
// network call: everything here is memory and local files.

import (
	"github.com/portcullis/hub/internal/doctor"
	"github.com/portcullis/hub/internal/sshaccess"
)

func (h *Hub) doctorSSHIn() *doctor.SSHIn {
	h.mu.RLock()
	st := h.st.SSH.Clone()
	h.mu.RUnlock()
	in := &doctor.SSHIn{Enabled: st.Settings.Enabled, CLIClientConflict: h.CLIClientConflict(), RoleProblems: map[string]string{}}
	h.sshrt.mu.Lock()
	in.CAProblems = append(in.CAProblems, h.sshrt.caProblems...)
	for hg, why := range h.sshrt.roleErr {
		in.RoleProblems[hg] = why
	}
	in.BreakglassImported = h.sshrt.breakglassImported
	c := h.sshrt.compiled
	h.sshrt.mu.Unlock()
	for fp := range h.sshRevocationsIncomplete() {
		in.Incomplete = append(in.Incomplete, fp)
	}
	for _, g := range st.Grants {
		if p, why := sshaccess.PrivilegedIn(st, g); p {
			in.Privileged = append(in.Privileged, doctor.SSHGrantIn{ID: g.ID, Group: g.Group, HostGroup: g.HostGroup, Why: why})
		}
	}
	h.sshhosts.mu.Lock()
	oversize := clone(h.sshhosts.oversize)
	h.sshhosts.mu.Unlock()
	for _, v := range h.SSHHosts() {
		if !v.Managed || v.Removed {
			continue
		}
		hi := doctor.SSHHostIn{ID: v.ID, Enrolled: v.Enrolled, Oversize: oversize[v.ID]}
		if v.LastSync != nil {
			hi.LastSync = *v.LastSync
		}
		if v.HostCertUntil != nil {
			hi.HostCertUntil = *v.HostCertUntil
		}
		for _, f := range v.Findings {
			hi.Findings = append(hi.Findings, doctor.SSHHostFinding{Kind: f.Kind, Severity: f.Severity, Subject: f.Subject, Detail: f.Detail})
		}
		in.Hosts = append(in.Hosts, hi)
	}
	for _, g := range h.SSHHostGroups() {
		in.HostGroups = append(in.HostGroups, doctor.SSHHostGroupIn{ID: g.ID, Grants: g.Grants, Hosts: len(g.Hosts) + len(g.Patterns)})
	}
	if c != nil {
		for _, col := range c.Collisions {
			in.Collisions = append(in.Collisions, doctor.SSHCollisionIn{User: col.User, Grant: col.Grant, Reason: col.Reason})
		}
	}
	return in
}
