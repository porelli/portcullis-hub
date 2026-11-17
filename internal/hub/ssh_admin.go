package hub

// SSH access's admin and people views and actions (contract §18,
// spec §9.11): settings, host groups, hosts, previews, certificates,
// host certificates, the people card, and the break-glass import.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/sshaccess"
	"github.com/portcullis/hub/internal/state"
)

// SSHSettingsView is Settings → SSH.
type SSHSettingsView struct {
	Enabled         bool     `json:"enabled"`
	DefaultTTLHours int      `json:"default_ttl_hours"`
	UserCAs         []string `json:"user_cas"`
	HostCAs         []string `json:"host_cas"`
	UserCAFP        string   `json:"user_ca_fp"`
	HostCAFP        string   `json:"host_ca_fp"`
	Problems        []string `json:"problems"`
	CLIClientReady  bool     `json:"cli_client_ready"`
}

// SSHSettings is the settings view.
func (h *Hub) SSHSettings() SSHSettingsView {
	h.mu.RLock()
	s := h.st.SSH.Settings
	h.mu.RUnlock()
	u, ho := h.SSHCAKeys()
	h.sshrt.mu.Lock()
	probs := nonNilStrings(slices.Clone(h.sshrt.caProblems))
	h.sshrt.mu.Unlock()
	v := SSHSettingsView{Enabled: s.Enabled, DefaultTTLHours: s.TTLHours(), UserCAs: u, HostCAs: ho, Problems: probs, CLIClientReady: h.CLIClientReady()}
	if len(u) > 0 {
		v.UserCAFP = caFP(u[0])
	}
	if len(ho) > 0 {
		v.HostCAFP = caFP(ho[0])
	}
	return v
}

// SetSSHSettings switches SSH access and sets the default lifetime (1–12
// h). Switching it on or raising the lifetime widens access: it needs a
// fresh sign-in under the hub template (p).
func (h *Hub) SetSSHSettings(ctx context.Context, actor directory.Actor, enabled bool, ttl int, p *freshauth.Proof) (err error) {
	defer func() {
		h.auditOp(actor, "ssh.settings", "ssh", fmt.Sprintf("enabled=%v default_ttl_hours=%d", enabled, ttl), err)
	}()
	if actor.Via == directory.ViaAI {
		return statusErr(http.StatusForbidden, "SSH settings can't be changed through an AI assistant")
	}
	if ttl < 1 || ttl > 12 {
		return statusErr(http.StatusBadRequest, "the default lifetime must be 1–12 hours")
	}
	h.mu.RLock()
	cur := h.st.SSH.Settings
	h.mu.RUnlock()
	if (enabled && !cur.Enabled) || ttl > cur.TTLHours() {
		if err := h.needFresh(ctx, actor, p); err != nil {
			return err
		}
	}
	h.mu.Lock()
	h.st.SSH.Settings = state.SSHSettings{Enabled: enabled, DefaultTTLHours: ttl}
	h.saveLocked()
	h.mu.Unlock()
	h.TriggerSSHCompile()
	return nil
}

// SSHHostGroupView is one host group.
type SSHHostGroupView struct {
	ID string `json:"id"`
	state.SSHHostGroup
	HostCerts    bool     `json:"host_certs"`
	Hosts        []string `json:"hosts"`
	Names        []string `json:"names"`
	Grants       int      `json:"grants"`
	Hints        []string `json:"hints"`
	TrustCommand string   `json:"trust_command"`
	Builtin      bool     `json:"builtin"`
}

// SSHHostGroups lists the host groups.
func (h *Hub) SSHHostGroups() []SSHHostGroupView {
	h.mu.RLock()
	st := h.st.SSH.Clone()
	h.mu.RUnlock()
	c := h.sshCompiled()
	userCAs, _ := h.SSHCAKeys()
	out := []SSHHostGroupView{}
	for _, id := range sshKeys(st.HostGroups) {
		g := st.HostGroups[id]
		v := SSHHostGroupView{ID: id, SSHHostGroup: g, HostCerts: g.HostCerts(), Hosts: []string{}, Names: []string{}, Hints: []string{}, Builtin: id == cliapi.BuiltinAllHostGroup}
		for _, hid := range sshKeys(st.Hosts) {
			if hst := st.Hosts[hid]; !hst.Removed && (slices.Contains(hst.HostGroups, id) || (id == cliapi.BuiltinAllHostGroup && hst.Managed)) {
				v.Hosts = append(v.Hosts, hid)
			}
		}
		for _, gr := range st.Grants {
			if gr.HostGroup == id {
				v.Grants++
			}
		}
		if c != nil {
			v.Names = nonNilStrings(slices.Clone(c.Hosts[id]))
			v.Hints = nonNilStrings(slices.Clone(c.Hints[id]))
		}
		v.TrustCommand = trustCommand(h.cfg.Domain, id, userCAs, v.Hints)
		out = append(out, v)
	}
	return out
}

func trustCommand(domain, hg string, userCAs, hints []string) string {
	if len(userCAs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("sudo portcullis host trust --domain " + domain + " --host-group " + hg + " \\\n     --ca-key '" + userCAs[0] + "'")
	for _, a := range hints {
		if acct, ok := strings.CutPrefix(a, cliapi.PrincipalPersonal+":"); ok {
			b.WriteString(" --person " + acct)
		} else if acct, ok := strings.CutPrefix(a, cliapi.PrincipalShared+":"); ok {
			b.WriteString(" --account " + acct)
		}
	}
	b.WriteString(" --revoked-keys")
	return b.String()
}

// sshTemplateUsable: some allowlisted method can meet tmpl (else a host
// group can't take it: 409).
func (h *Hub) sshTemplateUsable(tmpl string) bool {
	h.mu.RLock()
	_, rule, why := h.governingLocked(govTemplate(tmpl))
	on := h.st.SignIn.MethodsOn()
	h.mu.RUnlock()
	if why != "" {
		return false
	}
	acc, err := signin.FreshAccepted(rule, on)
	if err != nil {
		return false
	}
	for _, m := range strongFreshMethods {
		if acc[m] && on[m] {
			return true
		}
	}
	return false
}

// hostGroupAccessChanged: an edit that changes who can get in or how
// (everything but the label and description).
func hostGroupAccessChanged(before, after state.SSHHostGroup) bool {
	before.Label, before.Description, after.Label, after.Description = "", "", "", ""
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	return !bytes.Equal(a, b)
}

// needFresh: a fresh sign-in under the hub template (p nil = none given).
func (h *Hub) needFresh(ctx context.Context, actor directory.Actor, p *freshauth.Proof) error {
	if p == nil {
		return statusErr(http.StatusForbidden, freshauth.Message)
	}
	return h.checkAdminFresh(ctx, actor, *p)
}

// SaveHostGroup creates or updates host group id (administrators; never
// through the Portcullis MCP). An update that changes anything but the
// label and description changes access: it needs a fresh sign-in (p).
func (h *Hub) SaveHostGroup(ctx context.Context, actor directory.Actor, id string, g state.SSHHostGroup, create bool, p *freshauth.Proof) (err error) {
	action := "ssh.hostgroup.update"
	if create {
		action = "ssh.hostgroup.create"
	}
	defer func() {
		h.auditOp(actor, action, id, fmt.Sprintf("template=%s patterns=%s source=%s vpn_only=%v delegable=%v create_shared=%v host_certs=%v",
			g.GoverningTemplate(), strings.Join(g.Patterns, ","), strings.Join(g.SourceCIDRs, ","), g.VPNOnly, g.Delegable, g.CreateShared, g.HostCerts()), err)
	}()
	if actor.Via == directory.ViaAI {
		return statusErr(http.StatusForbidden, "host groups can't be changed through an AI assistant")
	}
	if !h.sshTemplateUsable(g.GoverningTemplate()) {
		return statusErr(http.StatusConflict, "template %s can't be met by any phishing-resistant method that is switched on (passkeys, security keys, YubiKey certificates): pick another", g.GoverningTemplate())
	}
	h.mu.RLock()
	before, had := h.st.SSH.HostGroups[id]
	h.mu.RUnlock()
	if had && !create && hostGroupAccessChanged(before, g) {
		if err := h.needFresh(ctx, actor, p); err != nil {
			return err
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, exists := h.st.SSH.HostGroups[id]
	switch {
	case create && exists:
		return statusErr(http.StatusConflict, "host group %s exists already", id)
	case !create && !exists:
		return statusErr(http.StatusNotFound, "no host group %s", id)
	}
	next := h.st.SSH.Clone()
	next.HostGroups[id] = g
	if err := sshaccess.Validate(next); err != nil {
		return statusErr(http.StatusBadRequest, "%v", err)
	}
	h.st.SSH.HostGroups = next.HostGroups
	h.saveLocked()
	h.goBackground(h.TriggerSSHCompile)
	return nil
}

// DeleteHostGroup deletes an unused host group (not all).
func (h *Hub) DeleteHostGroup(actor directory.Actor, id string) (err error) {
	defer func() { h.auditOp(actor, "ssh.hostgroup.delete", id, "", err) }()
	if id == cliapi.BuiltinAllHostGroup {
		return statusErr(http.StatusConflict, "all is built in")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.st.SSH.HostGroups[id]; !ok {
		return statusErr(http.StatusNotFound, "no host group %s", id)
	}
	for _, g := range h.st.SSH.Grants {
		if g.HostGroup == id {
			return statusErr(http.StatusConflict, "grant %s uses host group %s: delete it first", g.ID, id)
		}
	}
	for hid, hst := range h.st.SSH.Hosts {
		if slices.Contains(hst.HostGroups, id) && !hst.Removed {
			return statusErr(http.StatusConflict, "host %s is in host group %s: move it first", hid, id)
		}
	}
	delete(h.st.SSH.HostGroups, id)
	h.saveLocked()
	h.goBackground(h.TriggerSSHCompile)
	return nil
}

// SSHHostView is one host.
type SSHHostView struct {
	ID            string           `json:"id"`
	Names         []string         `json:"names"`
	Addrs         []string         `json:"addrs"`
	HostGroups    []string         `json:"host_groups"`
	Managed       bool             `json:"managed"`
	Enrolled      bool             `json:"enrolled"`
	Removed       bool             `json:"removed"`
	State         string           `json:"state"`
	KeyFP         string           `json:"key_fp,omitempty"`
	LastSync      *time.Time       `json:"last_sync,omitempty"`
	Serial        int64            `json:"serial"`
	Applied       int64            `json:"applied"`
	HostCertUntil *time.Time       `json:"host_cert_until,omitempty"`
	SSHDVersion   string           `json:"sshd_version,omitempty"`
	Findings      []cliapi.Finding `json:"findings"`
	Ceiling       *cliapi.Ceiling  `json:"ceiling,omitempty"`
	EnrolOpen     bool             `json:"enrol_open"`
}

// SSHHosts lists the hosts with their last report's findings.
func (h *Hub) SSHHosts() []SSHHostView {
	h.mu.RLock()
	st := h.st.SSH.Clone()
	h.mu.RUnlock()
	now := h.sshrt.clock()
	out := []SSHHostView{}
	for _, id := range sshKeys(st.Hosts) {
		hst := st.Hosts[id]
		v := SSHHostView{ID: id, Names: nonNilStrings(hst.Names), Addrs: nonNilStrings(hst.Addrs), HostGroups: nonNilStrings(hst.HostGroups), Managed: hst.Managed,
			Enrolled: hst.HostKey != "", Removed: hst.Removed, KeyFP: hst.KeyFP, Serial: hst.Serial, Findings: []cliapi.Finding{}, Ceiling: hst.Ceiling,
			EnrolOpen: hst.EnrolHash != "" && now.Before(hst.EnrolExpires)}
		if t := h.HostLastSync(id); !t.IsZero() {
			v.LastSync = &t
		}
		if !hst.HostCertUntil.IsZero() {
			u := hst.HostCertUntil
			v.HostCertUntil = &u
		}
		if rep, err := h.LastHostReport(id); err == nil {
			v.Findings = nonNilFindings(rep.Report.Findings)
			v.Applied, v.SSHDVersion = rep.Report.Serial, rep.Report.SSHDVersion
		}
		v.State = hostState(v, now)
		out = append(out, v)
	}
	return out
}

func nonNilFindings(f []cliapi.Finding) []cliapi.Finding {
	if f == nil {
		return []cliapi.Finding{}
	}
	return f
}

func hostState(v SSHHostView, now time.Time) string {
	switch {
	case v.Removed:
		return "removed"
	case !v.Managed:
		return "unmanaged"
	case !v.Enrolled:
		return "waiting for enrolment"
	case v.LastSync == nil || now.Sub(*v.LastSync) > 15*time.Minute:
		return "stale"
	}
	for _, f := range v.Findings {
		if f.Severity == cliapi.SeverityProblem {
			return "problem"
		}
	}
	return "ready"
}

// UpdateHost changes a host's names, addresses and host groups (Managed
// stays as it was). Any change of them changes access (who reaches the
// host, the names its certificate vouches for): an administrator, never
// through the Portcullis MCP, with a fresh sign-in (p). Unchanged values
// need none.
func (h *Hub) UpdateHost(ctx context.Context, actor directory.Actor, id string, in HostInput, p *freshauth.Proof) (err error) {
	defer func() {
		h.auditOp(actor, "ssh.host.update", id, fmt.Sprintf("names=%s addrs=%s groups=%s", strings.Join(in.Names, ","), strings.Join(in.Addrs, ","), strings.Join(in.HostGroups, ",")), err)
	}()
	if actor.Via == directory.ViaAI {
		return statusErr(http.StatusForbidden, "hosts can't be changed through an AI assistant")
	}
	h.mu.RLock()
	cur, ok := h.st.SSH.Hosts[id]
	h.mu.RUnlock()
	if ok && (!slices.Equal(dedupStrings(cur.HostGroups), dedupStrings(in.HostGroups)) || !slices.Equal(cur.Names, in.Names) || !slices.Equal(cur.Addrs, in.Addrs)) {
		if err := h.needFresh(ctx, actor, p); err != nil {
			return err
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	hst, ok := h.st.SSH.Hosts[id]
	if !ok || hst.Removed {
		return statusErr(http.StatusNotFound, "no host %s", id)
	}
	in.ID, in.Managed = id, hst.Managed
	if err := validHostInput(h.st.SSH, in); err != nil {
		return err
	}
	hst.Names, hst.Addrs, hst.HostGroups = in.Names, in.Addrs, dedupStrings(in.HostGroups)
	hst.HostCert, hst.HostCertFrom, hst.HostCertUntil = "", time.Time{}, time.Time{} // new names: a new certificate
	h.st.SSH.Hosts[id] = hst
	h.saveLocked()
	h.goBackground(h.TriggerSSHCompile)
	return nil
}

// RemoveSSHAccount asks managed host id to remove account name (its next
// bundle's remove list; the home is kept).
func (h *Hub) RemoveSSHAccount(actor directory.Actor, id, name string) (err error) {
	defer func() { h.auditOp(actor, "ssh.account.remove", id+"/"+clip(name, 64), "", err) }()
	if !cliapi.ValidAccount(name) {
		return statusErr(http.StatusBadRequest, "not an account name")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	hst, ok := h.st.SSH.Hosts[id]
	if !ok || !hst.Managed || hst.Removed {
		return statusErr(http.StatusNotFound, "no managed host %s", id)
	}
	if !slices.Contains(hst.RemoveAccounts, name) {
		hst.RemoveAccounts = append(hst.RemoveAccounts, name)
	}
	h.st.SSH.Hosts[id] = hst
	h.saveLocked()
	h.goBackground(h.TriggerSSHCompile)
	return nil
}

// SSHAccess is an access preview: kind host, hostgroup or person.
func (h *Hub) SSHAccess(kind, id string, rootOnly bool) ([]sshaccess.PreviewRow, error) {
	c := h.sshCompiled()
	if c == nil {
		return []sshaccess.PreviewRow{}, nil
	}
	h.mu.RLock()
	st := h.st.SSH
	_, hostOK := st.Hosts[id]
	_, hgOK := st.HostGroups[id]
	h.mu.RUnlock()
	switch kind {
	case "host":
		if !hostOK {
			return nil, statusErr(http.StatusNotFound, "no host %s", id)
		}
		return c.Preview(id, rootOnly), nil
	case "hostgroup":
		if !hgOK {
			return nil, statusErr(http.StatusNotFound, "no host group %s", id)
		}
		return c.PreviewHostGroup(id, rootOnly), nil
	case "person":
		rows := c.PreviewPerson(id)
		if rootOnly {
			rows = slices.DeleteFunc(rows, func(r sshaccess.PreviewRow) bool { return !r.Root && !r.Sudo })
		}
		return rows, nil
	}
	return nil, statusErr(http.StatusBadRequest, "unknown preview")
}

// SSHGrantView is one grant.
type SSHGrantView struct {
	state.SSHGrant
	Privileged bool   `json:"privileged"`
	Why        string `json:"why,omitempty"`
	TTL        int    `json:"effective_ttl_hours"`
}

// SSHGrants lists the grants (onlyDelegable: those on delegable groups).
func (h *Hub) SSHGrants(onlyDelegable bool) []SSHGrantView {
	h.mu.RLock()
	st := h.st.SSH.Clone()
	h.mu.RUnlock()
	out := []SSHGrantView{}
	for _, g := range st.Grants {
		if onlyDelegable && !st.HostGroups[g.HostGroup].Delegable {
			continue
		}
		p, why := sshaccess.Privileged(g)
		out = append(out, SSHGrantView{SSHGrant: g, Privileged: p, Why: why, TTL: sshaccess.GrantTTLHours(g, st.Settings)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SSHRevokedView is one revoked key, by fingerprint.
type SSHRevokedView struct {
	FP     string     `json:"fp"`
	Reason string     `json:"reason"`
	Actor  string     `json:"actor"`
	Added  time.Time  `json:"added"`
	Until  *time.Time `json:"until,omitempty"`
	NoKey  bool       `json:"no_key,omitempty"`
}

// SSHHostKeyView is one signed unmanaged host key.
type SSHHostKeyView struct {
	FP        string    `json:"fp"`
	HostGroup string    `json:"host_group"`
	Names     []string  `json:"names"`
	Until     time.Time `json:"until"`
	Revoked   bool      `json:"revoked"`
}

// SSHCertificatesView is Certificates.
type SSHCertificatesView struct {
	Issued     []IssuedRecord   `json:"issued"`
	Revoked    []SSHRevokedView `json:"revoked"`
	Incomplete []string         `json:"incomplete"`
	// HostKeys: the unmanaged hosts' signed keys (revocable by fingerprint).
	HostKeys []SSHHostKeyView `json:"host_keys"`
}

// SSHCertificates is the issued index (newest first; user "" = all) and
// the revoked list (fingerprints only).
func (h *Hub) SSHCertificates(user string) SSHCertificatesView {
	recs := h.IssuedFor(user)
	slices.Reverse(recs)
	v := SSHCertificatesView{Issued: recs, Revoked: []SSHRevokedView{}, Incomplete: []string{}, HostKeys: []SSHHostKeyView{}}
	l, _ := h.sshRevokedList()
	for _, e := range l {
		rv := SSHRevokedView{FP: e.FP, Reason: e.Reason, Actor: e.Actor, Added: e.Added, NoKey: e.Key == ""}
		if !e.Until.IsZero() {
			u := e.Until
			rv.Until = &u
		}
		v.Revoked = append(v.Revoked, rv)
	}
	for fp := range h.sshRevocationsIncomplete() {
		v.Incomplete = append(v.Incomplete, fp)
	}
	sort.Strings(v.Incomplete)
	h.mu.RLock()
	for fp, hk := range h.st.SSH.HostKeys {
		v.HostKeys = append(v.HostKeys, SSHHostKeyView{FP: fp, HostGroup: hk.HostGroup, Names: slices.Clone(hk.Names), Until: hk.Until, Revoked: hk.Revoked})
	}
	h.mu.RUnlock()
	sort.Slice(v.HostKeys, func(i, j int) bool { return v.HostKeys[i].FP < v.HostKeys[j].FP })
	return v
}

// RevokeSSHCertificates revokes keys by fingerprint (an admin's Revoke).
// RevokeSSHCertificatesOf is RevokeSSHCertificates for keys the caller
// named as user's (L-C1): every fingerprint must be a key a certificate
// was issued to user for, or nothing is revoked — the confirmation names
// user, so it can't revoke someone else's key.
func (h *Hub) RevokeSSHCertificatesOf(actor directory.Actor, user string, fps []string, reason string) (int, error) {
	own := map[string]bool{}
	for _, r := range h.IssuedFor(user) {
		own[r.KeyFP] = true
	}
	for _, fp := range fps {
		if !own[fp] {
			return 0, statusErr(http.StatusBadRequest, "%s isn't a key of %s", clip(fp, 80), user)
		}
	}
	return h.RevokeSSHCertificates(actor, fps, reason)
}

func (h *Hub) RevokeSSHCertificates(actor directory.Actor, fps []string, reason string) (int, error) {
	if len(fps) == 0 || len(fps) > 256 {
		return 0, statusErr(http.StatusBadRequest, "1–256 fingerprints")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "revoked by " + actor.User
	}
	// Unmanaged hosts' signed keys (M1) are revoked here: clients get them
	// as @revoked lines at their next login.
	var userFPs []string
	n := 0
	h.mu.Lock()
	for _, fp := range fps {
		hk, ok := h.st.SSH.HostKeys[fp]
		if !ok {
			userFPs = append(userFPs, fp)
			continue
		}
		if !hk.Revoked {
			hk.Revoked = true
			h.st.SSH.HostKeys[fp] = hk
			if h.st.SSH.RevokedHostKeys == nil {
				h.st.SSH.RevokedHostKeys = map[string]string{}
			}
			h.st.SSH.RevokedHostKeys[fp] = hk.Key
			n++
		}
	}
	if n > 0 {
		h.saveLocked()
	}
	h.mu.Unlock()
	for _, fp := range fps {
		if !slices.Contains(userFPs, fp) {
			h.auditSSH(actor.User, "ssh.host_certificate.revoke", "-", "key "+fp+": "+clip(reason, 200), nil)
		}
	}
	if len(userFPs) == 0 {
		return n, nil
	}
	target := "-"
	if recs := h.issuedByFP(userFPs[0]); len(recs) > 0 {
		target = recs[0].User
	}
	m, err := h.RevokeFingerprints(actor.User, reason, userFPs, target)
	return n + m, err
}

// RevokeAllSSH revokes every unexpired certificate's key of user.
func (h *Hub) RevokeAllSSH(actor directory.Actor, user, reason string) (int, error) {
	now := h.sshrt.clock()
	seen := map[string]bool{}
	var fps []string
	for _, r := range h.IssuedFor(user) {
		if r.ValidBefore.After(now) && !seen[r.KeyFP] {
			seen[r.KeyFP] = true
			fps = append(fps, r.KeyFP)
		}
	}
	if len(fps) == 0 {
		return 0, nil
	}
	return h.RevokeFingerprints(actor.User, reason, fps, user)
}

// HostKeyRequest is Sign a host key / host certify.
type HostKeyRequest struct {
	HostGroup string   `json:"host_group"`
	PublicKey string   `json:"public_key"`
	Names     []string `json:"names"`
}

// hostCertMethods are the only methods that may sign a host key (C31).
var hostCertMethods = []string{string(signin.SecurityKey), string(signin.YubiKeyCert)}

// SignHostKey signs an unmanaged host's key (the Hub page): an
// administrator with a fresh security_key / yubikey_cert sign-in.
func (h *Hub) SignHostKey(ctx context.Context, actor directory.Actor, req HostKeyRequest, p freshauth.Proof) (*cliapi.HostCertAnswer, error) {
	if actor.Via == directory.ViaAI {
		return nil, statusErr(http.StatusForbidden, "host keys are never signed through an AI assistant")
	}
	res, _, err := h.checkFreshAuthOn(ctx, ListenerHub, govCore("hub"), p, actor.User)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(hostCertMethods, res.Result.Method) {
		return nil, statusErr(http.StatusForbidden, "signing a host key needs a security key or a YubiKey certificate sign-in")
	}
	return h.signHostKey(ctx, actor.User, req)
}

// SignHostKeyCLI is POST ssh/host-certificates (plan C31).
func (h *Hub) SignHostKeyCLI(ctx context.Context, req cliapi.HostCertRequest, addr string) (*cliapi.HostCertAnswer, error) {
	const action = "ssh.host_certificate.issue"
	if !h.SSHEnabled() {
		return nil, refusal(http.StatusConflict, TextSSHOff, "ssh access off")
	}
	vc, err := h.verifyCLIProof(ctx, freshauth.Proof{Code: req.Code, CodeVerifier: req.CodeVerifier, Nonce: req.Nonce, RedirectURI: req.RedirectURI}, addr, action)
	if err != nil {
		return nil, err
	}
	h.mu.RLock()
	people := h.people
	h.mu.RUnlock()
	if people == nil {
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "no directory")
	}
	m, err := people.Membership(ctx, h.sshrt.clock())
	if err != nil {
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "directory unreadable")
	}
	if _, admin := m.Users[vc.user]["lldap_admin"]; !admin {
		r := refusal(http.StatusForbidden, "only administrators can sign host keys", "not an administrator")
		h.auditSSH(vc.user, action, req.HostGroup, "addr="+clip(addr, 64), r)
		return nil, r
	}
	if !slices.Contains(hostCertMethods, vc.res.Method) {
		r := refusal(http.StatusForbidden, "signing a host key needs a security key or a YubiKey certificate sign-in: use --method security_key", "method "+vc.res.Method)
		h.auditSSH(vc.user, action, req.HostGroup, "addr="+clip(addr, 64), r)
		return nil, r
	}
	return h.signHostKey(ctx, vc.user, HostKeyRequest{HostGroup: req.HostGroup, PublicKey: req.PublicKey, Names: req.Names})
}

func (h *Hub) signHostKey(ctx context.Context, actor string, req HostKeyRequest) (ans *cliapi.HostCertAnswer, err error) {
	fp := "-"
	defer func() {
		h.auditSSH(actor, "ssh.host_certificate.issue", req.HostGroup, "key "+fp+" names="+clip(strings.Join(req.Names, ","), 400), err)
	}()
	key, norm, perr := cliapi.ParseAuthorizedKey(req.PublicKey)
	if perr != nil || key.Type() != "ssh-ed25519" {
		return nil, refusal(http.StatusBadRequest, "the host key must be an ed25519 public key", "bad host key")
	}
	fp = cliapi.Fingerprint(key)
	if len(req.Names) == 0 || len(req.Names) > 32 {
		return nil, refusal(http.StatusBadRequest, "1–32 names", "names count")
	}
	h.mu.RLock()
	st := h.st.SSH.Clone()
	h.mu.RUnlock()
	g, ok := st.HostGroups[req.HostGroup]
	if !ok {
		return nil, refusal(http.StatusNotFound, "no such host group", "unknown host group")
	}
	for _, n := range req.Names {
		if !cliapi.ValidHostName(n) || !hostNameAllowed(st, req.HostGroup, g, n) {
			return nil, refusal(http.StatusConflict, fmt.Sprintf("%s matches none of host group %s's patterns or hosts", clip(n, 64), req.HostGroup), "name outside the group")
		}
	}
	if _, revoked := st.RevokedHostKeys[fp]; revoked {
		return nil, refusal(http.StatusConflict, "this host key was revoked: make the host a new key (ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key)", "a revoked host key")
	}
	acts := h.sshActions()
	if acts == nil {
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "enroll not connected")
	}
	signed, serr := acts.SignSSHHost(ctx, invite.SSHHostSign{PublicKey: norm, Principals: req.Names, HostGroup: req.HostGroup, HostID: "unmanaged"})
	if serr != nil {
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "enroll refused")
	}
	// Recorded so it can be revoked (M1): clients get @revoked lines.
	now := h.sshrt.clock()
	h.mu.Lock()
	if h.st.SSH.HostKeys == nil {
		h.st.SSH.HostKeys = map[string]state.SSHHostKey{}
	}
	for k, v := range h.st.SSH.HostKeys {
		if !v.Until.After(now) {
			delete(h.st.SSH.HostKeys, k)
		}
	}
	_, wasRevoked := h.st.SSH.RevokedHostKeys[fp]
	h.st.SSH.HostKeys[fp] = state.SSHHostKey{Key: norm, HostGroup: req.HostGroup, Names: slices.Clone(req.Names), Until: signed.ValidBefore.UTC(), Revoked: wasRevoked}
	h.saveLocked()
	h.mu.Unlock()
	return &cliapi.HostCertAnswer{Certificate: signed.Certificate, ValidBefore: signed.ValidBefore.UTC()}, nil
}

// hostNameAllowed: name may go in an unmanaged host key's certificate
// for host group id (L-A1): never a managed host's name or address (it
// has its own host certificate, from its own key); a negated pattern
// matching it refuses it (as ssh reads the list); else a pattern matches
// it, or it's an unmanaged host's name or address in that group.
func hostNameAllowed(st state.SSHState, id string, g state.SSHHostGroup, name string) bool {
	low := strings.ToLower(name)
	for _, hst := range st.Hosts {
		if !hst.Removed && hst.Managed && (slices.ContainsFunc(hst.Names, func(n string) bool { return strings.EqualFold(n, name) }) || slices.Contains(hst.Addrs, name)) {
			return false
		}
	}
	match := func(p string) bool {
		p = strings.ToLower(p)
		ok, _ := path.Match(p, low)
		return ok && !strings.Contains(strings.TrimPrefix(low, strings.TrimSuffix(p, "*")), "/")
	}
	for _, p := range g.Patterns {
		if strings.HasPrefix(p, "!") && match(strings.TrimPrefix(p, "!")) {
			return false
		}
	}
	for _, p := range g.Patterns {
		if !strings.HasPrefix(p, "!") && match(p) {
			return true
		}
	}
	for _, hst := range st.Hosts {
		if !hst.Removed && !hst.Managed && slices.Contains(hst.HostGroups, id) {
			if slices.ContainsFunc(hst.Names, func(n string) bool { return strings.EqualFold(n, name) }) || slices.Contains(hst.Addrs, name) {
				return true
			}
		}
	}
	return false
}

// PersonSSHGroup is one host group on a person's card.
type PersonSSHGroup struct {
	ID       string    `json:"id"`
	Label    string    `json:"label"`
	Accounts []string  `json:"accounts"`
	Sudo     bool      `json:"sudo"`
	Hosts    []string  `json:"hosts"`
	Until    time.Time `json:"until"`
}

// PersonSSH is the person's SSH access card (spec §9.11).
type PersonSSH struct {
	Enabled      bool             `json:"enabled"`
	User         string           `json:"user"`
	HostGroups   []PersonSSHGroup `json:"host_groups"`
	Certificates []IssuedRecord   `json:"certificates"`
	Commands     []string         `json:"commands"`
	Download     string           `json:"download"`
}

// PersonSSHAccess is user's card.
func (h *Hub) PersonSSHAccess(user string) PersonSSH {
	out := PersonSSH{Enabled: h.SSHEnabled(), User: user, HostGroups: []PersonSSHGroup{}, Certificates: []IssuedRecord{},
		Commands: []string{"portcullis login " + h.cfg.Domain, "portcullis ssh-config --install"},
		Download: "https://github.com/porelli/portcullis-hub/releases"}
	c := h.sshCompiled()
	if c == nil {
		return out
	}
	h.mu.RLock()
	hgs := h.st.SSH.Clone().HostGroups
	h.mu.RUnlock()
	for _, hg := range sshaccess.SortedHostGroups(c.People[user].HostGroups) {
		p := c.People[user].HostGroups[hg]
		v := PersonSSHGroup{ID: hg, Label: hgs[hg].Label, Hosts: nonNilStrings(slices.Clone(c.Hosts[hg])), Until: p.Until, Accounts: []string{}}
		for _, pr := range p.Principals {
			if _, acct, _, ok := cliapi.ParsePrincipal(pr); ok {
				v.Accounts = append(v.Accounts, acct)
			}
		}
		for _, r := range c.PreviewHostGroup(hg, false) {
			if r.Person == user && r.Sudo {
				v.Sudo = true
			}
		}
		out.HostGroups = append(out.HostGroups, v)
	}
	now := h.sshrt.clock()
	for _, r := range h.IssuedFor(user) {
		if r.ValidBefore.After(now) {
			out.Certificates = append(out.Certificates, r)
		}
	}
	return out
}

// ── break-glass import (contract §18.13) ──

// BreakglassRecord is one line of secrets/ssh/breakglass.jsonl.
type BreakglassRecord struct {
	Time        time.Time `json:"time"`
	User        string    `json:"user"`
	HostGroup   string    `json:"host_group"`
	Principals  []string  `json:"principals"`
	KeyFP       string    `json:"key_fp"`
	Serial      string    `json:"serial"`
	ValidBefore time.Time `json:"valid_before"`
	Note        string    `json:"note"`
}

func (h *Hub) breakglassImportedPath() string {
	return filepath.Join(h.sshDir(), "breakglass-imported.json")
}

// ImportBreakglass appends each new line of the break-glass record to the
// audit (ssh.certificate.breakglass) once, by serial; malformed lines are
// skipped and counted. Run at Init (the file is read-only to the Hub).
func (h *Hub) ImportBreakglass() (imported, malformed int) {
	p := h.cfg.SSHBreakglassFile
	if p == "" {
		return 0, 0
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("ssh: break-glass record unreadable: %v", err)
		}
		return 0, 0
	}
	done := map[string]bool{}
	if b, err := os.ReadFile(h.breakglassImportedPath()); err == nil {
		var l []string
		if json.Unmarshal(b, &l) == nil {
			for _, s := range l {
				done[s] = true
			}
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r BreakglassRecord
		if cliapi.UnmarshalStrict(line, &r) != nil || r.Serial == "" || !reportStringOK(r.Serial) || !reportStringOK(r.User) ||
			!reportStringOK(r.HostGroup) || !reportStringOK(r.KeyFP) || !reportStringOK(r.Note) {
			malformed++
			continue
		}
		if done[r.Serial] {
			continue
		}
		done[r.Serial] = true
		imported++
		h.auditSSH("-", "ssh.certificate.breakglass", clip(r.User, 64), fmt.Sprintf("%s: principals=%s key %s serial=%s until=%s note=%s",
			r.HostGroup, clip(strings.Join(r.Principals, ","), 200), r.KeyFP, r.Serial, r.ValidBefore.UTC().Format(time.RFC3339), clip(r.Note, 128)), nil)
	}
	h.sshrt.mu.Lock()
	h.sshrt.breakglassImported += imported
	h.sshrt.breakglassMalformed += malformed
	h.sshrt.mu.Unlock()
	l := make([]string, 0, len(done))
	for s := range done {
		l = append(l, s)
	}
	sort.Strings(l)
	b, _ := json.Marshal(l)
	if err := os.MkdirAll(h.sshDir(), 0o700); err == nil {
		_ = writeFile0600(h.breakglassImportedPath(), b)
	}
	return imported, malformed
}

// HostSSHHost is one managed host in `hub ssh status`.
type HostSSHHost struct {
	ID       string     `json:"id"`
	State    string     `json:"state"`
	LastSync *time.Time `json:"last_sync"`
	// SyncAgeSeconds: seconds since the last sync (-1: never).
	SyncAgeSeconds int64 `json:"sync_age_s"`
	Findings       int   `json:"findings"`
}

// HostSSHStatus is `hub ssh status` (the host control socket): on/off,
// the CA fingerprints, enroll's §18.7 problems and the managed hosts.
type HostSSHStatus struct {
	Enabled        bool          `json:"enabled"`
	UserCAFP       string        `json:"user_ca_fp"`
	HostCAFP       string        `json:"host_ca_fp"`
	Problems       []string      `json:"problems"`
	CLIClientReady bool          `json:"cli_client_ready"`
	Hosts          []HostSSHHost `json:"hosts"`
}

// HostSSHStatus answers the SSH block of ./portcullis status.
func (h *Hub) HostSSHStatus() HostSSHStatus {
	s := h.SSHSettings()
	out := HostSSHStatus{Enabled: s.Enabled, UserCAFP: s.UserCAFP, HostCAFP: s.HostCAFP, Problems: s.Problems, CLIClientReady: s.CLIClientReady, Hosts: []HostSSHHost{}}
	if out.Problems == nil {
		out.Problems = []string{}
	}
	now := h.sshrt.clock()
	for _, v := range h.SSHHosts() {
		if !v.Managed || v.Removed {
			continue
		}
		age := int64(-1)
		if v.LastSync != nil && !v.LastSync.IsZero() {
			age = int64(now.Sub(*v.LastSync) / time.Second)
		}
		out.Hosts = append(out.Hosts, HostSSHHost{ID: v.ID, State: v.State, LastSync: v.LastSync, SyncAgeSeconds: age, Findings: len(v.Findings)})
	}
	return out
}
