package hub

// Signing a person's SSH certificates (contract §18.5): the ten steps,
// fail closed at every one. Nothing a request carries — code, verifier,
// nonce, key proof, the key itself — reaches a log, an error or the audit;
// the audit holds fingerprints.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/sshaccess"
	"github.com/portcullis/hub/internal/state"
)

// The fixed texts (contract §18.5).
const (
	TextFreshRequired  = freshauth.Message
	TextImpersonated   = "a session as someone else can't get SSH certificates"
	TextSSHOff         = "SSH access is off on this server"
	TextSSHUnavailable = "SSH certificates can't be issued right now"
	TextCLIUnavailable = "SSH sign-in isn't available right now"
	TextTooMany        = "too many attempts: wait a minute and try again"
	TextKeyType        = "this key type can't be certified: use an ed25519 or ECDSA P-256 key (a FIDO sk- key works too)"
	TextKeyRevoked     = "this key is revoked: use another key"
	TextProtectedName  = "this account can't get SSH certificates"
	TextNotInDirectory = "this account isn't in the directory"
	TextDisabled       = "this account is disabled"
	TextNotAvailable   = "not available to you"
	TextTooManyCerts   = "at most 16 certificates per sign-in"
	TextEndsTooSoon    = "your access ends in less than 5 minutes"
	TextTemplateUnmeet = "can't be signed with any sign-in method that is switched on"
	flowLoopback       = "loopback"
)

// SSHUserLookup is Keycloak's user list (keycloak.Client.ListedUser): a
// disabled account gets nothing.
type SSHUserLookup interface {
	ListedUser(ctx context.Context, username string) (*keycloak.UserStatus, error)
}

// SetSSHKeycloak wires the Keycloak user lookup (nil: every signing 503).
func (h *Hub) SetSSHKeycloak(k SSHUserLookup) {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	h.sshrt.kc = k
}

// sshRefusal is a refused request: status, the fixed text answered, the
// reason for the audit (never an input).
type sshRefusal struct {
	status int
	text   string
	reason string
}

func (r *sshRefusal) Error() string { return r.text }

// Status is the HTTP status.
func (r *sshRefusal) Status() int { return r.status }

func refusal(status int, text, reason string) *sshRefusal {
	return &sshRefusal{status: status, text: text, reason: reason}
}

// verifiedCLI is a proof the CLI verifier accepted.
type verifiedCLI struct {
	res  *freshauth.Result
	user string
}

// verifyCLIProof runs steps 1–3: the code exchange and every freshauth
// check for portcullis-cli, impersonation refused, a valid username. addr
// is limited first.
func (h *Hub) verifyCLIProof(ctx context.Context, p freshauth.Proof, addr, action string) (*verifiedCLI, error) {
	now := h.sshrt.clock()
	if h.sshlim.addrBlocked(addr, now) {
		return nil, refusal(http.StatusTooManyRequests, TextTooMany, "too many refusals from this address")
	}
	v := h.cliVerifier()
	if v == nil {
		return nil, refusal(http.StatusServiceUnavailable, TextCLIUnavailable, "the portcullis-cli client isn't in place")
	}
	res, err := v.VerifyAnyUser(ctx, p)
	if err != nil {
		var fe *freshauth.Error
		reason := "proof refused"
		if errors.As(err, &fe) {
			reason = fe.Reason
			if fe.Reason == freshauth.ReasonUnreachable {
				return nil, refusal(http.StatusServiceUnavailable, TextCLIUnavailable, reason)
			}
		}
		h.sshlim.refused(addr, "", now)
		h.auditSSH("-", action, "-", "addr="+clip(addr, 64), refusal(http.StatusForbidden, TextFreshRequired, reason))
		return nil, refusal(http.StatusForbidden, TextFreshRequired, reason)
	}
	user := res.User
	if h.sshlim.userBlocked(user, now) {
		return nil, refusal(http.StatusTooManyRequests, TextTooMany, "too many refusals for this person")
	}
	if res.Impersonated {
		h.sshlim.refused(addr, user, now)
		r := refusal(http.StatusForbidden, TextImpersonated, "impersonated session")
		h.auditSSH(user, action, user, "addr="+clip(addr, 64), r)
		return nil, r
	}
	if !cliapi.ValidUsername(user) || invite.ProtectedName(user) {
		h.sshlim.refused(addr, user, now)
		r := refusal(http.StatusConflict, TextProtectedName, "protected or invalid username")
		h.auditSSH(clip(user, 64), action, clip(user, 64), "addr="+clip(addr, 64), r)
		return nil, r
	}
	return &verifiedCLI{res: res, user: user}, nil
}

// SignSSH is POST ssh/certificates (contract §18.5).
func (h *Hub) SignSSH(ctx context.Context, req cliapi.CertRequest, addr string) (*cliapi.CertAnswer, error) {
	const action = "ssh.certificate.issue"
	if !h.SSHEnabled() {
		return nil, refusal(http.StatusConflict, TextSSHOff, "ssh access off")
	}
	vc, err := h.verifyCLIProof(ctx, freshauth.Proof{Code: req.Code, CodeVerifier: req.CodeVerifier, Nonce: req.Nonce, RedirectURI: req.RedirectURI}, addr, action)
	if err != nil {
		return nil, err
	}
	user, now := vc.user, h.sshrt.clock()
	fail := func(r *sshRefusal) error {
		h.sshlim.refused(addr, user, now)
		h.auditSSH(user, action, user, "addr="+clip(addr, 64), r)
		return r
	}
	// Step 4: the key and its proof.
	pub, norm, perr := cliapi.ParseAuthorizedKey(req.PublicKey)
	if perr != nil || !cliapi.AcceptedKeyType(pub.Type(), cliapi.SKKeysAccepted) {
		return nil, fail(refusal(http.StatusBadRequest, TextKeyType, "key type refused"))
	}
	fp := cliapi.Fingerprint(pub)
	sig, serr := sshsig.Unarmor([]byte(req.KeyProof))
	if serr != nil || sshsig.Verify(bytes.NewReader(cliapi.KeyProofMessage(h.cfg.Domain, req.Nonce, req.Code, norm)), sig, pub, sshsig.HashSHA512, cliapi.NSKeyProof) != nil {
		return nil, fail(refusal(http.StatusForbidden, TextFreshRequired, "key proof"))
	}
	// Step 5: revoked keys.
	revoked, rerr := h.sshRevokedList()
	if rerr != nil {
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "revoked keys unreadable")
	}
	for _, r := range revoked {
		if r.FP == fp {
			return nil, fail(refusal(http.StatusForbidden, TextKeyRevoked, "revoked key "+fp))
		}
	}
	// Step 6: the mapping, on a fresh directory snapshot (plan C41).
	c, st, ferr := h.sshFreshCompile(ctx, user, now)
	if ferr != nil {
		var r *sshRefusal
		if errors.As(ferr, &r) {
			return nil, fail(r)
		}
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "compile failed")
	}
	plans := c.People[user].HostGroups
	ans := &cliapi.CertAnswer{User: user, Certificates: []cliapi.IssuedCert{}, Refused: []cliapi.Refusal{}, HostCAs: h.sshHostCAs(), RevokedHostKeys: revokedHostKeys(st)}
	want := sshaccess.SortedHostGroups(plans)
	if len(req.HostGroups) > 0 {
		want = nil
		seen := map[string]bool{}
		for _, hg := range req.HostGroups {
			if seen[hg] {
				continue
			}
			seen[hg] = true
			if _, ok := plans[hg]; ok && cliapi.ValidHostGroupID(hg) {
				want = append(want, hg)
			} else if cliapi.ValidHostGroupID(hg) {
				ans.Refused = append(ans.Refused, cliapi.Refusal{HostGroup: hg, Reason: TextNotAvailable})
			}
		}
		slices.Sort(want)
	}
	// Strength (§18.5): the host group's template and strongFreshMethods.
	var issue []string
	for _, hg := range want {
		if text := h.sshStrengthRefusal(st, hg, vc.res); text != "" {
			ans.Refused = append(ans.Refused, cliapi.Refusal{HostGroup: hg, Reason: text})
			h.auditSSH(user, action, user, hg+": method="+vc.res.Method+" addr="+clip(addr, 64), refusal(http.StatusForbidden, text, "template not met"))
			continue
		}
		if !plans[hg].Until.After(now.Add(cliapi.MinCertSeconds * time.Second)) {
			ans.Refused = append(ans.Refused, cliapi.Refusal{HostGroup: hg, Reason: TextEndsTooSoon})
			continue
		}
		if len(issue) == cliapi.MaxCertsPerLogin {
			ans.Refused = append(ans.Refused, cliapi.Refusal{HostGroup: hg, Reason: TextTooManyCerts})
			continue
		}
		issue = append(issue, hg)
	}
	if len(issue) == 0 {
		h.sshlim.refused(addr, user, now)
		return ans, nil // signed in, nothing issued (exit 3)
	}
	if !h.sshlim.signing(user, now) {
		return nil, refusal(http.StatusTooManyRequests, TextTooMany, "too many signings")
	}
	// Step 7: every role current before anything is signed.
	acts := h.sshActions()
	if acts == nil {
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "enroll not connected")
	}
	for _, hg := range issue {
		if err := h.putRole(ctx, acts, hg, c.Roles[hg]); err != nil {
			log.Printf("ssh: role hg-%s isn't current: %v", hg, err)
			r := refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "role hg-"+hg+" can't be made current")
			h.auditSSH(user, action, user, hg+": addr="+clip(addr, 64), r)
			return nil, r
		}
	}
	// The key is recorded before anything is signed (fail closed): a
	// certificate whose key the Hub can't put on the revoked list later
	// (revocation on leave) is never issued.
	if err := h.rememberKey(fp, norm, now); err != nil {
		log.Printf("ssh: recording the key to sign failed: %v", err)
		r := refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "the key couldn't be recorded")
		h.auditSSH(user, action, user, "key="+pub.Type()+" "+fp+" addr="+clip(addr, 64), r)
		return nil, r
	}
	// Step 8: enroll signs; every answer is checked before it's handed out.
	userCAs := h.sshUserCAs()
	var recs []IssuedRecord
	var issuedAudit []string
	for _, hg := range issue {
		p := plans[hg]
		secs := int(p.Until.Sub(now) / time.Second)
		secs = min(secs, cliapi.MaxCertSeconds)
		reqID := make([]byte, 8)
		_, _ = rand.Read(reqID)
		keyID := cliapi.KeyID(user, hg, hex.EncodeToString(reqID))
		signed, err := acts.SignSSHUser(ctx, invite.SSHUserSign{User: user, HostGroup: hg, PublicKey: norm, Principals: p.Principals, ValidSeconds: secs, Extensions: p.Extensions, KeyID: keyID})
		if err != nil {
			log.Printf("ssh: signing %s for %s failed: %v", hg, user, err)
			r := refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "enroll refused or failed")
			h.auditSSH(user, action, user, hg+": key="+pub.Type()+" "+fp+" addr="+clip(addr, 64), r)
			return nil, r
		}
		if err := checkIssuedCert(signed.Certificate, pub, p.Principals, keyID, p.Until, userCAs); err != nil {
			log.Printf("ssh: enroll's certificate for %s/%s fails the check: %v", user, hg, err)
			r := refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "issued certificate fails the check")
			h.auditSSH(user, action, user, hg+": key="+pub.Type()+" "+fp, r)
			return nil, r
		}
		ans.Certificates = append(ans.Certificates, cliapi.IssuedCert{HostGroup: hg, Certificate: signed.Certificate, Principals: p.Principals,
			Serial: signed.Serial, ValidBefore: signed.ValidBefore.UTC(), Hosts: nonNilStrings(c.Hosts[hg])})
		// Step 9: the issued index, then the audit.
		issuedAudit = append(issuedAudit, fmt.Sprintf("%s: principals=%s key=%s %s serial=%s until=%s flow=%s method=%s addr=%s",
			hg, strings.Join(p.Principals, ","), pub.Type(), fp, signed.Serial, signed.ValidBefore.UTC().Format(time.RFC3339), flowLoopback, vc.res.Method, clip(addr, 64)))
		recs = append(recs, IssuedRecord{Time: now.UTC(), User: user, HostGroup: hg, Serial: signed.Serial, KeyFP: fp, Principals: p.Principals,
			ValidBefore: signed.ValidBefore.UTC(), Flow: flowLoopback, Addr: clip(addr, 64), Own: req.OwnKey})
	}
	// RR-M3: a certificate the index doesn't hold could never be revoked
	// on leave: nothing is issued (the signed certificates never leave).
	if err := h.appendIssued(recs, now); err != nil {
		log.Printf("ssh: issued index: %v", err)
		r := refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "the issued index can't be written")
		for _, d := range issuedAudit {
			h.auditSSH(user, action, user, d, r)
		}
		return nil, r
	}
	for _, d := range issuedAudit {
		h.auditSSH(user, action, user, d, nil)
	}
	return ans, nil
}

// checkIssuedCert: enroll's answer is a user certificate for exactly this
// key, principals and key id, from a known user CA, valid no longer than
// planned (one minute of slack for the clocks).
func checkIssuedCert(line string, pub ssh.PublicKey, principals []string, keyID string, until time.Time, userCAs []string) error {
	k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(bytes.TrimSpace(rest)) > 0 {
		return errors.New("not a certificate line")
	}
	cert, ok := k.(*ssh.Certificate)
	switch {
	case !ok:
		return errors.New("not a certificate")
	case cert.CertType != ssh.UserCert:
		return errors.New("not a user certificate")
	case !bytes.Equal(cert.Key.Marshal(), pub.Marshal()):
		return errors.New("for another key")
	case cert.KeyId != keyID:
		return errors.New("another key id")
	case !slices.Equal(cert.ValidPrincipals, principals):
		return errors.New("other principals")
	case time.Unix(int64(cert.ValidBefore), 0).After(until.Add(time.Minute)):
		return errors.New("valid longer than planned")
	case len(cert.CriticalOptions) > 0 && cert.CriticalOptions["source-address"] == "":
		return errors.New("an unexpected critical option")
	}
	for k := range cert.Extensions {
		if k != cliapi.ExtPTY && k != cliapi.ExtPortForwarding && k != cliapi.ExtAgentForwarding {
			return errors.New("an extension outside the four")
		}
	}
	ca := cliapi.NormalAuthorizedKey(cert.SignatureKey)
	for _, u := range userCAs {
		if _, n, err := cliapi.ParseAuthorizedKey(u); err == nil && n == ca {
			return nil
		}
	}
	return errors.New("signed by an unknown CA")
}

// sshFreshCompile compiles with one fresh directory snapshot and checks
// the person is in it and enabled in Keycloak (steps 6, plan C41).
func (h *Hub) sshFreshCompile(ctx context.Context, user string, now time.Time) (*sshaccess.Compiled, state.SSHState, error) {
	h.mu.RLock()
	st := h.st.SSH.Clone()
	people := h.people
	h.mu.RUnlock()
	h.sshrt.mu.Lock()
	kc := h.sshrt.kc
	h.sshrt.mu.Unlock()
	if people == nil || kc == nil {
		return nil, st, errors.New("the directory or Keycloak isn't connected")
	}
	m, err := people.Membership(ctx, now)
	if err != nil {
		return nil, st, err
	}
	if _, ok := m.Users[user]; !ok {
		return nil, st, refusal(http.StatusConflict, TextNotInDirectory, "not in LLDAP")
	}
	us, err := kc.ListedUser(ctx, user)
	if err != nil {
		return nil, st, err
	}
	if us == nil || !us.Enabled {
		return nil, st, refusal(http.StatusConflict, TextDisabled, "disabled or unknown in Keycloak")
	}
	c, err := sshaccess.Compile(h.sshInput(st, m, now))
	return c, st, err
}

// sshInput is the compile input for st and m.
func (h *Hub) sshInput(st state.SSHState, m *directory.Membership, now time.Time) sshaccess.Input {
	return sshaccess.Input{State: st, Members: m.Users, Pending: m.Pending, Expired: m.Expired, Now: now,
		VPNRanges: h.vpnAllowRanges, UserCAs: h.sshUserCAs(), RevokedKeys: h.RevokedKeys()}
}

// sshStrengthRefusal is "" when the proof's method may sign hg, else the
// refused entry's text naming the method to use.
func (h *Hub) sshStrengthRefusal(st state.SSHState, hg string, res *freshauth.Result) string {
	tmpl := st.HostGroups[hg].GoverningTemplate()
	if strongFresh(signin.Method(res.Method)) {
		if _, _, err := h.freshMethodAccepted(govTemplate(tmpl), res); err == nil {
			return ""
		}
	}
	h.mu.RLock()
	_, rule, why := h.governingLocked(govTemplate(tmpl))
	on := h.st.SignIn.MethodsOn()
	h.mu.RUnlock()
	if why == "" {
		if acc, err := signin.FreshAccepted(rule, on); err == nil {
			for _, m := range strongFreshMethods {
				if acc[m] && on[m] {
					info, _ := signin.InfoOf(m)
					return fmt.Sprintf("%s needs %s: sign in with --method %s", hg, info.Phrase, m)
				}
			}
		}
	}
	return hg + " " + TextTemplateUnmeet
}

func (h *Hub) sshUserCAs() []string {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	return slices.Clone(h.sshrt.userCAs)
}

func (h *Hub) sshHostCAs() []string {
	h.sshrt.mu.Lock()
	defer h.sshrt.mu.Unlock()
	return nonNilStrings(slices.Clone(h.sshrt.hostCAs))
}

// revokedHostKeys are removed hosts' pinned keys and revoked unmanaged
// host keys (clients' @revoked).
func revokedHostKeys(st state.SSHState) []string {
	out := []string{}
	for _, id := range sshKeys(st.Hosts) {
		if h := st.Hosts[id]; h.Removed && h.HostKey != "" {
			out = append(out, h.HostKey)
		}
	}
	for _, fp := range sshKeys(st.RevokedHostKeys) {
		if k := st.RevokedHostKeys[fp]; k != "" {
			out = append(out, k)
		}
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SSHCAKeys are the user and host CA public keys (GET ssh/ca).
func (h *Hub) SSHCAKeys() (user, host []string) {
	return nonNilStrings(h.sshUserCAs()), h.sshHostCAs()
}

// SSHErrorStatus is err's HTTP status and the text to answer: a refusal's
// own; anything else 500 with a generic text (never an inner error).
func SSHErrorStatus(err error) (int, string) {
	var r *sshRefusal
	if errors.As(err, &r) {
		return r.status, r.text
	}
	var se *StatusError
	if errors.As(err, &se) && se.Status < 500 {
		return se.Status, se.Error()
	}
	return http.StatusInternalServerError, "internal error"
}
