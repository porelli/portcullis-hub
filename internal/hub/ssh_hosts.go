package hub

// Managed hosts (contract §18.11): enrolment codes, the challenge and
// proof, the pinned host key, bundles by long-poll, removal.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/sshaccess"
	"github.com/portcullis/hub/internal/state"
)

const (
	enrolCodeTTL      = 15 * time.Minute
	enrolChallengeTTL = 2 * time.Minute

	// TextHostsOff answers every host route while SSH access is off.
	TextHostsOff = "SSH access is off"
	// TextRemoved answers a removed, unknown or unpinned host.
	TextRemoved = "removed"
)

// bundlePollMax is how long a long-poll is held (a var for tests).
var bundlePollMax = 55 * time.Second

// HostInput is Add host / Edit host.
type HostInput struct {
	ID         string   `json:"id"`
	Names      []string `json:"names"`
	Addrs      []string `json:"addrs"`
	HostGroups []string `json:"host_groups"`
	Managed    bool     `json:"managed"`
}

// hostRuntime is the hosts' memory: challenges, nonces, last syncs.
type hostRuntime struct {
	mu         sync.Mutex
	challenges map[string]map[string]time.Time // host → challenge → expiry
	nonces     map[string]time.Time            // host|nonce → first use
	lastSync   map[string]time.Time
	oversize   map[string]bool
	enrolMu    map[string]*sync.Mutex
}

func (r *hostRuntime) init() {
	if r.challenges == nil {
		r.challenges, r.nonces, r.lastSync, r.oversize, r.enrolMu = map[string]map[string]time.Time{}, map[string]time.Time{}, map[string]time.Time{}, map[string]bool{}, map[string]*sync.Mutex{}
	}
}

func random32() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func secretHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// checkAdminFresh: a fresh sign-in under the hub template (Add host, a new
// code, Remove host, privileged grants: contract §18.11).
func (h *Hub) checkAdminFresh(ctx context.Context, actor directory.Actor, p freshauth.Proof) error {
	if actor.User == "" {
		return statusErr(http.StatusForbidden, "administrators only")
	}
	if actor.Via == directory.ViaAI {
		return statusErr(http.StatusForbidden, "not through an AI assistant")
	}
	_, _, err := h.checkFreshAuthOn(ctx, ListenerHub, govCore("hub"), p, actor.User)
	return err
}

func validHostInput(st state.SSHState, in HostInput) error {
	tmp := st.Clone()
	if tmp.Hosts == nil {
		tmp.Hosts = map[string]state.SSHHost{}
	}
	tmp.Hosts[in.ID] = state.SSHHost{Names: in.Names, Addrs: in.Addrs, HostGroups: in.HostGroups, Managed: in.Managed}
	if err := sshaccess.Validate(tmp); err != nil {
		return statusErr(http.StatusBadRequest, "%v", err)
	}
	for _, g := range in.HostGroups {
		if g == cliapi.BuiltinAllHostGroup {
			return statusErr(http.StatusBadRequest, "every managed host is in all already: pick other host groups or none")
		}
	}
	return nil
}

// CreateHost adds a host. A managed host gets its one-time enrolment code
// (returned once, never stored; only its secret's hash is).
func (h *Hub) CreateHost(ctx context.Context, actor directory.Actor, in HostInput, p freshauth.Proof) (code string, err error) {
	defer func() {
		h.auditSSH(actor.User, "ssh.host.create", in.ID, fmt.Sprintf("names=%s addrs=%s groups=%s managed=%v", strings.Join(in.Names, ","), strings.Join(in.Addrs, ","), strings.Join(in.HostGroups, ","), in.Managed), err)
	}()
	if err := h.checkAdminFresh(ctx, actor, p); err != nil {
		return "", err
	}
	h.mu.Lock()
	if _, ok := h.st.SSH.Hosts[in.ID]; ok {
		h.mu.Unlock()
		return "", statusErr(http.StatusConflict, "a host %s exists already", in.ID)
	}
	if err := validHostInput(h.st.SSH, in); err != nil {
		h.mu.Unlock()
		return "", err
	}
	if h.st.SSH.Hosts == nil {
		h.st.SSH.Hosts = map[string]state.SSHHost{}
	}
	h.st.SSH.Hosts[in.ID] = state.SSHHost{Names: in.Names, Addrs: in.Addrs, HostGroups: dedupStrings(in.HostGroups), Managed: in.Managed}
	h.saveLocked()
	h.mu.Unlock()
	h.TriggerSSHCompile()
	if !in.Managed {
		return "", nil
	}
	return h.newEnrolCode(in.ID)
}

// NewEnrolCode issues a new code for a managed host (the last one stops
// working). A host enrolled before is re-pinned by the next enrolment.
func (h *Hub) NewEnrolCode(ctx context.Context, actor directory.Actor, hostID string, p freshauth.Proof) (code string, err error) {
	defer func() { h.auditSSH(actor.User, "ssh.host.update", hostID, "new enrolment code", err) }()
	if err := h.checkAdminFresh(ctx, actor, p); err != nil {
		return "", err
	}
	return h.newEnrolCode(hostID)
}

func (h *Hub) newEnrolCode(hostID string) (string, error) {
	userCAs, hostCAs := h.SSHCAKeys()
	if len(userCAs) == 0 || len(hostCAs) == 0 {
		return "", statusErr(http.StatusServiceUnavailable, "the SSH CAs aren't known yet: check enroll and Vault (./portcullis status)")
	}
	ufp, hfp := caFP(userCAs[0]), caFP(hostCAs[0])
	if ufp == "" || hfp == "" {
		return "", statusErr(http.StatusServiceUnavailable, "the SSH CA keys can't be read")
	}
	secret := random32()
	now := h.sshrt.clock()
	h.mu.Lock()
	hst, ok := h.st.SSH.Hosts[hostID]
	if !ok || !hst.Managed || hst.Removed {
		h.mu.Unlock()
		return "", statusErr(http.StatusNotFound, "no managed host %s", hostID)
	}
	hst.EnrolHash, hst.EnrolExpires = secretHash(secret), now.Add(enrolCodeTTL).UTC()
	h.st.SSH.Hosts[hostID] = hst
	groups := append([]string{cliapi.BuiltinAllHostGroup}, hst.HostGroups...)
	h.saveLocked()
	h.mu.Unlock()
	c := cliapi.EnrolCode{Domain: h.cfg.Domain, HostID: hostID, HostGroups: dedupStrings(groups), UserCAFP: ufp, HostCAFP: hfp, Secret: secret, Expires: now.Add(enrolCodeTTL).UTC()}
	return c.String(), nil
}

func caFP(line string) string {
	k, _, err := cliapi.ParseAuthorizedKey(line)
	if err != nil {
		return ""
	}
	return cliapi.Fingerprint(k)
}

// EnrolChallenge is POST hosts/enrol/challenge: 32 random bytes, valid 2
// minutes, single use, for a host with a live enrolment code.
func (h *Hub) EnrolChallenge(hostID string) (string, error) {
	if !h.SSHEnabled() {
		return "", refusal(http.StatusServiceUnavailable, TextHostsOff, "ssh off")
	}
	now := h.sshrt.clock()
	h.mu.RLock()
	hst, ok := h.st.SSH.Hosts[hostID]
	h.mu.RUnlock()
	if !ok || !hst.Managed || hst.Removed || hst.EnrolHash == "" || !now.Before(hst.EnrolExpires) {
		return "", refusal(http.StatusForbidden, "no enrolment is open for this host: ask an administrator for a new code", "no live enrolment code")
	}
	ch := random32()
	h.sshhosts.mu.Lock()
	defer h.sshhosts.mu.Unlock()
	h.sshhosts.init()
	m := h.sshhosts.challenges[hostID]
	if m == nil {
		m = map[string]time.Time{}
		h.sshhosts.challenges[hostID] = m
	}
	for c, exp := range m {
		if !now.Before(exp) {
			delete(m, c)
		}
	}
	if len(m) >= 4 {
		return "", refusal(http.StatusTooManyRequests, TextTooMany, "too many open challenges")
	}
	m[ch] = now.Add(enrolChallengeTTL)
	return ch, nil
}

// Enrol is POST hosts/enrol (plan C4): the secret against the stored hash
// (constant time), the proof by the host key over a live challenge, then
// the host key is pinned and the first bundle answered. Any failure
// leaves the host as it was (the code still works until it expires).
func (h *Hub) Enrol(ctx context.Context, req cliapi.EnrolRequest, addr string) (b *cliapi.Bundle, err error) {
	if !h.SSHEnabled() {
		return nil, refusal(http.StatusServiceUnavailable, TextHostsOff, "ssh off")
	}
	id := req.HostID
	fp := "-"
	defer func() {
		h.auditSSH("-", "ssh.host.enrol", clip(id, 64), "key "+fp+" addr="+clip(addr, 64), err)
	}()
	if !cliapi.ValidHostID(id) {
		return nil, refusal(http.StatusForbidden, TextRemoved, "bad host id")
	}
	lock := h.enrolLock(id)
	lock.Lock()
	defer lock.Unlock()
	now := h.sshrt.clock()
	h.mu.RLock()
	hst, ok := h.st.SSH.Hosts[id]
	h.mu.RUnlock()
	if !ok || !hst.Managed || hst.Removed || hst.EnrolHash == "" || !now.Before(hst.EnrolExpires) {
		return nil, refusal(http.StatusForbidden, "no enrolment is open for this host: ask an administrator for a new code", "no live enrolment code")
	}
	want, _ := hex.DecodeString(hst.EnrolHash)
	got := sha256.Sum256([]byte(req.Secret))
	if len(want) != 32 || subtle.ConstantTimeCompare(got[:], want) != 1 {
		return nil, refusal(http.StatusForbidden, "the enrolment code is wrong", "wrong secret")
	}
	key, norm, perr := cliapi.ParseAuthorizedKey(req.HostKey)
	if perr != nil || key.Type() != ssh.KeyAlgoED25519 {
		return nil, refusal(http.StatusBadRequest, "the host key must be the host's ed25519 key", "host key not ed25519")
	}
	fp = cliapi.Fingerprint(key)
	sig, serr := sshsig.Unarmor([]byte(req.Proof))
	if serr != nil || !h.consumeChallenge(id, now, func(ch string) bool {
		return sshsig.Verify(bytes.NewReader(cliapi.EnrolMessage(h.cfg.Domain, id, ch)), sig, key, sshsig.HashSHA512, cliapi.NSHostEnrol) == nil
	}) {
		return nil, refusal(http.StatusForbidden, "the enrolment proof is wrong", "proof over no live challenge")
	}
	if err := req.Ceiling.Validate(); err != nil {
		return nil, refusal(http.StatusBadRequest, "the host's ceiling is invalid", "ceiling invalid")
	}
	if len(req.SSHDVersion) > 64 {
		return nil, refusal(http.StatusBadRequest, "malformed request", "sshd version too long")
	}
	// Pin, compile, answer; undo the pin if no bundle comes out.
	ceil := req.Ceiling
	h.mu.Lock()
	cur := h.st.SSH.Hosts[id]
	prev := cur
	cur.HostKey, cur.KeyFP, cur.EnrolHash, cur.EnrolExpires, cur.Ceiling = norm, fp, "", time.Time{}, &ceil
	cur.HostCert, cur.HostCertFrom, cur.HostCertUntil, cur.BundleHash = "", time.Time{}, time.Time{}, ""
	cur.LastSync = now.UTC()
	h.st.SSH.Hosts[id] = cur
	h.saveLocked()
	h.mu.Unlock()
	h.sshrt.runMu.Lock()
	cerr := h.compileSSH(ctx)
	h.sshrt.runMu.Unlock()
	b, berr := h.bundleFor(id)
	if cerr != nil || berr != nil {
		h.mu.Lock()
		h.st.SSH.Hosts[id] = prev
		h.saveLocked()
		h.mu.Unlock()
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "first bundle couldn't be compiled")
	}
	return b, nil
}

func (h *Hub) enrolLock(id string) *sync.Mutex {
	h.sshhosts.mu.Lock()
	defer h.sshhosts.mu.Unlock()
	h.sshhosts.init()
	l := h.sshhosts.enrolMu[id]
	if l == nil {
		l = &sync.Mutex{}
		h.sshhosts.enrolMu[id] = l
	}
	return l
}

// consumeChallenge removes and reports the first live challenge of id
// that ok accepts.
func (h *Hub) consumeChallenge(id string, now time.Time, ok func(string) bool) bool {
	h.sshhosts.mu.Lock()
	defer h.sshhosts.mu.Unlock()
	h.sshhosts.init()
	for ch, exp := range h.sshhosts.challenges[id] {
		if now.Before(exp) && ok(ch) {
			delete(h.sshhosts.challenges[id], ch)
			return true
		}
	}
	return false
}

// bundleFor is the compiled bundle of host id (a copy), checked against
// the 4 MiB cap.
func (h *Hub) bundleFor(id string) (*cliapi.Bundle, error) {
	c := h.sshCompiled()
	if c == nil {
		return nil, errors.New("not compiled")
	}
	b, ok := c.Bundles[id]
	if !ok {
		return nil, errors.New("no bundle")
	}
	raw, err := json.Marshal(b)
	h.sshhosts.mu.Lock()
	h.sshhosts.init()
	h.sshhosts.oversize[id] = err == nil && len(raw) > cliapi.MaxBundle
	h.sshhosts.mu.Unlock()
	if err != nil || len(raw) > cliapi.MaxBundle {
		return nil, refusal(http.StatusServiceUnavailable, TextSSHUnavailable, "bundle over 4 MiB")
	}
	var out cliapi.Bundle
	_ = json.Unmarshal(raw, &out)
	return &out, nil
}

// HostBundle is GET hosts/bundle?since=: the bundle as soon as the host's
// serial is above since, else nil (204) after 55 s.
func (h *Hub) HostBundle(ctx context.Context, hostID string, since int64) (*cliapi.Bundle, error) {
	if !h.SSHEnabled() {
		return nil, refusal(http.StatusServiceUnavailable, TextHostsOff, "ssh off")
	}
	timer := time.NewTimer(bundlePollMax)
	defer timer.Stop()
	for {
		ch := h.sshChanged()
		b, err := h.bundleFor(hostID)
		var r *sshRefusal
		switch {
		case err == nil && b.Serial > since:
			return b, nil
		case errors.As(err, &r):
			return nil, err // over the cap: never served
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-timer.C:
			return nil, nil
		case <-ch:
		}
	}
}

// RemoveHost marks a host removed: its next request gets 403 removed
// (the agent then removes the Portcullis trust), its host key becomes an
// @revoked line for clients, and it leaves every compile.
func (h *Hub) RemoveHost(ctx context.Context, actor directory.Actor, hostID string, p freshauth.Proof) (err error) {
	defer func() { h.auditSSH(actor.User, "ssh.host.remove", hostID, "", err) }()
	if err := h.checkAdminFresh(ctx, actor, p); err != nil {
		return err
	}
	h.mu.Lock()
	hst, ok := h.st.SSH.Hosts[hostID]
	if !ok {
		h.mu.Unlock()
		return statusErr(http.StatusNotFound, "no host %s", hostID)
	}
	if !hst.Managed || hst.HostKey == "" {
		delete(h.st.SSH.Hosts, hostID) // nothing to tell: just forget it
	} else {
		hst.Removed, hst.EnrolHash = true, ""
		h.st.SSH.Hosts[hostID] = hst
	}
	h.saveLocked()
	h.mu.Unlock()
	h.TriggerSSHCompile()
	return nil
}

func dedupStrings(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return slices.Compact(out)
}

// PinHostForTest adds an enrolled managed host with hostKey (tests of
// other packages only).
func (h *Hub) PinHostForTest(id, hostKey string) error {
	if !testing.Testing() {
		return errors.New("PinHostForTest: tests only")
	}
	k, norm, err := cliapi.ParseAuthorizedKey(hostKey)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.st.SSH.Hosts == nil {
		h.st.SSH.Hosts = map[string]state.SSHHost{}
	}
	h.st.SSH.Hosts[id] = state.SSHHost{Names: []string{id + ".example.org"}, Managed: true, HostKey: norm, KeyFP: cliapi.Fingerprint(k)}
	return nil
}
