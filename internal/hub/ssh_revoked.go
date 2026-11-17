package hub

// The revoked-keys list (contract §18.10, plan C21): hub_data/ssh/
// revoked.json (0600, atomic). Public keys only; the public list and the
// bundles carry the keys, the Hub's views the fingerprints.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/cliapi"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/fsutil"
)

// RevokedKey is one entry. Until zero = until an administrator removes it
// (a bring-your-own key).
type RevokedKey struct {
	Key    string    `json:"key"`
	FP     string    `json:"fp"`
	Reason string    `json:"reason"`
	Actor  string    `json:"actor"`
	Added  time.Time `json:"added"`
	Until  time.Time `json:"until"`
}

// revokedStore guards the file.
type revokedStore struct {
	mu sync.Mutex
}

func (h *Hub) sshDir() string { return filepath.Join(h.cfg.DataDir, "ssh") }

func (h *Hub) revokedPath() string { return filepath.Join(h.sshDir(), "revoked.json") }

// loadRevokedLocked reads the list; a missing file is empty, an
// unreadable one an error (callers fail closed: no signing without it).
func (h *Hub) loadRevokedLocked() ([]RevokedKey, error) {
	raw, err := os.ReadFile(h.revokedPath())
	if errors.Is(err, os.ErrNotExist) {
		return []RevokedKey{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("revoked keys: %w", err)
	}
	var out []RevokedKey
	if err := cliapi.UnmarshalStrict(raw, &out); err != nil {
		return nil, fmt.Errorf("revoked keys: %s is corrupt", h.revokedPath())
	}
	return out, nil
}

func (h *Hub) saveRevokedLocked(list []RevokedKey) error {
	sort.Slice(list, func(i, j int) bool { return list[i].FP < list[j].FP })
	raw, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.sshDir(), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(h.revokedPath(), append(raw, '\n'), 0o600)
}

// sshRevokedList is the list (nil, err when unreadable).
func (h *Hub) sshRevokedList() ([]RevokedKey, error) {
	h.sshrev.mu.Lock()
	defer h.sshrev.mu.Unlock()
	return h.loadRevokedLocked()
}

// RevokedKeys are the revoked public keys, sorted (the public list, the
// bundles). An unreadable file logs and answers nil.
func (h *Hub) RevokedKeys() []string {
	l, err := h.sshRevokedList()
	if err != nil {
		log.Printf("ssh: %v", err)
		return nil
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		if e.Key != "" { // a fingerprint-only entry (key unknown) is refused at signing only
			out = append(out, e.Key)
		}
	}
	sort.Strings(out)
	return out
}

// TextRevocationIncomplete is the audit and doctor text of a revocation
// whose key the Hub doesn't know (Ruling C21-b): the fingerprint is
// recorded (never signed again) but hosts can't refuse the key.
const TextRevocationIncomplete = "revocation incomplete: key unknown"

// RevokeFingerprints revokes the keys with these fingerprints (an admin's
// Revoke, revocation on leave). A fingerprint whose key isn't in
// keys.json is still recorded — the Hub never signs it again, and the
// account side (locks) follows the mapping anyway — and raises
// TextRevocationIncomplete in the audit and the doctor; never a silent
// no-op.
func (h *Hub) RevokeFingerprints(actor, reason string, fps []string, target string) (int, error) {
	var keys []string
	n := 0
	for _, fp := range fps {
		if k := h.issuedKey(fp); k != "" {
			keys = append(keys, k)
			continue
		}
		if !strings.HasPrefix(fp, "SHA256:") || len(fp) > 80 {
			continue
		}
		now := h.sshrt.clock()
		h.sshrev.mu.Lock()
		list, err := h.loadRevokedLocked()
		if err == nil && !slices.ContainsFunc(list, func(e RevokedKey) bool { return e.FP == fp }) {
			list = append(list, RevokedKey{FP: fp, Reason: clip(reason, 200), Actor: clip(actor, 64), Added: now.UTC()})
			err = h.saveRevokedLocked(list)
			n++
		}
		h.sshrev.mu.Unlock()
		if err == nil {
			err = refusal(http.StatusConflict, TextRevocationIncomplete, TextRevocationIncomplete+" "+fp)
		}
		h.auditSSH(actor, "ssh.certificate.revoke", target, "key "+fp+": "+clip(reason, 200), err)
	}
	m, err := h.RevokeKeys(actor, reason, keys, target)
	return n + m, err
}

// sshRevocationsIncomplete are the fingerprints revoked without a
// usable key (the doctor's input), with when: read from revoked.json, so
// they survive a restart (L-C2). An unreadable list logs and answers nil.
func (h *Hub) sshRevocationsIncomplete() map[string]time.Time {
	l, err := h.sshRevokedList()
	if err != nil {
		log.Printf("ssh: %v", err)
		return nil
	}
	var out map[string]time.Time
	for _, e := range l {
		if _, _, perr := cliapi.ParseAuthorizedKey(e.Key); e.Key == "" || perr != nil {
			if out == nil {
				out = map[string]time.Time{}
			}
			out[e.FP] = e.Added
		}
	}
	return out
}

// revokedUntil is when key fp's entry may go: 24 h after the last
// certificate issued for it; zero (never) for a person's own key.
//
// auto (RR-M5): an automatic revocation (revocation on leave, SSH switched
// off) of a person's own key expires like the others — a group change
// mustn't burn a security key for good; an explicit one (an admin, the
// person, logout --revoke) is permanent.
func (h *Hub) revokedUntil(fp string, auto bool) time.Time {
	var last time.Time
	for _, r := range h.issuedByFP(fp) {
		if r.Own && !auto {
			return time.Time{}
		}
		if r.ValidBefore.After(last) {
			last = r.ValidBefore
		}
	}
	if last.IsZero() {
		return time.Time{} // never issued here: kept until removed
	}
	return last.Add(24 * time.Hour)
}

// RevokeKeys puts keys on the list (each audited ssh.certificate.revoke
// with its fingerprint, actor and reason) and triggers a compile so the
// bundles carry it. A key already listed keeps the later until.
func (h *Hub) RevokeKeys(actor, reason string, keys []string, target string) (int, error) {
	now := h.sshrt.clock()
	type add struct{ e RevokedKey }
	var adds []add
	for _, k := range keys {
		pub, norm, err := cliapi.ParseAuthorizedKey(k)
		if err != nil {
			continue
		}
		fp := cliapi.Fingerprint(pub)
		adds = append(adds, add{RevokedKey{Key: norm, FP: fp, Reason: clip(reason, 200), Actor: clip(actor, 64), Added: now.UTC(), Until: h.revokedUntil(fp, actor == "-")}})
	}
	if len(adds) == 0 {
		return 0, nil
	}
	h.sshrev.mu.Lock()
	list, err := h.loadRevokedLocked()
	if err != nil {
		h.sshrev.mu.Unlock()
		return 0, err
	}
	n := 0
	for _, a := range adds {
		i := slices.IndexFunc(list, func(e RevokedKey) bool { return e.FP == a.e.FP })
		if i >= 0 {
			if list[i].Until.IsZero() || a.e.Until.IsZero() {
				list[i].Until = time.Time{}
			} else if a.e.Until.After(list[i].Until) {
				list[i].Until = a.e.Until
			}
			continue
		}
		list = append(list, a.e)
		n++
	}
	err = h.saveRevokedLocked(list)
	h.sshrev.mu.Unlock()
	for _, a := range adds {
		h.auditSSH(actor, "ssh.certificate.revoke", target, "key "+a.e.FP+": "+clip(reason, 200), err)
	}
	if err != nil {
		return 0, err
	}
	h.TriggerSSHCompile()
	return n, nil
}

// pruneRevoked drops entries past their until (daily, from RunSSH).
func (h *Hub) pruneRevoked(now time.Time) {
	h.sshrev.mu.Lock()
	defer h.sshrev.mu.Unlock()
	list, err := h.loadRevokedLocked()
	if err != nil {
		return
	}
	keep := list[:0]
	for _, e := range list {
		if e.Until.IsZero() || now.Before(e.Until) {
			keep = append(keep, e)
		}
	}
	if len(keep) != len(list) {
		if err := h.saveRevokedLocked(keep); err != nil {
			log.Printf("ssh: pruning revoked keys: %v", err)
		}
	}
}

// RevokeOwnSSH is POST ssh/revocations (plan C30): a proof that passes
// freshauth for portcullis-cli (any switched-on method); revokes only the
// listed keys the issued index shows were issued to that person.
func (h *Hub) RevokeOwnSSH(ctx context.Context, req cliapi.RevocationRequest, addr string) (int, error) {
	const action = "ssh.certificate.revoke"
	if !h.SSHEnabled() {
		return 0, refusal(http.StatusConflict, TextSSHOff, "ssh access off")
	}
	vc, err := h.verifyCLIProof(ctx, freshauth.Proof{Code: req.Code, CodeVerifier: req.CodeVerifier, Nonce: req.Nonce, RedirectURI: req.RedirectURI}, addr, action)
	if err != nil {
		return 0, err
	}
	if len(req.PublicKeys) > 64 {
		return 0, refusal(http.StatusBadRequest, "at most 64 keys", "too many keys")
	}
	mine := map[string]bool{}
	for _, r := range h.IssuedFor(vc.user) {
		mine[r.KeyFP] = true
	}
	var keys []string
	for _, k := range req.PublicKeys {
		pub, _, err := cliapi.ParseAuthorizedKey(k)
		if err == nil && mine[cliapi.Fingerprint(pub)] {
			keys = append(keys, k)
		}
	}
	return h.RevokeKeys(vc.user, "logout --revoke", keys, vc.user)
}

// TextUnrevokeConfirm is the refusal when the typed fingerprint doesn't
// match.
const TextUnrevokeConfirm = "type the key's fingerprint to confirm"

// UnrevokeSSHKey takes key fp off the revoked list (RR-M5): an
// administrator, a fresh sign-in under the hub template, the fingerprint
// typed again, never through an AI assistant; audited
// ssh.certificate.unrevoke. Managed hosts get the shorter list at their
// next bundle.
func (h *Hub) UnrevokeSSHKey(ctx context.Context, actor directory.Actor, fp, typed string, p freshauth.Proof) error {
	err := h.unrevokeSSHKey(ctx, actor, fp, typed, p)
	h.auditSSH(actor.User, "ssh.certificate.unrevoke", "-", "key "+clip(fp, 80), err)
	return err
}

func (h *Hub) unrevokeSSHKey(ctx context.Context, actor directory.Actor, fp, typed string, p freshauth.Proof) error {
	if actor.Via == directory.ViaAI {
		return statusErr(http.StatusForbidden, "not through an AI assistant")
	}
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) > 80 {
		return statusErr(http.StatusBadRequest, "not a key fingerprint")
	}
	if typed != fp {
		return statusErr(http.StatusBadRequest, TextUnrevokeConfirm)
	}
	if err := h.checkAdminFresh(ctx, actor, p); err != nil {
		return err
	}
	h.sshrev.mu.Lock()
	list, err := h.loadRevokedLocked()
	if err != nil {
		h.sshrev.mu.Unlock()
		return err
	}
	i := slices.IndexFunc(list, func(e RevokedKey) bool { return e.FP == fp })
	if i < 0 {
		h.sshrev.mu.Unlock()
		return statusErr(http.StatusNotFound, "this key isn't revoked")
	}
	list = slices.Delete(list, i, i+1)
	err = h.saveRevokedLocked(list)
	h.sshrev.mu.Unlock()
	if err != nil {
		return err
	}
	h.TriggerSSHCompile()
	return nil
}

// fillRevokedKey gives a fingerprint-only revocation of fp its key once
// the key is known (a break-glass key imported after its revocation,
// N-L4), so the bundles carry it.
func (h *Hub) fillRevokedKey(fp, key string) {
	h.sshrev.mu.Lock()
	list, err := h.loadRevokedLocked()
	changed := false
	if err == nil {
		for i := range list {
			if list[i].FP == fp && list[i].Key == "" {
				list[i].Key, changed = key, true
			}
		}
		if changed {
			err = h.saveRevokedLocked(list)
		}
	}
	h.sshrev.mu.Unlock()
	if err != nil {
		log.Printf("ssh: revoked keys: %v", err)
	}
	if changed {
		h.TriggerSSHCompile()
	}
}
