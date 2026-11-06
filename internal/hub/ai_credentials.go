package hub

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/templates"
)

// Lazy credential minting (contract §15.5 "Credential lifecycle", §15.7
// POST /internal/credentials; G26, G35, G6).
//
// The gate asks for a person's credential for an app_token companion the
// first time they use it. The Hub accepts only a kind: companion
// resource of its own current gate configuration (rebuilt here from
// state and a FRESH directory snapshot — the cached file is never
// trusted), re-checks the person against that snapshot, and then, under
// the instance's AI lock (never lockApp) and single flight per
// (resource, user), returns the active entry's id or runs the mint hook.
// The hook's stdout is parsed strictly, the credential encrypted to the
// gate (aiCredStore.Put) and every plaintext copy the Hub made zeroed; it
// is never logged, audited, put in an op record, an error or an answer.

// MintResult is MintCredential's answer: the active entry's id, or
// NoAccount with the app's URL (the mint hook exited 3: the person never
// signed in to the app).
type MintResult struct {
	ID        string
	NoAccount bool
	AppURL    string
}

// Mint bounds: the whole mint (lock wait, directory, hook) runs on its
// own context, detached from the first caller's, so one caller giving up
// doesn't fail the others sharing the flight.
const (
	mintTimeout       = 2 * time.Minute
	mintCredentialMax = 4096
	mintNameLen       = 12
	mintNameAlphabet  = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// errMintOutput is the companion's last error for a mint whose output
// was refused (never quoting it).
const errMintOutput = "mint hook output refused: want exactly {\"credential\", \"id\"} (credential 1–4096 printable ASCII characters, id as in §15.4)"

// aiMintIn is the mint hook's stdin, keys in §15.5's order.
type aiMintIn struct {
	Action    string   `json:"action"`
	User      string   `json:"user"`
	Instance  string   `json:"instance"`
	Companion string   `json:"companion"`
	Name      string   `json:"name"`
	Mode      string   `json:"mode"`
	Scopes    []string `json:"scopes"`
}

// errMintFailed: the hook failed or its output was refused (502
// mint_failed; the details are on the AI tab and the op record).
func errMintFailed(companion string) error {
	return &StatusError{Status: http.StatusBadGateway, Err: fmt.Errorf("companion %s: minting the credential failed", companion)}
}

// MintCredential returns user's active credential id for the companion
// resource (its URL), minting one first if there is none. Errors are
// *StatusError: 404 not a current app_token companion resource, 403 not
// in its population, 502 the hook failed or its output was refused,
// 503 the directory couldn't be read. Single flight per (resource,
// user): concurrent callers share one run and one answer.
func (h *Hub) MintCredential(ctx context.Context, resource, user string) (*MintResult, error) {
	if resource == "" || !aigate.ValidUsername(user) {
		// Exact lowercase usernames only (the population's form): any
		// other spelling is nobody.
		if resource == "" {
			return nil, statusErr(http.StatusNotFound, "no such resource")
		}
		return nil, statusErr(http.StatusForbidden, "not in the population")
	}
	ch := h.mints.DoChan(resource+"\x00"+user, func() (any, error) {
		mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mintTimeout)
		defer cancel()
		return h.mint(mctx, resource, user)
	})
	select {
	case <-ctx.Done():
		return nil, &StatusError{Status: http.StatusServiceUnavailable, Err: ctx.Err()}
	case r := <-ch:
		if r.Err != nil {
			return nil, r.Err
		}
		res := *r.Val.(*MintResult)
		return &res, nil
	}
}

// mintTarget finds resource in the gate configuration built from state
// and m: a kind: companion app_token resource (else 404) whose
// population holds user and who isn't past their expiring time (else
// 403). gateFile already leaves out companions that are off, owe a
// revoke_all, are on a disabled, deleting or restoring instance, at LoA
// 3, and everything while the master switch is off or no gate exists.
func (h *Hub) mintTarget(m *directory.Membership, resource, user string) (aigate.Resource, error) {
	f, _, err := h.gateFile(m, h.aiClientHealth(), nil)
	if err != nil {
		return aigate.Resource{}, statusErr(http.StatusServiceUnavailable, "the AI configuration can't be built: %v", err)
	}
	if !f.Enabled {
		return aigate.Resource{}, statusErr(http.StatusNotFound, "AI support is off")
	}
	i := slices.IndexFunc(f.Resources, func(r aigate.Resource) bool { return r.URL == resource })
	if i < 0 || f.Resources[i].Kind != aigate.KindCompanion || f.Resources[i].Identity.Mode != aigate.IdentityAppToken {
		return aigate.Resource{}, statusErr(http.StatusNotFound, "not a current app_token companion resource")
	}
	r := f.Resources[i]
	if !slices.Contains(r.Population, user) {
		return aigate.Resource{}, statusErr(http.StatusForbidden, "not in the population")
	}
	if at, ok := r.Expiring[user]; ok && !time.Now().Before(at.Time) {
		return aigate.Resource{}, statusErr(http.StatusForbidden, "not in the population")
	}
	return r, nil
}

// mint is one flight of MintCredential.
func (h *Hub) mint(ctx context.Context, resource, user string) (*MintResult, error) {
	// A fresh directory snapshot: never the last gate file's population.
	m, err := h.membership(ctx)
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status != http.StatusServiceUnavailable {
			// 502 is mint_failed to the gate: a directory problem is 503.
			return nil, &StatusError{Status: http.StatusServiceUnavailable, Err: err}
		}
		return nil, err
	}
	r, err := h.mintTarget(m, resource, user)
	if err != nil {
		return nil, err
	}
	// The instance's AI lock (G35: never lockApp), then the same checks
	// again: a switch-off, mode change or restore that held the lock may
	// have changed the state meanwhile.
	defer h.aiLock(r.Instance)()
	again, err := h.mintTarget(m, resource, user)
	if err != nil {
		return nil, err
	}
	if again.Instance != r.Instance || again.Companion != r.Companion || again.Mode != r.Mode {
		return nil, statusErr(http.StatusNotFound, "not a current app_token companion resource")
	}
	for _, e := range h.creds().Entries() {
		if e.Instance == r.Instance && e.Companion == r.Companion && e.User == user && e.State == aigate.StateActive {
			return &MintResult{ID: e.ID}, nil
		}
	}
	h.mu.RLock()
	lt := h.findLocked(r.Instance)
	var t templates.Template
	if lt != nil {
		t = *lt
	}
	h.mu.RUnlock()
	if lt == nil {
		return nil, statusErr(http.StatusNotFound, "not a current app_token companion resource")
	}
	c := companionOf(&t, r.Companion)
	if c == nil || c.Identity.Mode != templates.IdentityAppToken || c.Identity.Mint == "" {
		return nil, statusErr(http.StatusNotFound, "not a current app_token companion resource")
	}
	name, err := mintName()
	if err != nil {
		return nil, statusErr(http.StatusInternalServerError, "companion %s: %v", c.Name, err)
	}
	scopes := slices.Clone(c.Identity.Scopes[r.Mode])
	if scopes == nil {
		scopes = []string{}
	}
	stdin, _ := json.Marshal(aiMintIn{Action: "mint", User: user, Instance: r.Instance, Companion: r.Companion, Name: name, Mode: r.Mode, Scopes: scopes})
	target := r.Instance + "/" + r.Companion + "/" + user
	actor := directory.Human(user)

	out, exit, u := h.runAIHookExit(ctx, &t, c.Identity.Mint, stdin)
	defer clear(out)
	switch {
	case exit == 3:
		// The person has no app account yet (the hook never creates
		// one): not the companion's failure.
		h.auditAI(actor, "ai.credential.mint", target, "no app account", statusErr(http.StatusConflict, "no app account yet"))
		return &MintResult{NoAccount: true, AppURL: r.AppURL}, nil
	case !u.OK:
		h.mintFailed(&t, c, actor, target, u.Error)
		return nil, errMintFailed(c.Name)
	}
	id, cred, ok := parseMintOutput(out)
	clear(out)
	if !ok {
		h.mintFailed(&t, c, actor, target, "hook "+c.Identity.Mint+": "+errMintOutput)
		return nil, errMintFailed(c.Name)
	}
	// Put encrypts to the gate and zeroes cred (always).
	if err := h.creds().Put(aigate.Credential{Instance: r.Instance, Companion: r.Companion, User: user, ID: id, MintedAt: aigate.At(time.Now())}, cred); err != nil {
		h.mintFailed(&t, c, actor, target, "hook "+c.Identity.Mint+": the credential couldn't be stored: "+err.Error())
		// The app holds a credential nobody can use: revoke it now
		// (best effort; never retried — it is in no file).
		h.revokeOrphan(ctx, &t, c, user, id)
		return nil, errMintFailed(c.Name)
	}
	h.clearMintError(r.Instance, c)
	h.auditAI(actor, "ai.credential.mint", target, "id "+id, nil)
	return &MintResult{ID: id}, nil
}

// mintFailed records a failed mint (msg already redacted and clipped by
// runAIHook, or the Hub's own text): the companion's last error, a
// failed op ai and an audit error entry.
func (h *Hub) mintFailed(t *templates.Template, c *templates.Companion, actor directory.Actor, target, msg string) {
	msg = clipRunes(msg, unitErrorMax)
	h.setAIError(t.ID, c.Name, msg)
	err := &StatusError{Status: http.StatusBadGateway, Err: fmt.Errorf("companion %s: mint failed: %s", c.Name, msg)}
	h.finishOpGuarded(t.ID, OpAI, err, false, true)
	h.auditAI(actor, "ai.credential.mint", target, "", err)
}

// clearMintError clears the companion's last error if it was a mint's
// (a lifecycle failure stays until the lifecycle step succeeds).
func (h *Hub) clearMintError(id string, c *templates.Companion) {
	if strings.HasPrefix(h.aiError(id, c.Name), "hook "+c.Identity.Mint+":") {
		h.setAIError(id, c.Name, "")
	}
}

// aiRevokeIn is the revoke hook's stdin for one person (§15.5).
type aiRevokeIn struct {
	Action string   `json:"action"`
	User   string   `json:"user"`
	IDs    []string `json:"ids"`
}

// revokeOrphan revokes a just-minted credential that couldn't be stored.
func (h *Hub) revokeOrphan(ctx context.Context, t *templates.Template, c *templates.Companion, user, id string) {
	if c.Identity.Revoke == "" {
		return
	}
	stdin, _ := json.Marshal(aiRevokeIn{Action: "revoke", User: user, IDs: []string{id}})
	out, u := h.runAIHook(ctx, t, c.Identity.Revoke, stdin)
	clear(out)
	if !u.OK {
		log.Printf("ai: %s/%s: revoking the unstored credential %s of %s failed: %s", t.ID, c.Name, id, user, u.Error)
	}
}

// mintName is portcullis-ai-<12 random [a-z0-9]> (§15.5), unbiased.
func mintName() (string, error) {
	b := make([]byte, 0, mintNameLen)
	buf := make([]byte, 32)
	for len(b) < mintNameLen {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("random name: %v", err)
		}
		for _, x := range buf {
			// 252 = 7 × 36: rejection sampling keeps every letter equally likely.
			if x < 252 && len(b) < mintNameLen {
				b = append(b, mintNameAlphabet[int(x)%len(mintNameAlphabet)])
			}
		}
	}
	return templates.AIClientPrefix + string(b), nil
}

// parseMintOutput reads the mint hook's stdout strictly: exactly one JSON
// object with exactly the keys credential and id (no duplicates, nothing
// after it), credential a string of 1–4096 printable ASCII characters
// written without escapes, id as §15.4 allows. cred is a fresh copy the
// caller zeroes (Put does); out is not kept. Nothing here quotes out.
func parseMintOutput(out []byte) (id string, cred []byte, ok bool) {
	if topLevelMembers(out) != 2 {
		return "", nil, false
	}
	var v map[string]json.RawMessage
	// json.Unmarshal reads out in place (a Decoder would copy it into a
	// buffer the Hub can't zero); RawMessage values are copies, zeroed
	// below.
	if err := json.Unmarshal(out, &v); err != nil {
		return "", nil, false
	}
	defer func() {
		for _, raw := range v {
			clear(raw)
		}
	}()
	rawCred, okC := v["credential"]
	rawID, okI := v["id"]
	if len(v) != 2 || !okC || !okI {
		return "", nil, false
	}
	if err := json.Unmarshal(rawID, &id); err != nil || !aigate.ValidCredentialID(id) {
		return "", nil, false
	}
	n := len(rawCred)
	if n < 3 || n-2 > mintCredentialMax || rawCred[0] != '"' || rawCred[n-1] != '"' {
		return "", nil, false
	}
	for _, c := range rawCred[1 : n-1] {
		// Printable ASCII; '"' and '\\' would need escapes: refused
		// rather than unescaped into a copy the Hub couldn't zero.
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return "", nil, false
		}
	}
	return id, append([]byte(nil), rawCred[1:n-1]...), true
}

// topLevelMembers counts the members of the JSON object b is (-1: not an
// object, or anything but whitespace after it). Only the structure is
// looked at; b must still be decoded (json.Unmarshal checks validity).
// Duplicate keys show as more members than the decoded map has keys.
func topLevelMembers(b []byte) int {
	depth, members := 0, 0
	inStr, esc, seenObj, done, empty := false, false, false, false, true
	for _, c := range b {
		switch {
		case inStr:
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		case done:
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				return -1
			}
			continue
		}
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '"':
			inStr = true
		case '{', '[':
			if depth == 0 {
				if c != '{' || seenObj {
					return -1
				}
				seenObj = true
			}
			depth++
			continue
		case '}', ']':
			depth--
			if depth == 0 {
				done = true
				if !empty {
					members++
				}
			}
			continue
		case ',':
			if depth == 1 {
				members++
			}
		}
		if depth == 0 {
			return -1
		}
		if depth == 1 {
			empty = false
		}
	}
	if !done {
		return -1
	}
	return members
}
