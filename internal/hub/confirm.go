package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/portcullis/hub/internal/aigate"
	"github.com/portcullis/hub/internal/confirm"
	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	sdk "github.com/portcullis/hub/internal/mcpsdk"
	"github.com/portcullis/hub/internal/templates"
)

// Confirmations (contract §15.6, §15.7, §5.1; plan 4 Task 14; G11, G26,
// G27, G75). The store (internal/confirm) is in memory; this file is the
// Hub's two creation paths, the page's view, the decision with a fresh
// passkey touch, the consume and the sweeper.
//
//   - Companions: the gate creates and consumes through the internal API
//     (CreateCompanionConfirmation / ConsumeCompanionConfirmation), only
//     for a kind: companion resource of the Hub's current configuration,
//     with the person re-checked against a fresh directory snapshot; the
//     page is on the people listener and its typed check is the instance
//     label.
//   - Portcullis tools (Tasks 15 / 16): in process, CreateConfirmation /
//     ConsumeConfirmation; the internal API never touches them.

// confirmAuthSlack: a sign-in may be at most this much older than the
// confirmation it approves (§15.6: a sign-in from before the request
// never approves it).
const confirmAuthSlack = 60 * time.Second

// confirmSweepEvery is how often expired confirmations are recorded.
const confirmSweepEvery = 30 * time.Second

// confirmPreviewMax: arguments over 4 KiB never get a confirmation
// (§15.7: never a clipped preview).
const confirmPreviewMax = 4 << 10

var (
	argsDigestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	toolNameRe   = regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,128}$`) // the gate's tool names
	clientRe     = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
	methodRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`) // the gate's literal methods
)

// errNoConfirmation is the one answer to an unknown id, another person's
// confirmation and one of the other listener (no oracle).
var errNoConfirmation = &StatusError{Status: http.StatusNotFound, Err: errors.New("no such confirmation")}

// errTooManyConfirmations is the limit's answer (G27): 429; the gate
// answers the AI with the same text.
var errTooManyConfirmations = &StatusError{Status: http.StatusTooManyRequests, Err: confirm.ErrTooMany}

// ConfirmationStateError: the confirmation isn't pending (409 with its
// state: approved, declined, consumed or expired).
type ConfirmationStateError struct{ State string }

func (e *ConfirmationStateError) Error() string { return "the confirmation is " + e.State }

func (h *Hub) confirms() *confirm.Store {
	h.confirmOnce.Do(func() {
		if h.confirmStore == nil {
			h.confirmStore = confirm.New(nil)
		}
	})
	return h.confirmStore
}

// SetConfirmClockForTest gives the confirmation store a clock (a new,
// empty store). Panics outside tests.
func (h *Hub) SetConfirmClockForTest(now func() time.Time) {
	if !testing.Testing() {
		panic("SetConfirmClockForTest: tests only")
	}
	h.confirms()
	h.confirmStore = confirm.New(now)
}

// SetConfirmPerHourForTest sets the store's per-person hourly limit.
// Panics outside tests.
func (h *Hub) SetConfirmPerHourForTest(n int) {
	if !testing.Testing() {
		panic("SetConfirmPerHourForTest: tests only")
	}
	h.confirms().SetPerHourForTest(n)
}

// auditConfirm records ai.confirm: what (approved, declined, expired,
// refused), the tool, the resource and args_sha256 — never the
// arguments.
func (h *Hub) auditConfirm(actor directory.Actor, what, resource, tool, digest, id, why string) {
	h.mu.RLock()
	a := h.audit
	h.mu.RUnlock()
	if a == nil {
		return
	}
	d := what + " tool " + tool + " args_sha256 " + digest
	if id != "" {
		d += " confirmation " + id
	}
	if why != "" {
		d += ": " + why
	}
	e := directory.AuditEntry{Actor: actor.User, Via: actor.Via, Client: actor.Client, Action: "ai.confirm",
		Target: clip(resource, 256), Detail: clipRunes(d, 600), Result: "ok"}
	if what == "refused" {
		e.Result = "refused"
	}
	if err := a.Append(e); err != nil {
		log.Printf("audit: %v", err)
	}
}

// CreateConfirmation creates (or returns the pending one with the same
// binding) a confirmation of a Portcullis tool, in process (Tasks 15 /
// 16): r is the Hub's own rendering of the call (Listener hub for admin
// tools, people for people tools). Over a limit (G27): 429, audited
// ai.confirm refused. actor is who asked (via ai, the client).
func (h *Hub) CreateConfirmation(actor directory.Actor, r confirm.Request) (*confirm.Confirmation, error) {
	c, err := h.confirms().Create(r)
	switch {
	case errors.Is(err, confirm.ErrTooMany):
		h.auditConfirm(actor, "refused", r.Resource, r.Tool, r.ArgsSHA256, "", "too many confirmations requested")
		return nil, errTooManyConfirmations
	case errors.Is(err, confirm.ErrInvalid):
		return nil, statusErr(http.StatusBadRequest, "%v", err)
	case err != nil:
		return nil, statusErr(http.StatusInternalServerError, "creating the confirmation: %v", err)
	}
	return c, nil
}

// ConsumeConfirmation consumes the first approved confirmation of
// listener (ListenerHub for admin tools, ListenerPeople for people tools)
// with the binding, in process (Tasks 15 / 16): confirm.ErrPending,
// confirm.ErrDeclined or confirm.ErrNotFound otherwise.
func (h *Hub) ConsumeConfirmation(listener, user, resource, tool, digest string) (*confirm.Confirmation, error) {
	return h.confirms().Consume(listener, user, resource, tool, digest)
}

// ConfirmationURL is the page of c: https://<listener>.<domain>/confirm/<id>.
func (h *Hub) ConfirmationURL(c *confirm.Confirmation) string {
	return "https://" + c.Listener + "." + NormalizeHost(h.Domain()) + "/confirm/" + c.ID
}

// CompanionConfirmRequest is POST /internal/confirmations' body (§15.7).
type CompanionConfirmRequest struct {
	User, Client, Resource, Tool, ArgsSHA256, ArgsPreview, Reason string
}

// companionTarget is the current kind: companion resource with that URL
// (any identity mode the gate file lists) whose population holds user
// (not past their expiring time): else 404 / 403, like mintTarget.
func (h *Hub) companionTarget(m *directory.Membership, resource, user string) (aigate.Resource, error) {
	f, _, err := h.gateFile(m, h.aiClientHealth(), nil)
	if err != nil {
		return aigate.Resource{}, statusErr(http.StatusServiceUnavailable, "the AI configuration can't be built: %v", err)
	}
	if !f.Enabled {
		return aigate.Resource{}, statusErr(http.StatusNotFound, "AI support is off")
	}
	i := slices.IndexFunc(f.Resources, func(r aigate.Resource) bool { return r.URL == resource })
	if i < 0 || f.Resources[i].Kind != aigate.KindCompanion {
		return aigate.Resource{}, statusErr(http.StatusNotFound, "not a current companion resource")
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

// confirmCaught: tool (and, for a "tool:method" pattern, the arguments'
// method) is caught by one of patterns, exactly as the gate matches
// (contract §15.5: "*" globs, case-folded; a method that isn't a plain
// string matches every tool:method pattern of the tool).
func confirmCaught(patterns []string, tool, preview string) bool {
	var methods []string
	unknown := false
	var top map[string]json.RawMessage
	if json.Unmarshal([]byte(preview), &top) == nil {
		for k, v := range top {
			if strings.ToLower(k) != "method" {
				continue
			}
			var s string
			if json.Unmarshal(v, &s) == nil && methodRe.MatchString(s) {
				methods = append(methods, s)
			} else {
				unknown = true
			}
		}
	}
	for _, p := range patterns {
		pt, pm, hasMethod := strings.Cut(strings.ToLower(p), ":")
		if !globFold(pt, strings.ToLower(tool)) {
			continue
		}
		if !hasMethod || unknown {
			return true
		}
		if len(methods) == 0 && globFold(pm, "") {
			return true
		}
		for _, m := range methods {
			if globFold(pm, strings.ToLower(m)) {
				return true
			}
		}
	}
	return false
}

// globFold: "*" is any run (both sides already folded).
func globFold(p, s string) bool {
	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return p == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// CreateCompanionConfirmation is POST /internal/confirmations (§15.7,
// G26): 400 a malformed request, arguments whose digest isn't
// args_sha256, or a tool neither the companion's confirm patterns catch
// nor reason destructive; 404 not a current companion resource; 403 the
// person isn't in its population (a fresh directory snapshot); 429 over
// a limit (audited refused); 503 the directory can't be read. The page
// is on the people listener, its typed check the instance label (G75).
func (h *Hub) CreateCompanionConfirmation(ctx context.Context, q CompanionConfirmRequest) (*confirm.Confirmation, error) {
	if !aigate.ValidUsername(q.User) {
		return nil, statusErr(http.StatusForbidden, "not in the population")
	}
	if !toolNameRe.MatchString(q.Tool) || !argsDigestRe.MatchString(q.ArgsSHA256) || !clientRe.MatchString(q.Client) ||
		(q.Reason != "confirm" && q.Reason != "destructive") {
		return nil, statusErr(http.StatusBadRequest, "invalid confirmation request")
	}
	if len(q.ArgsPreview) > confirmPreviewMax || !utf8.ValidString(q.ArgsPreview) || !json.Valid([]byte(q.ArgsPreview)) {
		return nil, statusErr(http.StatusBadRequest, "these arguments are too long to confirm safely")
	}
	// The preview is the canonical JSON the digest is of: the person
	// approves exactly the bytes the gate forwards.
	if sum := sha256.Sum256([]byte(q.ArgsPreview)); hex.EncodeToString(sum[:]) != q.ArgsSHA256 {
		return nil, statusErr(http.StatusBadRequest, "args_preview is not the arguments of args_sha256")
	}
	// And it is that canonical form (RFC 8785, the gate's rules): what the
	// person reads is what the upstream parses (final review M1).
	if c, err := sdk.CanonicalArguments(json.RawMessage(q.ArgsPreview)); err != nil || string(c) != q.ArgsPreview {
		return nil, statusErr(http.StatusBadRequest, "args_preview is not canonical JSON arguments")
	}
	if q.Resource == aigate.AdminURL(NormalizeHost(h.Domain())) || q.Resource == aigate.PeopleURL(NormalizeHost(h.Domain())) {
		return nil, statusErr(http.StatusNotFound, "not a current companion resource")
	}
	m, err := h.freshMembership(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.companionTarget(m, q.Resource, q.User)
	if err != nil {
		return nil, err
	}
	if q.Reason == "confirm" && !confirmCaught(r.Tools.Confirm, q.Tool, q.ArgsPreview) {
		return nil, statusErr(http.StatusBadRequest, "the companion doesn't ask to confirm %s", q.Tool)
	}
	h.mu.RLock()
	t := h.findLocked(r.Instance)
	label := ""
	if t != nil {
		label = instanceName(t)
	}
	h.mu.RUnlock()
	if t == nil {
		return nil, statusErr(http.StatusNotFound, "not a current companion resource")
	}
	why := label + " asks you to confirm every call of " + q.Tool + "."
	if q.Reason == "destructive" {
		why = r.Label + " marks " + q.Tool + " as destructive: it may delete or overwrite data in " + label + "."
	}
	return h.CreateConfirmation(directory.Actor{User: q.User, Via: directory.ViaAI, Client: q.Client}, confirm.Request{
		User: q.User, Client: q.Client, Resource: q.Resource, Tool: q.Tool, ArgsSHA256: q.ArgsSHA256, ArgsPreview: q.ArgsPreview,
		Listener: ListenerPeople,
		Typed:    label,
		Label:    r.Label + " on " + label + " (" + r.Host + ")",
		Consequences: []string{
			"Runs " + q.Tool + " once on " + label + " (" + r.Host + ") as you, with exactly the arguments below.",
			why,
		},
	})
}

// Consume states of ConsumeCompanionConfirmation.
const (
	ConsumeConsumed = "consumed"
	ConsumeNone     = "none"
	ConsumePending  = confirm.Pending
	ConsumeDeclined = confirm.Declined
)

// ConsumeCompanionConfirmation is POST /internal/confirmations/consume
// (§15.7): the id of the approved match it consumed, or the state
// (none: the gate creates a new one). Only a current companion resource
// whose population holds the person (fresh snapshot) is ever consumed;
// anything else is none — never a Portcullis-resource confirmation.
func (h *Hub) ConsumeCompanionConfirmation(ctx context.Context, user, resource, tool, digest string) (id, state string, err error) {
	if !aigate.ValidUsername(user) || !toolNameRe.MatchString(tool) || !argsDigestRe.MatchString(digest) {
		return "", ConsumeNone, nil
	}
	m, err := h.freshMembership(ctx)
	if err != nil {
		return "", "", err
	}
	if _, err := h.companionTarget(m, resource, user); err != nil {
		var se *StatusError
		if errors.As(err, &se) && (se.Status == http.StatusNotFound || se.Status == http.StatusForbidden) {
			return "", ConsumeNone, nil
		}
		return "", "", err
	}
	// A companion's confirmation is the people listener's: a Hub-listener
	// match is never seen, let alone consumed.
	c, err := h.confirms().Consume(ListenerPeople, user, resource, tool, digest)
	switch {
	case err == nil:
		return c.ID, ConsumeConsumed, nil
	case errors.Is(err, confirm.ErrPending):
		return "", ConsumePending, nil
	case errors.Is(err, confirm.ErrDeclined):
		return "", ConsumeDeclined, nil
	}
	return "", ConsumeNone, nil
}

// ConfirmationView is what the page shows (every value escaped by the
// page): the stored request as the Hub rendered it.
type ConfirmationView struct {
	ID           string
	State        string
	Tool         string
	Target       string
	Resource     string
	Client       string
	Consequences []string
	Arguments    string // canonical JSON, never clipped
	Typed        string
	Created      time.Time
	Expires      time.Time
	FreshAuth    *freshauth.AuthorizeInfo
}

// ConfirmationPage is user's confirmation id on listener: 404 for an
// unknown id, another person's and the other listener's.
func (h *Hub) ConfirmationPage(listener, id, user string) (*ConfirmationView, error) {
	c, err := h.confirms().Get(id, strings.ToLower(user))
	if err != nil || c.Listener != listener {
		return nil, errNoConfirmation
	}
	// Every displayed field with its invisible characters made visible
	// (final review I3): bidi controls, zero-width and other format
	// characters, control characters and line separators never reorder or
	// hide what the person approves. The typed check is compared raw: one
	// holding such a character can't be typed, so it can't be approved.
	cons := make([]string, len(c.Consequences))
	for i, l := range c.Consequences {
		cons[i] = VisibleText(l)
	}
	return &ConfirmationView{ID: c.ID, State: c.State, Tool: VisibleText(c.Tool), Target: VisibleText(c.Label), Resource: VisibleText(c.Resource), Client: VisibleText(c.Client),
		Consequences: cons, Arguments: VisibleText(c.ArgsPreview), Typed: VisibleText(c.Typed), Created: c.Created, Expires: c.Expires,
		FreshAuth: h.FreshAuthInfoFor(listener)}, nil
}

// VisibleText is s with every character that could hide or reorder text
// on the confirmation page written as an escape: \uXXXX (\U00XXXXXX
// above the BMP) for control (Cc), format (Cf: bidi controls, zero-width
// characters, U+FEFF, …), line and paragraph separators, spaces other
// than U+0020, variation selectors and the other default-ignorable code
// points; a backslash stays as it is. Invalid UTF-8 shows as U+FFFD.
func VisibleText(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if hiddenRune(r) {
			if r > 0xFFFF {
				fmt.Fprintf(&b, "\\U%08X", r)
			} else {
				fmt.Fprintf(&b, "\\u%04X", r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func needsEscape(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if hiddenRune(r) {
			return true
		}
	}
	return false
}

func hiddenRune(r rune) bool {
	switch {
	case r == ' ':
		return false
	case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r), unicode.Is(unicode.Zs, r),
		unicode.Is(unicode.Variation_Selector, r), unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r),
		unicode.Is(unicode.Co, r), unicode.Is(unicode.Cs, r):
		return true
	}
	return templates.IsControlRune(r)
}

// Decision is POST /api/me/confirmations/{id}'s body, decoded.
type Decision struct {
	Approve bool
	Typed   string
	Proof   freshauth.Proof
}

// DecideConfirmation records user's decision on their confirmation id on
// listener → the new state. Refusals in §5.1's order: 404 (as the page);
// 409 *ConfirmationStateError when it isn't pending; 409 "type <check>
// to confirm" (nothing recorded); 403 freshauth.Message when the proof
// fails or its auth_time is more than 60 s before the confirmation was
// created; 503 when proofs can't be verified. A decline needs neither
// the typed check nor a proof. Refusals count toward the per-caller
// limit (entryLimit; on the Hub listener only refused approvals).
func (h *Hub) DecideConfirmation(ctx context.Context, listener, id, user string, d Decision) (string, error) {
	user = strings.ToLower(user)
	if !h.entryLimit.reserve(user, h.entryClock()) {
		return "", errEntryLimited
	}
	state, err := h.decideConfirmation(ctx, listener, id, user, d)
	h.entryLimit.release(user, h.entryClock(), isRefusal(err) && (listener == ListenerPeople || d.Approve))
	return state, err
}

func (h *Hub) decideConfirmation(ctx context.Context, listener, id, user string, d Decision) (string, error) {
	s := h.confirms()
	c, err := s.Get(id, user)
	if err != nil || c.Listener != listener {
		return "", errNoConfirmation
	}
	if c.State != confirm.Pending {
		return "", &StatusError{Status: http.StatusConflict, Err: &ConfirmationStateError{State: c.State}}
	}
	actor := directory.Human(user)
	refuse := func(why string, err error) (string, error) {
		h.auditConfirm(actor, "refused", c.Resource, c.Tool, c.ArgsSHA256, c.ID, why)
		return "", err
	}
	if d.Approve {
		if strings.TrimSpace(d.Typed) != c.Typed || c.Typed == "" {
			return refuse("typed check didn't match", statusErr(http.StatusConflict, "type %s to confirm", VisibleText(c.Typed)))
		}
		res, reason, err := h.checkFreshAuthOn(ctx, listener, d.Proof, user)
		if err != nil {
			return refuse(reason, err)
		}
		now := time.Now()
		switch {
		case res == nil || res.User != user:
			return refuse("username mismatch", errFreshAuth)
		case res.AuthTime.Before(now.Add(-freshauth.MaxAge)):
			return refuse("sign-in too old", errFreshAuth)
		case !hardwareAMR(res.AMR):
			return refuse("no hardware sign-in", errFreshAuth)
		case res.AuthTime.Before(c.Created.Add(-confirmAuthSlack)):
			return refuse("sign-in from before the request", errFreshAuth)
		}
	}
	if err := s.Decide(c.ID, user, d.Approve); err != nil {
		if errors.Is(err, confirm.ErrNotPending) {
			if now, gerr := s.Get(c.ID, user); gerr == nil {
				return "", &StatusError{Status: http.StatusConflict, Err: &ConfirmationStateError{State: now.State}}
			}
		}
		return "", errNoConfirmation
	}
	what := confirm.Declined
	if d.Approve {
		what = confirm.Approved
	}
	h.auditConfirm(actor, what, c.Resource, c.Tool, c.ArgsSHA256, c.ID, "")
	return what, nil
}

// hardwareAMR: a non-empty amr with hwk or mtls and never file (the
// verifier's rule, checked again on its result).
func hardwareAMR(amr []string) bool {
	ok := false
	for _, m := range amr {
		switch strings.ToLower(m) {
		case "file":
			return false
		case "hwk", "mtls":
			ok = true
		}
	}
	return ok
}

// SweepConfirmations records every confirmation past its TTL as expired,
// audited ai.confirm expired (actor hub).
func (h *Hub) SweepConfirmations() {
	for _, c := range h.confirms().Sweep() {
		h.auditConfirm(directory.Human("hub"), confirm.Expired, c.Resource, c.Tool, c.ArgsSHA256, c.ID, "")
	}
}

// runConfirmSweeper sweeps every confirmSweepEvery until ctx ends.
func (h *Hub) runConfirmSweeper(ctx context.Context) {
	t := time.NewTicker(confirmSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.SweepConfirmations()
		}
	}
}

// SetEntryClockForTest sets the per-caller refusal limiter's clock.
// Panics outside tests.
func (h *Hub) SetEntryClockForTest(now func() time.Time) {
	if !testing.Testing() {
		panic("SetEntryClockForTest: tests only")
	}
	h.entryNow = now
}
