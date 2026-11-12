package hub

// Administrators signing in as someone else (contract §8.1
// "Impersonation", §9.7 "Signing in as someone else", D36–D38, D41,
// D44, D45): the Settings switch, the start's rules and its fresh
// YubiKey touch, the records in state (top level, F3), Stop, the expiry
// loop, the audit and the next-sign-in notice. The published file is
// impersonation_file.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/hub/internal/directory"
	"github.com/portcullis/hub/internal/freshauth"
	"github.com/portcullis/hub/internal/invite"
	"github.com/portcullis/hub/internal/keycloak"
	"github.com/portcullis/hub/internal/lldap"
	"github.com/portcullis/hub/internal/signin"
	"github.com/portcullis/hub/internal/signinhistory"
	"github.com/portcullis/hub/internal/state"
)

// DefaultImpersonationMaxMinutes is the longest impersonation, and
// HUB_IMPERSONATION_MAX_MINUTES's default and ceiling (D36: the variable
// can only shorten it).
const DefaultImpersonationMaxMinutes = 30

// The ways an impersonation ends (state.Impersonation.How).
const (
	ImpStopped     = "stopped"
	ImpExpired     = "expired"
	ImpSwitchedOff = "switched_off"
	ImpNotUsed     = "not_used"
)

// impSystem is the audit actor of an end nobody asked for (expiry, the
// switch, not used).
const impSystem = "portcullis"

// ImpersonationKeycloak is the Keycloak side the impersonation rules and
// the notice need (keycloak.Client). Network calls: never under mu.
type ImpersonationKeycloak interface {
	UserEnabled(ctx context.Context, username string) (bool, error)
	RequiredActions(ctx context.Context, username string) ([]string, error)
	RequireImpersonationNotice(ctx context.Context, username string) error
}

// impState is the Hub's impersonation wiring. kc and apps are guarded by
// mu; fileMu (a leaf, taken under mu) guards written and fileFailed.
type impState struct {
	kc   ImpersonationKeycloak
	apps func(ctx context.Context, rec state.Impersonation) ([]signinhistory.OpenedApp, bool)
	// now is the clock (nil: time.Now; tests set it before use).
	now func() time.Time
	// endMu serialises the end's second half (apps, audit, notice) per
	// call; the record's own end is under mu.
	endMu      sync.Mutex
	fileMu     sync.Mutex
	written    time.Time
	fileFailed bool
	// saveFailed: an end couldn't be saved; the loop saves again.
	saveFailed bool
}

func (h *Hub) impNow() time.Time {
	if h.imp.now != nil {
		return h.imp.now().UTC()
	}
	return time.Now().UTC()
}

// SetImpersonationKeycloak wires the Keycloak calls (nil: starts are 503
// and no notice is added).
func (h *Hub) SetImpersonationKeycloak(k ImpersonationKeycloak) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.imp.kc = k
}

// SetImpersonationApps wires the apps-opened function (Task 7: the
// opened log and Keycloak's events): the apps opened during rec and
// whether it was used (an IMPERSONATE event with its id; an unreadable
// source is used). nil: no apps, used (fail toward telling).
func (h *Hub) SetImpersonationApps(f func(ctx context.Context, rec state.Impersonation) (apps []signinhistory.OpenedApp, used bool)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.imp.apps = f
}

func (h *Hub) impKC() ImpersonationKeycloak {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.imp.kc
}

// impersonationApps runs the apps function outside mu (a panic or none
// wired: no apps, used).
func (h *Hub) impersonationApps(ctx context.Context, rec state.Impersonation) (apps []signinhistory.OpenedApp, used bool) {
	h.mu.RLock()
	f := h.imp.apps
	h.mu.RUnlock()
	if f == nil {
		return nil, true
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("impersonation: %s: the apps-opened function panicked: %v (counted as used)", rec.ID, r)
			apps, used = nil, true
		}
	}()
	return f(ctx, rec.Clone())
}

// impersonationMaxMinutes is the configured length (1–30; anything else
// the default: main refuses such a value).
func (h *Hub) impersonationMaxMinutes() int {
	if m := h.cfg.ImpersonationMaxMinutes; m >= 1 && m <= DefaultImpersonationMaxMinutes {
		return m
	}
	return DefaultImpersonationMaxMinutes
}

// ParseImpersonationMaxMinutes reads HUB_IMPERSONATION_MAX_MINUTES (D36):
// unset is 30, an integer 1–30 that many, anything else an error (the
// Hub refuses to start).
func ParseImpersonationMaxMinutes(v string) (int, error) {
	if v == "" {
		return DefaultImpersonationMaxMinutes, nil
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' || n > DefaultImpersonationMaxMinutes {
			return 0, fmt.Errorf("HUB_IMPERSONATION_MAX_MINUTES must be an integer 1 to %d, got %q", DefaultImpersonationMaxMinutes, v)
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > DefaultImpersonationMaxMinutes {
		return 0, fmt.Errorf("HUB_IMPERSONATION_MAX_MINUTES must be an integer 1 to %d, got %q", DefaultImpersonationMaxMinutes, v)
	}
	return n, nil
}

// ── views ────────────────────────────────────────────────

// ImpersonationView is one impersonation as the API shows it (contract
// §8.1 "Hub API and audit"): ended null and how "" while running.
type ImpersonationView struct {
	ID      string     `json:"id"`
	Admin   string     `json:"admin"`
	Person  string     `json:"person"`
	Reason  string     `json:"reason"`
	Started time.Time  `json:"started"`
	Until   time.Time  `json:"until"`
	Ended   *time.Time `json:"ended"`
	How     string     `json:"how"`
}

// ImpersonationsView is GET /api/impersonations: the switch, the length,
// the running ones (oldest first) and the last 20 ended (newest first).
type ImpersonationsView struct {
	Allowed    bool                `json:"allowed"`
	MaxMinutes int                 `json:"max_minutes"`
	Running    []ImpersonationView `json:"running"`
	Recent     []ImpersonationView `json:"recent"`
}

// impRecentMax is how many ended impersonations the view lists.
const impRecentMax = 20

func impView(r state.Impersonation) ImpersonationView {
	v := ImpersonationView{ID: r.ID, Admin: r.Admin, Person: r.Target, Reason: r.Reason, Started: r.Started, Until: r.Until, How: r.How}
	if !r.Running() {
		e := r.Ended
		v.Ended = &e
	}
	return v
}

// Impersonations is the switch, the running impersonations and the
// recent ended ones.
func (h *Hub) Impersonations() ImpersonationsView {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.impersonationsViewLocked()
}

func (h *Hub) impersonationsViewLocked() ImpersonationsView {
	v := ImpersonationsView{Allowed: !h.st.SignIn.ImpersonationOff, MaxMinutes: h.impersonationMaxMinutes(),
		Running: []ImpersonationView{}, Recent: []ImpersonationView{}}
	var ended []state.Impersonation
	for _, r := range h.st.Impersonations {
		if r.Running() {
			v.Running = append(v.Running, impView(r))
		} else {
			ended = append(ended, r)
		}
	}
	slices.SortStableFunc(v.Running, func(a, b ImpersonationView) int { return a.Started.Compare(b.Started) })
	slices.SortStableFunc(ended, func(a, b state.Impersonation) int {
		if c := b.Ended.Compare(a.Ended); c != 0 {
			return c
		}
		return b.Started.Compare(a.Started)
	})
	for i, r := range ended {
		if i == impRecentMax {
			break
		}
		v.Recent = append(v.Recent, impView(r))
	}
	return v
}

// ImpersonationOf is person's running impersonation id as a view; nil
// unless it runs, is person's and is before its until.
func (h *Hub) ImpersonationOf(person, id string) *ImpersonationView {
	person = strings.ToLower(strings.TrimSpace(person))
	now := h.impNow()
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.st.SignIn.ImpersonationOff {
		return nil
	}
	for _, r := range h.st.Impersonations {
		if r.ID == id && id != "" && r.Target == person && r.Running() && now.Before(r.Until) {
			v := impView(r)
			return &v
		}
	}
	return nil
}

// runningOfLocked is the running record whose field (admin or target)
// is user (-1: none). Caller holds mu.
func (h *Hub) runningOfLocked(user string, byAdmin bool) int {
	for i, r := range h.st.Impersonations {
		if !r.Running() {
			continue
		}
		if (byAdmin && r.Admin == user) || (!byAdmin && r.Target == user) {
			return i
		}
	}
	return -1
}

// ── the switch ───────────────────────────────────────────

// SetImpersonationAllowed sets the "Signing in as someone else" switch
// (state.yaml sign_in.impersonation_off, outside the sign-in writers:
// their commit re-copies it, F3). Off ends every running impersonation
// (switched_off). Audited signin.impersonation on / off (a change only).
func (h *Hub) SetImpersonationAllowed(ctx context.Context, allowed bool, actor directory.Actor) (*ImpersonationsView, error) {
	if actor.User == "" {
		return nil, statusErr(http.StatusUnauthorized, "changing the sign-in settings needs a signed-in admin")
	}
	h.mu.Lock()
	if h.st.SignIn.ImpersonationOff == !allowed {
		v := h.impersonationsViewLocked()
		h.mu.Unlock()
		return &v, nil
	}
	h.st.SignIn.ImpersonationOff = !allowed
	if err := h.saveStateLocked(); err != nil {
		h.st.SignIn.ImpersonationOff = allowed
		h.mu.Unlock()
		h.auditSignIn(actor, "signin.impersonation", "impersonation", onOff(allowed), err)
		return nil, err
	}
	var ended []string
	if !allowed {
		ended = h.endRunningLocked(func(state.Impersonation) bool { return true }, ImpSwitchedOff, impSystem)
	}
	_ = h.writeImpersonationFileLocked()
	h.mu.Unlock()
	h.auditSignIn(actor, "signin.impersonation", "impersonation", onOff(allowed), nil)
	h.finishEnds(ctx, ended, directory.Human(impSystem))
	h.mu.RLock()
	v := h.impersonationsViewLocked()
	h.mu.RUnlock()
	return &v, nil
}

// ── start ────────────────────────────────────────────────

// StartImpersonation is POST /api/directory/users/{u}/impersonation's
// input: the person, the typed reason, the caller's Keycloak session id
// (the sid of X-Forwarded-Access-Token), the listener the proof was made
// on and the fresh-auth proof.
type StartImpersonation struct {
	Target, Reason, AdminSID, Listener string
	Proof                              freshauth.Proof
}

// StartedImpersonation is the start's answer: the id, the URL the page
// opens in the top window and the end at the latest.
type StartedImpersonation struct {
	ID    string    `json:"id"`
	Next  string    `json:"next"`
	Until time.Time `json:"until"`
}

var (
	errImpOff          = &StatusError{Status: http.StatusConflict, Err: errors.New("signing in as someone else is switched off (Settings → Sign-in)")}
	errImpAdminsOnly   = &StatusError{Status: http.StatusForbidden, Err: errors.New("not allowed: admins only")}
	errImpSelf         = &StatusError{Status: http.StatusConflict, Err: errors.New("you can't sign in as yourself")}
	errImpProtected    = &StatusError{Status: http.StatusConflict, Err: errors.New("this account can't be signed in as")}
	errImpAdminTarget  = &StatusError{Status: http.StatusConflict, Err: errors.New("administrators can't be signed in as")}
	errImpDisabled     = &StatusError{Status: http.StatusConflict, Err: errors.New("this account is disabled")}
	errImpReason       = &StatusError{Status: http.StatusBadRequest, Err: errors.New("type a reason (3–200 characters, one line)")}
	errImpNoTouch      = &StatusError{Status: http.StatusConflict, Err: errors.New("signing in as someone needs security keys or YubiKey certificates switched on")}
	errImpNoSID        = &StatusError{Status: http.StatusForbidden, Err: errors.New("your sign-in can't be read: sign in again")}
	errImpKCNA         = &StatusError{Status: http.StatusServiceUnavailable, Err: errors.New("signing in as someone else can't be checked right now: try again later")}
	errImpNoCaller     = &StatusError{Status: http.StatusUnauthorized, Err: errors.New("no signed-in user")}
	errNoImpersonation = &StatusError{Status: http.StatusNotFound, Err: errors.New("no running impersonation")}
)

func errImpCallerRuns(r state.Impersonation) error {
	return statusErr(http.StatusConflict, "you are signed in as %s until %s: Stop it first", r.Target, r.Until.UTC().Format("15:04"))
}

func errImpTargetTaken(r state.Impersonation) error {
	return statusErr(http.StatusConflict, "%s is signed in as %s right now", r.Admin, r.Target)
}

func errImpUnfinished(target string) error {
	return statusErr(http.StatusConflict, "%s has an unfinished sign-in step (a setup link?): finish or cancel it first", target)
}

// isLLDAPAdmin: user is in lldap_admin in snapshot m.
func isLLDAPAdmin(m *directory.Membership, user string) bool {
	return slices.ContainsFunc(m.Groups[lldap.AdminGroup].Members, func(u string) bool { return strings.EqualFold(u, user) })
}

// impNext is the start URL the page opens (D38): only the browser that
// holds the administrator's own Keycloak session can use the id.
func (h *Hub) impNext(id string) string {
	return "https://auth." + h.cfg.Domain + "/realms/portcullis/portcullis-impersonate/start?id=" + id
}

// impSignOut is oauth2-proxy's sign-out, back to the portal.
func (h *Hub) impSignOut() string {
	return "https://auth." + h.cfg.Domain + "/oauth2/sign_out?rd=" + url.QueryEscape("https://"+h.cfg.Domain+"/")
}

func newImpID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// StartImpersonation starts actor's impersonation of in.Target (D36's
// rules in order, D38). Every refusal is audited impersonation.start
// (the typed reason only on an administrator's own refusals, never a
// code, verifier or nonce); the whole call counts toward the caller's
// refusal limit. The Keycloak calls and the proof exchange run outside
// mu; the state is read again under the lock before the record is
// written, so a concurrent start for the same administrator or person
// loses with the 409 of rule 5.
func (h *Hub) StartImpersonation(ctx context.Context, in StartImpersonation, actor directory.Actor) (*StartedImpersonation, error) {
	admin := strings.ToLower(strings.TrimSpace(actor.User))
	if admin == "" {
		return nil, errImpNoCaller
	}
	if !h.entryLimit.reserve(admin, h.entryClock()) {
		return nil, errEntryLimited
	}
	var err error
	var out *StartedImpersonation
	out, err = h.startImpersonation(ctx, in, admin, actor)
	h.entryLimit.release(admin, h.entryClock(), isRefusal(err))
	return out, err
}

func (h *Hub) startImpersonation(ctx context.Context, in StartImpersonation, admin string, actor directory.Actor) (*StartedImpersonation, error) {
	target := strings.ToLower(strings.TrimSpace(in.Target))
	reason := strings.TrimSpace(in.Reason)
	isAdmin, why := false, ""
	refuse := func(err error) error {
		d := ""
		if isAdmin && validImpReason(reason) {
			d = reason
		}
		if why != "" {
			if d != "" {
				d += "; "
			}
			d += why
		}
		h.auditSignIn(actor, "impersonation.start", target, d, err)
		return err
	}
	if !lldap.ValidUsername(target) {
		return nil, refuse(statusErr(http.StatusBadRequest, "not a valid username"))
	}
	// 1. The switch.
	h.mu.RLock()
	off := h.st.SignIn.ImpersonationOff
	h.mu.RUnlock()
	if off {
		return nil, refuse(errImpOff)
	}
	// 2. The caller, on a fresh snapshot.
	m, err := h.membership(ctx)
	if err != nil {
		return nil, refuse(err)
	}
	if !isLLDAPAdmin(m, admin) {
		return nil, refuse(errImpAdminsOnly)
	}
	isAdmin = true
	// 3. The target (a protected name first: the service account isn't
	// in the snapshot, and it is never a target either way).
	switch _, known := m.UUIDs[target]; {
	case invite.ProtectedName(target):
		return nil, refuse(errImpProtected)
	case !known:
		return nil, refuse(statusErr(http.StatusNotFound, "no such person: %s", target))
	case target == admin:
		return nil, refuse(errImpSelf)
	case m.Administrators[target] || isLLDAPAdmin(m, target):
		return nil, refuse(errImpAdminTarget)
	}
	kc := h.impKC()
	if kc == nil {
		why = "Keycloak isn't wired"
		return nil, refuse(errImpKCNA)
	}
	enabled, err := kc.UserEnabled(ctx, target)
	if errors.Is(err, keycloak.ErrUserNotFound) {
		return nil, refuse(statusErr(http.StatusNotFound, "no such person: %s", target))
	}
	if err != nil {
		why = "reading the person in Keycloak failed"
		log.Printf("impersonation: %s: reading %s in Keycloak: %v", admin, target, err)
		return nil, refuse(errImpKCNA)
	}
	if !enabled {
		return nil, refuse(errImpDisabled)
	}
	// 4. The reason.
	if !validImpReason(reason) {
		return nil, refuse(errImpReason)
	}
	// 5. One at a time.
	if err := h.impOneAtATime(admin, target); err != nil {
		return nil, refuse(err)
	}
	// 6. Unfinished steps.
	acts, err := kc.RequiredActions(ctx, target)
	if err != nil {
		why = "reading the person's required actions failed"
		log.Printf("impersonation: %s: reading %s's required actions: %v", admin, target, err)
		return nil, refuse(errImpKCNA)
	}
	if slices.ContainsFunc(acts, func(a string) bool { return a != keycloak.ImpersonationNoticeAction }) {
		return nil, refuse(errImpUnfinished(target))
	}
	// 7. A touch method on (before the proof is spent).
	if !h.touchMethodOn() {
		return nil, refuse(errImpNoTouch)
	}
	// 8. The administrator's session.
	if !impSessionIDRe.MatchString(in.AdminSID) {
		return nil, refuse(errImpNoSID)
	}
	// 9. The fresh touch.
	res, err := h.verifyTouch(ctx, in.Listener, in.Proof, admin)
	if err != nil {
		var tr *touchRefused
		if errors.As(err, &tr) {
			why = tr.reason
		}
		return nil, refuse(err)
	}
	id, err := newImpID()
	if err != nil {
		why = "no random id"
		return nil, refuse(statusErr(http.StatusInternalServerError, "an id couldn't be made: try again"))
	}
	now := h.impNow().Truncate(time.Second)
	fresh := res.AuthTime.UTC().Truncate(time.Second)
	if fresh.IsZero() || fresh.After(now) {
		fresh = now
	}
	rec := state.Impersonation{ID: id, Admin: admin, Target: target, AdminSID: in.AdminSID, Reason: reason,
		Fresh: res.Method, FreshAt: fresh, Started: now, Until: now.Add(time.Duration(h.impersonationMaxMinutes()) * time.Minute)}
	h.mu.Lock()
	if h.st.SignIn.ImpersonationOff {
		h.mu.Unlock()
		return nil, refuse(errImpOff)
	}
	if err := h.impOneAtATimeLocked(admin, target); err != nil {
		h.mu.Unlock()
		return nil, refuse(err)
	}
	prev := h.st.Impersonations
	h.st.Impersonations = append(slices.Clone(prev), rec)
	if err := h.saveStateLocked(); err != nil {
		h.st.Impersonations = prev
		h.mu.Unlock()
		return nil, refuse(err)
	}
	if err := h.writeImpersonationFileLocked(); err != nil {
		// Not published: the resource would refuse it. Taken back.
		h.st.Impersonations = prev
		if serr := h.saveStateLocked(); serr != nil {
			h.imp.saveFailed = true
		}
		_ = h.writeImpersonationFileLocked()
		h.mu.Unlock()
		why = "the file couldn't be written"
		return nil, refuse(statusErr(http.StatusInternalServerError, "the impersonation couldn't be published: try again"))
	}
	h.mu.Unlock()
	h.auditSignIn(actor, "impersonation.start", target, id+" · "+rec.Fresh+" · "+reason, nil)
	return &StartedImpersonation{ID: id, Next: h.impNext(id), Until: rec.Until}, nil
}

func (h *Hub) impOneAtATime(admin, target string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.impOneAtATimeLocked(admin, target)
}

// impOneAtATimeLocked is rule 5. Caller holds mu.
func (h *Hub) impOneAtATimeLocked(admin, target string) error {
	if i := h.runningOfLocked(admin, true); i >= 0 {
		return errImpCallerRuns(h.st.Impersonations[i])
	}
	if i := h.runningOfLocked(target, false); i >= 0 {
		return errImpTargetTaken(h.st.Impersonations[i])
	}
	return nil
}

func (h *Hub) touchMethodOn() bool {
	h.mu.RLock()
	on := h.st.SignIn.MethodsOn()
	h.mu.RUnlock()
	return slices.ContainsFunc(impTouchMethods, func(m signin.Method) bool { return on[m] })
}

// touchRefused is a refused touch proof: err is the answer, reason the
// audit's (a fixed string, never a proof value).
type touchRefused struct {
	err    error
	reason string
}

func (e *touchRefused) Error() string { return e.err.Error() }
func (e *touchRefused) Unwrap() error { return e.err }

// verifyTouch checks an impersonation's fresh touch (D36.9, F11): a
// proof valid for user on listener whose pc_fresh is security_key or
// yubikey_cert, switched on as it is after the exchange. No governing
// template applies (a stricter carve-out from checkFreshAuthOn). 403
// "a fresh sign-in is required" for every refusal, 503 while the Hub
// can't verify proofs; the error carries the audit reason
// (*touchRefused).
func (h *Hub) verifyTouch(ctx context.Context, listener string, proof freshauth.Proof, user string) (*freshauth.Result, error) {
	f := h.freshAuthVerifier(listener)
	if f == nil {
		return nil, &touchRefused{errFreshAuth, "fresh auth is not configured"}
	}
	if !h.freshAuthReady.Load() {
		return nil, &touchRefused{errFreshAuthUnavailable, "fresh-auth client not in place"}
	}
	r, err := f.Verify(ctx, proof, strings.ToLower(user))
	var fe *freshauth.Error
	switch {
	case err == nil && r == nil:
		return nil, &touchRefused{errFreshAuth, "fresh auth failed"}
	case errors.As(err, &fe) && fe.Reason == freshauth.ReasonUnreachable:
		return nil, &touchRefused{errFreshAuthUnavailable, fe.Reason}
	case errors.As(err, &fe) && fe.Reason != "":
		return nil, &touchRefused{errFreshAuth, fe.Reason}
	case err != nil:
		return nil, &touchRefused{errFreshAuth, "fresh auth failed"}
	}
	if !strings.EqualFold(r.User, user) {
		return nil, &touchRefused{errFreshAuth, "the proof is another person's"}
	}
	h.mu.RLock()
	on := h.st.SignIn.MethodsOn()
	h.mu.RUnlock()
	m := signin.Method(r.Method)
	if !slices.Contains(impTouchMethods, m) {
		return nil, &touchRefused{errFreshAuth, "pc_fresh names " + clip(r.Method, 32) + ", not a security key or a YubiKey certificate"}
	}
	if !on[m] {
		return nil, &touchRefused{errFreshAuth, "pc_fresh names " + r.Method + ", which is switched off"}
	}
	return r, nil
}

// ── ending ───────────────────────────────────────────────

// endRunningLocked ends every running record match accepts (how, by),
// saves and answers their ids; the caller writes the file and then runs
// finishEnds outside mu. A failed save keeps the end in memory (never
// taken back: the file says ended) and the loop saves again. Caller
// holds mu (write).
func (h *Hub) endRunningLocked(match func(state.Impersonation) bool, how, by string) []string {
	now := h.impNow()
	var ids []string
	for i := range h.st.Impersonations {
		r := &h.st.Impersonations[i]
		if r.Running() && match(*r) {
			r.Ended, r.How, r.EndedBy = now, how, by
			if how == ImpExpired && r.Until.Before(now) {
				// It ended at until (the loop noticed up to a tick later).
				r.Ended = r.Until
			}
			ids = append(ids, r.ID)
		}
	}
	if len(ids) > 0 && h.saveStateLocked() != nil {
		h.imp.saveFailed = true
	}
	return ids
}

// finishEnds completes the ends of ids (already ended in state and the
// file): the apps opened and whether it was used, stored on the record
// (F1) — not used makes how not_used; the file written again; then the
// audit impersonation.end and, when used, the notice action. The file
// goes before the action (the Task 4 review): a sign-in right after the
// action is added already finds the notice.
func (h *Hub) finishEnds(ctx context.Context, ids []string, actor directory.Actor) {
	h.imp.endMu.Lock()
	defer h.imp.endMu.Unlock()
	for _, id := range ids {
		h.finishEnd(ctx, id, actor)
	}
}

func (h *Hub) finishEnd(ctx context.Context, id string, actor directory.Actor) {
	h.mu.RLock()
	i := slices.IndexFunc(h.st.Impersonations, func(r state.Impersonation) bool { return r.ID == id })
	var rec state.Impersonation
	if i >= 0 {
		rec = h.st.Impersonations[i].Clone()
	}
	h.mu.RUnlock()
	if i < 0 || rec.Running() {
		return
	}
	apps, used := h.impersonationApps(ctx, rec)
	used = used || rec.Used
	h.mu.Lock()
	i = slices.IndexFunc(h.st.Impersonations, func(r state.Impersonation) bool { return r.ID == id })
	if i < 0 {
		h.mu.Unlock()
		return
	}
	r := &h.st.Impersonations[i]
	r.Used = used
	r.Apps = nil
	for _, a := range apps {
		r.Apps = append(r.Apps, state.ImpersonationApp{Name: a.Name, OwnSession: a.OwnSession})
	}
	if !used {
		r.How = ImpNotUsed
	}
	rec = r.Clone()
	if h.saveStateLocked() != nil {
		h.imp.saveFailed = true
	}
	_ = h.writeImpersonationFileLocked()
	kc := h.imp.kc
	h.mu.Unlock()
	h.auditSignIn(actor, "impersonation.end", rec.Target, impEndDetail(rec), nil)
	if !used {
		return
	}
	if kc == nil {
		log.Printf("impersonation: %s: no Keycloak wired: %s gets no notice at their next sign-in", rec.ID, rec.Target)
		return
	}
	if err := kc.RequireImpersonationNotice(ctx, rec.Target); err != nil {
		log.Printf("impersonation: %s: adding the notice action for %s: %v (the history still shows it)", rec.ID, rec.Target, err)
	}
}

// impMinutes is the minutes from started to ended, rounded up, at least
// 1 (as the Keycloak notice counts them).
func impMinutes(r state.Impersonation) int {
	d := r.Ended.Sub(r.Started)
	n := int((d + time.Minute - 1) / time.Minute)
	if n < 1 {
		n = 1
	}
	return n
}

// impEndDetail is impersonation.end's detail (contract §8.1 audit
// actions): "<id> · <how> · <n> min · apps opened: <A, B>" (or "none"),
// or "<id> · not_used · 0 min · not used".
func impEndDetail(r state.Impersonation) string {
	if r.How == ImpNotUsed {
		return r.ID + " · not_used · 0 min · not used"
	}
	names := []string{}
	for _, a := range r.Apps {
		if n := impAppName(a.Name); n != "" {
			names = append(names, n)
		}
	}
	apps := "none"
	if len(names) > 0 {
		apps = strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s · %s · %d min · apps opened: %s", r.ID, r.How, impMinutes(r), apps)
}

// StopImpersonation ends target's running impersonation (how stopped,
// by actor): administrators only, on a fresh snapshot (403); 404 when
// none runs.
func (h *Hub) StopImpersonation(ctx context.Context, target string, actor directory.Actor) error {
	by := strings.ToLower(strings.TrimSpace(actor.User))
	if by == "" {
		return errImpNoCaller
	}
	target = strings.ToLower(strings.TrimSpace(target))
	m, err := h.membership(ctx)
	if err != nil {
		return err
	}
	if !isLLDAPAdmin(m, by) {
		return errImpAdminsOnly
	}
	h.mu.Lock()
	ids := h.endRunningLocked(func(r state.Impersonation) bool { return r.Target == target }, ImpStopped, by)
	if len(ids) == 0 {
		h.mu.Unlock()
		return errNoImpersonation
	}
	_ = h.writeImpersonationFileLocked()
	h.mu.Unlock()
	h.finishEnds(ctx, ids, actor)
	return nil
}

// StopOwnImpersonation is Stop in the impersonating browser: ends the
// running impersonation id of person (404 when it isn't theirs or isn't
// running), audited with the record's administrator as the actor, and
// answers oauth2-proxy's sign-out URL.
func (h *Hub) StopOwnImpersonation(ctx context.Context, id, person string) (string, error) {
	person = strings.ToLower(strings.TrimSpace(person))
	if id == "" || person == "" {
		return "", errNoImpersonation
	}
	h.mu.Lock()
	admin := ""
	ids := h.endRunningLocked(func(r state.Impersonation) bool {
		if r.ID == id && r.Target == person {
			admin = r.Admin
			return true
		}
		return false
	}, ImpStopped, "")
	if len(ids) == 0 {
		h.mu.Unlock()
		return "", errNoImpersonation
	}
	for i := range h.st.Impersonations {
		if h.st.Impersonations[i].ID == id {
			h.st.Impersonations[i].EndedBy = admin
		}
	}
	if h.saveStateLocked() != nil {
		h.imp.saveFailed = true
	}
	_ = h.writeImpersonationFileLocked()
	h.mu.Unlock()
	h.finishEnds(ctx, ids, directory.Human(admin))
	return h.impSignOut(), nil
}

// ── the loop ─────────────────────────────────────────────

// RunImpersonationExpiry checks the impersonations every interval
// (default 5 s) until ctx ends: past until → expired; switched off →
// switched_off; a record not used at created + 120 s → not_used; the
// records pruned; the file rewritten every minute (and after a failed
// write).
func (h *Hub) RunImpersonationExpiry(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		h.impersonationTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// impersonationTick is one pass of RunImpersonationExpiry.
func (h *Hub) impersonationTick(ctx context.Context) {
	now := h.impNow()
	h.mu.Lock()
	ended := h.endRunningLocked(func(r state.Impersonation) bool {
		return h.st.SignIn.ImpersonationOff
	}, ImpSwitchedOff, impSystem)
	ended = append(ended, h.endRunningLocked(func(r state.Impersonation) bool { return !now.Before(r.Until) }, ImpExpired, impSystem)...)
	// Not yet known to be used, at created + 120 s: ask.
	var check []state.Impersonation
	for _, r := range h.st.Impersonations {
		if r.Running() && !r.Used && now.Sub(r.Started) >= impPendingFor {
			check = append(check, r.Clone())
		}
	}
	pruned := h.pruneImpersonationsLocked(now)
	if (pruned || h.imp.saveFailed) && h.saveStateLocked() == nil {
		h.imp.saveFailed = false
	}
	if len(ended) > 0 || pruned || h.impersonationFileDue(now) {
		_ = h.writeImpersonationFileLocked()
	}
	h.mu.Unlock()
	h.finishEnds(ctx, ended, directory.Human(impSystem))
	for _, rec := range check {
		_, used := h.impersonationApps(ctx, rec)
		h.mu.Lock()
		i := slices.IndexFunc(h.st.Impersonations, func(r state.Impersonation) bool { return r.ID == rec.ID })
		if i < 0 || !h.st.Impersonations[i].Running() {
			h.mu.Unlock()
			continue
		}
		var ids []string
		if used {
			// Known used (or unreadable: counted as used): it runs until
			// until and is never asked again.
			h.st.Impersonations[i].Used = true
			if h.saveStateLocked() != nil {
				h.imp.saveFailed = true
			}
		} else {
			ids = h.endRunningLocked(func(r state.Impersonation) bool { return r.ID == rec.ID }, ImpNotUsed, impSystem)
			_ = h.writeImpersonationFileLocked()
		}
		h.mu.Unlock()
		h.finishEnds(ctx, ids, directory.Human(impSystem))
	}
}

// pruneImpersonationsLocked drops the ended records no longer kept: not
// used and ended an hour ago, used and ended history_days ago (F1).
// Caller holds mu (write).
func (h *Hub) pruneImpersonationsLocked(now time.Time) bool {
	keepUsed := now.AddDate(0, 0, -h.historyDaysLocked())
	n := len(h.st.Impersonations)
	h.st.Impersonations = slices.DeleteFunc(slices.Clone(h.st.Impersonations), func(r state.Impersonation) bool {
		if r.Running() {
			return false
		}
		if r.Used {
			return !r.Ended.After(keepUsed)
		}
		return now.Sub(r.Ended) >= impSessionsKeep
	})
	if len(h.st.Impersonations) == 0 {
		h.st.Impersonations = nil
	}
	return len(h.st.Impersonations) != n
}
